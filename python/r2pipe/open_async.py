# -*- coding: utf-8 -*-
"""open_async.py
This script use code from r2pipe-async/open_p3.py script.

"""
import asyncio
import json
import os
import re
import sys


from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from contextlib import ContextDecorator, suppress
from types import SimpleNamespace
from urllib.parse import quote, urlparse

from r2pipe.open_base import OpenBase, get_radare_path, jo2po, normalize_open_target


class open(OpenBase, ContextDecorator):
    # --------------------------------------------------------------------------
    # Context manager functions
    # --------------------------------------------------------------------------
    def __enter__(self):
        if self._running_loop() is not None:
            raise RuntimeError("Use 'async with' for r2pipe inside an event loop")
        return self

    def __exit__(self, *exc):
        if self._running_loop() is not None:
            raise RuntimeError("Use 'async with' for r2pipe inside an event loop")
        self.close()
        return False

    async def __aenter__(self):
        self._bind_loop()
        self._ensure_open()
        return self

    async def __aexit__(self, *exc):
        await self.aclose()
        return False

    async def _close_all_connections(self):
        """Close all connections in the connection pool"""
        async with self._connection_lock:
            for connections in self._connection_pool.values():
                for _, writer in connections:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
            self._connection_pool = {}

    async def _close_process(self):
        """Terminate the async subprocess and close its transport before the loop."""
        process = getattr(self, "process", None)
        if process is None:
            return

        stdin = getattr(process, "stdin", None)
        if stdin is not None:
            with suppress(Exception):
                if not stdin.is_closing():
                    stdin.close()

        if process.returncode is None:
            with suppress(ProcessLookupError):
                process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                with suppress(ProcessLookupError):
                    process.kill()
                with suppress(Exception):
                    await process.wait()
        else:
            with suppress(Exception):
                await process.wait()

        transport = getattr(process, "_transport", None)
        if transport is not None:
            with suppress(Exception):
                transport.close()

        delattr(self, "process")
        self._pending_output = b""

    async def _shutdown(self):
        """Tear down all async resources while the loop is still alive."""
        try:
            if self._command_tasks:
                await asyncio.gather(*tuple(self._command_tasks), return_exceptions=True)
            async with self._cmd_lock:
                await self._close_all_connections()
                await self._close_process()
                await self._close_native()
        finally:
            self._closed = True

    def _free_native(self):
        core = self.__dict__.pop("native", None)
        if core is not None:
            core.free()

    async def _close_native(self):
        executor = self._native_executor
        if executor is None:
            return
        try:
            await self._loop.run_in_executor(executor, self._free_native)
        finally:
            # The native call has finished; join the now-idle dedicated worker.
            executor.shutdown(wait=True)
            self._native_executor = None

    def _ensure_open(self):
        if self._closed or self._closing or self._loop.is_closed():
            raise RuntimeError("r2pipe is closed")

    @staticmethod
    def _running_loop():
        try:
            if hasattr(asyncio, "get_running_loop"):
                return asyncio.get_running_loop()
            loop = asyncio.get_event_loop()
            return loop if loop.is_running() else None
        except RuntimeError:
            return None

    def _bind_loop(self):
        """Adopt the caller's loop before first use; transports cannot move loops."""
        running = self._running_loop()
        if running is not None and running is not self._loop:
            if self._owns_loop and not self._used and not self._closing:
                self._loop.close()
                self._loop = running
                self._owns_loop = False
                self._cmd_lock = self._new_lock()
                self._connection_lock = self._new_lock()
            else:
                raise RuntimeError("r2pipe belongs to a different event loop")
        elif running is None and not self._owns_loop and not self._closed:
            raise RuntimeError("Use r2pipe from its owning event loop")
        return running

    def _dispatch(self, coroutine, *args):
        running = self._bind_loop()
        self._ensure_open()
        if running is not None:
            return coroutine(*args)
        return self._loop.run_until_complete(coroutine(*args))

    async def aclose(self):
        """Finish in-flight commands and close resources without closing the loop."""
        if self._closed:
            return
        self._bind_loop()
        if self._shutdown_task is None:
            self._closing = True
            self._shutdown_task = self._loop.create_task(self._shutdown())
        canceled = False
        while True:
            try:
                await asyncio.shield(self._shutdown_task)
                break
            except asyncio.CancelledError:
                if self._shutdown_task.cancelled():
                    raise
                # Repeated cancellation must still let resource cleanup finish.
                canceled = True
        if canceled:
            raise asyncio.CancelledError

    def close(self):
        """Close synchronously, or return an awaitable inside an event loop."""
        if self._closed:
            return self.aclose() if self._running_loop() is not None else None
        running = self._bind_loop()
        if running is not None:
            return self.aclose()
        try:
            self._loop.run_until_complete(self.aclose())
        finally:
            if self._owns_loop:
                self._loop.close()

    def quit(self):
        """Use this client's event loop to finish the asynchronous shutdown."""
        return self.close()

    def _new_lock(self):
        if sys.version_info < (3, 10):
            return asyncio.Lock(loop=self._loop)
        return asyncio.Lock()

    def __init__(self, filename="", flags=None, radare2home=None):
        filename, file_args = normalize_open_target(filename)

        super().__init__(filename, flags)
        if flags is None:
            flags = []

        self.r2home = radare2home

        self._loop = self._running_loop()
        self._owns_loop = self._loop is None
        if self._owns_loop and os.name == "nt":
            self._loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(self._loop)
        elif self._owns_loop:
            self._loop = asyncio.new_event_loop()
            if sys.version_info < (3, 12) and hasattr(asyncio, "get_child_watcher"):
                try:
                    watcher = asyncio.get_child_watcher()
                    watcher.attach_loop(self._loop)
                except RuntimeError:
                    pass

        # Add a lock for synchronizing command execution
        self._cmd_lock = self._new_lock()

        self._next_cmd_id = 0
        self._command_tasks = set()
        self._used = False
        self._closing = False
        self._shutdown_task = None
        self._native_executor = None

        # Add connection management for HTTP/TCP modes
        self._connection_pool = {}
        self._pool_size = 5  # Maximum number of concurrent connections
        self._connection_lock = self._new_lock()
        self._closed = False

        self.asyn = True

        if "_cmd" in self.__dict__:
            # OpenBase selected the embedded #!pipe or r2lang transport.
            self.asyn = False
            return

        if filename.startswith("http://"):
            self._cmd_coro = self._cmd_http
            self.uri = "/cmd"

            _tmp = urlparse(filename)
            self._host = _tmp.hostname
            self._port = _tmp.port

        elif filename.startswith("ccall://"):
            self._cmd_coro = self._cmd_native_async
            self.uri = filename[8:]

        elif filename.startswith("tcp://"):

            r = re.match(r"tcp://(\d+\.\d+.\d+.\d+):(\d+)/?", filename)
            if not r:
                raise ValueError("String doesn't match tcp format")

            self._cmd_coro = self._cmd_tcp
            self._host = r.group(1)
            self._port = r.group(2)

        elif filename:

            self._cmd_coro = self._cmd_process

            r_args = [f"-Rarg{i+1}={a}" for i, a in enumerate(file_args)]
            cmd = ["-q0", filename]
            cmd = cmd[:1] + flags + r_args + cmd[1:]
            self._process_start_cmd = cmd

        else:
            self.asyn = False

    async def _execute_cmd_with_lock(self, cmd, cmd_id, callback, started):
        """Execute command with proper synchronization"""
        async with self._cmd_lock:
            self._ensure_open()
            started[0] = True
            self._used = True
            result = await self._cmd_coro(cmd, cmd_id)
            if callback is not None:
                try:
                    callback(result)
                except Exception as error:
                    self._loop.call_exception_handler({
                        "message": "Exception in r2pipe command callback",
                        "exception": error,
                    })
            return result

    def _cmd(self, cmd, **kwargs):
        return self._dispatch(self._command, cmd, kwargs)

    async def _command(self, cmd, kwargs):
        self._bind_loop()
        self._ensure_open()
        callback = kwargs.get("callback")
        cmd_id = self._next_cmd_id
        self._next_cmd_id += 1
        started = [False]
        task = self._loop.create_task(
            self._execute_cmd_with_lock(cmd, cmd_id, callback, started)
        )
        self._command_tasks.add(task)
        task.add_done_callback(self._command_done)
        try:
            # A canceled caller must not interrupt reading a command's response.
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if not started[0]:
                task.cancel()
            raise

    def _command_done(self, task):
        self._command_tasks.discard(task)
        self._consume_task_error(task)

    @staticmethod
    def _consume_task_error(task):
        if not task.cancelled():
            # Retrieve errors even when a canceled caller no longer awaits the task.
            task.exception()

    async def _json_command(self, cmd, kwargs, object_hook=None, report_error=False):
        result = await self._command(cmd, kwargs)
        if report_error and result == "":
            result = "{}"
        try:
            return json.loads(result, object_hook=object_hook)
        except (ValueError, KeyError, TypeError) as error:
            if not report_error:
                raise
            sys.stderr.write(f"r2pipe.cmdj.Error: {error}\n")
            return None

    def cmdj(self, cmd, **kwargs):
        if not self.asyn:
            return super().cmdj(cmd, **kwargs)
        return self._dispatch(self._json_command, cmd, kwargs, None, True)

    async def _object_command(self, cmd, kwargs):
        result = await self._command(cmd, kwargs)
        try:
            return jo2po(result)
        except (ValueError, KeyError, TypeError) as error:
            sys.stderr.write(f"r2pipe.cmdj.Error: {error}\n")
            return None

    def cmdJ(self, cmd, **kwargs):
        if not self.asyn:
            return super().cmdJ(cmd, **kwargs)
        return self._dispatch(self._object_command, cmd, kwargs)

    def _r2pipe2(self, cmd, kwargs):
        request, transport_kwargs = self._r2pipe2_request(cmd, kwargs)
        cmd = "'" + json.dumps(request)
        return self._dispatch(
            self._json_command, cmd, transport_kwargs, lambda value: SimpleNamespace(**value)
        )

    def cmd2(self, cmd, **kwargs):
        if not self.asyn:
            return super().cmd2(cmd, **kwargs)
        return self._r2pipe2(cmd, kwargs)

    async def _cmd_native_async(self, cmd, _cmd_id):
        if self._native_executor is None:
            self._native_executor = ThreadPoolExecutor(max_workers=1)
        return await self._loop.run_in_executor(
            self._native_executor, super()._cmd_native, cmd
        )

    async def _cmd_process(self, cmd, _cmd_id):
        # Process initialization if needed
        if not hasattr(self, "process"):
            if self.r2home is not None:
                if not os.path.isdir(self.r2home):
                    raise Exception(
                        "`radare2home` passed to `open` is invalid, leave it None or put a valid path to r2 folder"
                    )
                r2path = os.path.join(self.r2home, "radare2")
                if os.name == "nt":
                    r2path += ".exe"
            else:
                r2path = get_radare_path()

            create = asyncio.create_subprocess_exec(
                r2path,
                *self._process_start_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
            )

            self.process = await create  # Init the process

            # Track command execution state
            if not hasattr(self, "_pending_output"):
                self._pending_output = b""

            await self.process.stdout.read(1)  # Reads initial \x00

        # Clean command formatting
        cmd = cmd.strip().replace("\n", ";")

        # Write command to stdin
        await self.process.stdin.drain()  # Ensure any previous writes are complete
        self.process.stdin.write(bytes(cmd + "\n", "utf-8"))
        await self.process.stdin.drain()  # Ensure this write is complete

        # Read response with proper handling of pending data
        out = []

        # First check if we have pending output from previous commands
        if hasattr(self, "_pending_output") and self._pending_output:
            # Check if pending output contains a complete command response
            null_pos = self._pending_output.find(b"\x00")
            if null_pos != -1:
                # Extract the complete response and update pending
                response = self._pending_output[:null_pos]
                self._pending_output = self._pending_output[null_pos+1:]
                return response.decode("utf-8")

            # Add pending output to our current response
            out.append(self._pending_output)
            self._pending_output = b""

        # Read response byte by byte until null terminator
        buffer_size = 1024  # Read in larger chunks for efficiency
        while True:
            data = await self.process.stdout.read(buffer_size)

            if not data:
                raise ConnectionError("r2pipe connection closed before response terminator")

            null_pos = data.find(b"\x00")
            if null_pos != -1:
                # Found the terminator
                out.append(data[:null_pos])

                # Save any data after the null for future commands
                if null_pos < len(data) - 1:
                    self._pending_output = data[null_pos+1:]

                break
            else:
                out.append(data)

        # Join the output and convert to string
        return b"".join(out).decode("utf-8")

    async def _get_http_connection(self):
        """Get a connection from the pool or create a new one"""
        async with self._connection_lock:
            # Create a connection pool key
            pool_key = f"{self._host}:{self._port}"

            # Get or create the connection queue
            if pool_key not in self._connection_pool:
                self._connection_pool[pool_key] = []

            # Check if we have an available connection
            if self._connection_pool[pool_key]:
                # Reuse existing connection
                while self._connection_pool[pool_key]:
                    reader, writer = self._connection_pool[pool_key].pop(0)
                    if not reader.at_eof() and not writer.is_closing():
                        return reader, writer
                    writer.close()
                    with suppress(Exception):
                        await writer.wait_closed()

            # Create a new connection
            return await asyncio.open_connection(
                self._host, self._port
            )

    async def _return_http_connection(self, reader, writer):
        """Return a connection to the pool"""
        if writer.is_closing():
            return

        async with self._connection_lock:
            pool_key = f"{self._host}:{self._port}"

            # Only keep connections if within pool size limit
            if pool_key in self._connection_pool and len(self._connection_pool[pool_key]) < self._pool_size:
                self._connection_pool[pool_key].append((reader, writer))
            else:
                # Close the connection if pool is full
                writer.close()
                await writer.wait_closed()

    async def _cmd_http(self, cmd, cmd_id):
        """HTTP command execution with connection pooling and request ID tracking"""
        writer = None
        pooled = False
        try:
            quocmd = quote(cmd)

            # Get a connection from the pool
            reader, writer = await self._get_http_connection()

            # Create HTTP request with request ID tracking
            message = "\r\n".join(
                [
                    "GET /cmd/%s HTTP/1.1" % quocmd,
                    "Host: %s:%s" % (self._host, self._port),
                    "User-Agent: r2pipe/Python Client",
                    "Accept: */*",
                    "X-R2Pipe-Request-ID: %s" % cmd_id,
                    "Connection: keep-alive",  # Keep connection alive for pooling
                    "",
                    "",
                ]
            ).encode()

            # Send the request
            writer.write(message)
            await writer.drain()  # Ensure the request is fully sent

            # Read response with timeout to prevent hanging
            try:
                # Use a timeout to prevent hanging on incomplete responses
                body = []

                # Read response with proper chunking
                buffer_size = 4096  # Larger buffer size for efficiency

                # Header boundaries can span multiple transport reads.
                data = await asyncio.wait_for(
                    reader.readuntil(b'\r\n\r\n'),
                    timeout=10.0
                )
                header_lines = data[:-4].decode('utf-8', errors='ignore').split('\r\n')
                content_length = None
                connection = ""
                for line in header_lines[1:]:
                    if line.lower().startswith('content-length:'):
                        content_length = int(line.split(':', 1)[1].strip())
                        if content_length < 0:
                            raise ValueError("Invalid HTTP Content-Length")
                    elif line.lower().startswith('connection:'):
                        connection = line.split(':', 1)[1].strip().lower()
                keep_alive = content_length is not None and "close" not in connection and (
                    header_lines[0].startswith("HTTP/1.1 ") or "keep-alive" in connection
                )

                if content_length is not None:
                    remaining = content_length
                    while remaining > 0:
                        chunk = await asyncio.wait_for(
                            reader.read(min(buffer_size, remaining)),
                            timeout=5.0
                        )
                        if not chunk:
                            raise ConnectionError("Incomplete HTTP response body")
                        body.append(chunk)
                        remaining -= len(chunk)
                else:
                    # Responses without a length are delimited by connection close.
                    while True:
                        chunk = await asyncio.wait_for(
                            reader.read(buffer_size),
                            timeout=5.0
                        )
                        if not chunk:
                            break
                        body.append(chunk)

                # Reuse only responses whose framing and headers allow persistence.
                if keep_alive and not reader.at_eof():
                    await self._return_http_connection(reader, writer)
                    pooled = True

            except asyncio.TimeoutError as error:
                # If timeout occurs, close the connection
                writer.close()
                raise TimeoutError("Timeout while reading HTTP response") from error

            body = b"".join(body)
            return body.decode("utf-8", errors="ignore")

        finally:
            if writer is not None and not pooled:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()

    async def _get_tcp_connection(self):
        """Get a TCP connection from the pool or create a new one"""
        async with self._connection_lock:
            # Create a connection pool key
            pool_key = f"tcp:{self._host}:{self._port}"

            # Get or create the connection queue
            if pool_key not in self._connection_pool:
                self._connection_pool[pool_key] = []

            # Check if we have an available connection
            if self._connection_pool[pool_key]:
                # Reuse existing connection
                reader, writer = self._connection_pool[pool_key].pop(0)
                return reader, writer

            # Create a new connection
            return await asyncio.open_connection(
                self._host, self._port
            )

    async def _return_tcp_connection(self, reader, writer):
        """Return a TCP connection to the pool"""
        if writer.is_closing():
            return

        async with self._connection_lock:
            pool_key = f"tcp:{self._host}:{self._port}"

            # Only keep connections if within pool size limit
            if pool_key in self._connection_pool and len(self._connection_pool[pool_key]) < self._pool_size:
                self._connection_pool[pool_key].append((reader, writer))
            else:
                # Close the connection if pool is full
                writer.close()
                await writer.wait_closed()

    async def _cmd_tcp(self, cmd, _cmd_id):
        """TCP command execution with connection pooling"""
        writer = None
        pooled = False
        try:
            # Get a connection from the pool
            reader, writer = await self._get_tcp_connection()

            writer.write(cmd.encode("utf-8"))

            # Make sure the command is sent
            await writer.drain()

            try:
                # Read with proper timeout handling
                res = []
                buffer_size = 4096  # Larger buffer for efficiency

                # Read data with timeout
                first_chunk = await asyncio.wait_for(
                    reader.read(buffer_size),
                    timeout=10.0
                )

                if not first_chunk:
                    # Connection closed, create new one next time
                    writer.close()
                    raise ConnectionError("TCP connection closed by server")

                res.append(first_chunk)

                # Continue reading until we get all data
                # TCP mode indicates end of data by closing the connection
                # or by having no more data available after a timeout
                try:
                    while not reader.at_eof():
                        chunk = await asyncio.wait_for(
                            reader.read(buffer_size),
                            timeout=1.0  # Short timeout to detect end of response
                        )
                        if not chunk:
                            break
                        res.append(chunk)
                except asyncio.TimeoutError:
                    # A short timeout here means we've likely read everything
                    pass

                # TCP connections are often single-use in r2pipe
                # But we'll attempt to keep them alive for reuse
                if not reader.at_eof():
                    await self._return_tcp_connection(reader, writer)
                    pooled = True
                else:
                    # Connection was closed by server, close our end too
                    writer.close()

            except asyncio.TimeoutError as error:
                # If we timeout on the initial read, something is wrong
                writer.close()
                raise TimeoutError("Timeout while reading TCP response") from error

            # Process the response
            response_data = b"".join(res)

            return response_data.decode("utf-8", errors="ignore")

        finally:
            if writer is not None and not pooled:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()

    def wait(self, task):
        """Wait for awaitables and return completed futures in input order."""
        tasks = list(task) if isinstance(task, Iterable) else [task]
        return self._dispatch(self._wait, tasks)

    async def _wait(self, tasks):
        self._bind_loop()
        self._ensure_open()
        futures = []
        for task in tasks:
            future = asyncio.ensure_future(task, loop=self._loop)
            # A canceled wait() caller no longer receives these wrapper tasks.
            future.add_done_callback(self._consume_task_error)
            futures.append(future)
        if futures:
            await asyncio.wait(futures)
        return futures
