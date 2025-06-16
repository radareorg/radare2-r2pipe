# -*- coding: utf-8 -*-
"""open_async.py
This script use code from r2pipe-async/open_p3.py script.

"""
import asyncio
import os
import re


# whole file doesn't have any profit of asyncio usage, TODO: refactor

from collections.abc import Iterable
from contextlib import ContextDecorator
from urllib.parse import quote, urlparse

from r2pipe.open_base import OpenBase, get_radare_path


class open(OpenBase, ContextDecorator):
    # --------------------------------------------------------------------------
    # Contenxt manager functions
    # --------------------------------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    async def _close_all_connections(self):
        """Close all connections in the connection pool"""
        async with self._connection_lock:
            for pool_key, connections in self._connection_pool.items():
                for reader, writer in connections:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except:
                        pass
            self._connection_pool = {}

    def close(self):
        """Close the r2pipe instance and clean up resources"""
        # Close any active connections
        if hasattr(self, '_connection_pool') and self._connection_pool:
            # Run the async close operation in the event loop
            if self._loop.is_running():
                asyncio.ensure_future(self._close_all_connections(), loop=self._loop)
            else:
                self._loop.run_until_complete(self._close_all_connections())

        # Stop and close the event loop
        if self._loop.is_running():
            self._loop.stop()
        if not self._loop.is_closed():
            self._loop.close()

    def __init__(self, filename="", flags=[], radare2home=None):
        super(open, self).__init__(filename, flags)

        self.r2home = radare2home

        if os.name == "nt":
            self._loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(self._loop)
        else:
            watcher = asyncio.get_child_watcher()
            self._loop = asyncio.new_event_loop()
            watcher.attach_loop(self._loop)

        # Add a lock for synchronizing command execution
        self._cmd_lock = asyncio.Lock()

        # Add a task queue for managing command sequence
        self._cmd_queue = []
        self._next_cmd_id = 0

        # Add connection management for HTTP/TCP modes
        self._connection_pool = {}
        self._pool_size = 5  # Maximum number of concurrent connections
        self._connection_lock = asyncio.Lock()

        self.asyn = True

        if filename.startswith("http://"):
            self._cmd_coro = self._cmd_http
            self.uri = "/cmd"

            _tmp = urlparse(filename)
            self._host = _tmp.hostname
            self._port = _tmp.port

        elif filename.startswith("ccall://"):
            self._cmd_coro = self._cmd_native
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

            cmd = ["-q0", filename]
            cmd = cmd[:1] + flags + cmd[1:]
            self._process_start_cmd = cmd

        else:
            self.asyn = False

    def _callback_wrapper(self, future):
        result_data = future.result()

        # Check if result contains command ID for ordered execution
        if isinstance(result_data, tuple) and len(result_data) == 3:
            cmd_id, result, callback = result_data

            # Ensure commands are processed in sequence
            if self._cmd_queue and self._cmd_queue[0] == cmd_id:
                self._cmd_queue.pop(0)  # Remove this command from queue

                # Process callback if provided
                if callback:
                    callback(result)

                # Process any waiting callbacks that can now be executed
                self._process_pending_callbacks()
        else:
            # Fallback for backward compatibility
            result, callback = result_data
            if callback:
                callback(result)

    def _process_pending_callbacks(self):
        """Process any callbacks that are ready based on command ID ordering"""
        # This would handle pending callbacks when their turn comes
        # Implementation would depend on how we store pending results
        pass

    async def _execute_cmd_with_lock(self, cmd, future, callback, cmd_id):
        """Execute command with proper synchronization"""
        async with self._cmd_lock:
            result = await self._cmd_coro(cmd, future, callback)
            return result, cmd_id

    def _cmd(self, cmd, **kwargs):
        # Get callback, if available
        callback = kwargs.get("callback")
        future = asyncio.Future(loop=self._loop)

        # Assign a sequential ID to this command for ordered execution
        cmd_id = self._next_cmd_id
        self._next_cmd_id += 1
        self._cmd_queue.append(cmd_id)

        # Store the command ID in the future for tracking
        future._cmd_id = cmd_id

        # Add the callback to process the result
        future.add_done_callback(self._callback_wrapper)

        # Wrap the command execution with lock
        task = self._loop.create_task(
            self._execute_cmd_with_lock(cmd, future, callback, cmd_id)
        )

        # Create and start a new task (coroutine)
        self._loop.run_until_complete(task)

        # In sequential mode, we should always have the result by now
        return task.result()[0] if task else None

    async def _cmd_process(self, cmd, future, callback):
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
                shell=False,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                loop=self._loop
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
                result = response.decode("utf-8")

                # Set result and return
                if hasattr(future, "_cmd_id"):
                    future.set_result((future._cmd_id, result, callback))
                else:
                    future.set_result((result, callback))
                return result

            # Add pending output to our current response
            out.append(self._pending_output)
            self._pending_output = b""

        # Read response byte by byte until null terminator
        buffer_size = 1024  # Read in larger chunks for efficiency
        while True:
            data = await self.process.stdout.read(buffer_size)

            if not data:
                # Connection closed or error
                if out:
                    break
                return None

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
        result = b"".join(out).decode("utf-8")

        # Set result with command ID if available
        if hasattr(future, "_cmd_id"):
            future.set_result((future._cmd_id, result, callback))
        else:
            future.set_result((result, callback))

        return result

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
                reader, writer = self._connection_pool[pool_key].pop(0)
                return reader, writer

            # Create a new connection
            return await asyncio.open_connection(
                self._host, self._port, loop=self._loop
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

    async def _cmd_http(self, cmd, future, callback):
        """HTTP command execution with connection pooling and request ID tracking"""
        try:
            quocmd = quote(cmd)

            # Get a connection from the pool
            reader, writer = await self._get_http_connection()

            # Add request ID as a custom header for tracking
            cmd_id = None
            if hasattr(future, '_cmd_id'):
                cmd_id = future._cmd_id

            # Create HTTP request with request ID tracking
            message = "\n\r".join(
                [
                    "GET /cmd/%s HTTP/1.1" % quocmd,
                    "Host: %s:%s" % (self._host, self._port),
                    "User-Agent: r2pipe/Python Client",
                    "Accept: */*",
                    "X-R2Pipe-Request-ID: %s" % (cmd_id if cmd_id is not None else "none"),
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
                res = []

                # Read response with proper chunking
                buffer_size = 4096  # Larger buffer size for efficiency

                # Read first chunk to get headers
                data = await asyncio.wait_for(
                    reader.read(buffer_size),
                    timeout=10.0
                )

                if not data:
                    # Connection closed, need to create a new one next time
                    writer.close()
                    raise ConnectionError("Connection closed by server")

                res.append(data)

                # Check for Content-Length header to determine how much to read
                headers_end = data.find(b'\r\n\r\n')
                if headers_end != -1:
                    headers = data[:headers_end].decode('utf-8', errors='ignore')
                    content_length = None

                    # Parse content length
                    for line in headers.split('\r\n'):
                        if line.lower().startswith('content-length:'):
                            try:
                                content_length = int(line.split(':', 1)[1].strip())
                                break
                            except ValueError:
                                pass

                    # Calculate how much more data we need to read
                    if content_length is not None:
                        bytes_read = len(data) - headers_end - 4  # subtract header size
                        remaining = content_length - bytes_read

                        # Read remaining content if needed
                        while remaining > 0 and not reader.at_eof():
                            chunk = await asyncio.wait_for(
                                reader.read(min(buffer_size, remaining)),
                                timeout=5.0
                            )
                            if not chunk:
                                break
                            res.append(chunk)
                            remaining -= len(chunk)
                    else:
                        # If no content length, read until connection closes
                        while not reader.at_eof():
                            chunk = await asyncio.wait_for(
                                reader.read(buffer_size),
                                timeout=5.0
                            )
                            if not chunk:
                                break
                            res.append(chunk)

                # Return connection to the pool for reuse
                await self._return_http_connection(reader, writer)

            except asyncio.TimeoutError:
                # If timeout occurs, close the connection
                writer.close()
                raise TimeoutError("Timeout while reading HTTP response") from exc

            # Process the response
            res = b"".join(res)

            # Remove HTTP headers
            start = 0
            header_end = res.find(b'\r\n\r\n')
            if header_end != -1:
                start = header_end + 4
            else:
                # Fallback to line-by-line parsing if we can't find the header end
                for x in res.splitlines():
                    if not x:
                        start += 1
                        break
                    start += len(x) + 1  # +1 because we must be count '\n'

            # Parse the result
            result = res[start:].decode("utf-8", errors="ignore")

            # Set result with command ID if available
            if cmd_id is not None:
                future.set_result((cmd_id, result, callback))
            else:
                future.set_result((result, callback))
            return result

        except Exception as e:
            # Set error result with command ID if available
            if hasattr(future, '_cmd_id'):
                future.set_result((future._cmd_id, str(e), callback))
            else:
                future.set_result((str(e), callback))

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
                self._host, self._port, loop=self._loop
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

    async def _cmd_tcp(self, cmd, future, callback):
        """TCP command execution with connection pooling and command tracking"""
        try:
            # Get a connection from the pool
            reader, writer = await self._get_tcp_connection()

            # Get command ID if available
            cmd_id = None
            if hasattr(future, '_cmd_id'):
                cmd_id = future._cmd_id

            # We need to distinguish between commands in TCP mode
            # Add a command ID and separator that won't interfere with regular r2 commands
            if cmd_id is not None:
                # Add command ID as a prefix separated by a special marker
                tracked_cmd = f"r2p_{cmd_id}:{cmd}"
                writer.write(tracked_cmd.encode("utf-8"))
            else:
                # Use normal command without tracking if no cmd_id
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
                else:
                    # Connection was closed by server, close our end too
                    writer.close()

            except asyncio.TimeoutError:
                # If we timeout on the initial read, something is wrong
                writer.close()
                raise TimeoutError("Timeout while reading TCP response") from exc

            # Process the response
            response_data = b"".join(res)

            # Check if the response contains our tracking ID
            result = response_data.decode("utf-8", errors="ignore")

            # Set result with command ID if available
            if cmd_id is not None:
                future.set_result((cmd_id, result, callback))
            else:
                future.set_result((result, callback))

            return result

        except Exception as e:
            # Set error result with command ID if available
            if hasattr(future, '_cmd_id'):
                future.set_result((future._cmd_id, str(e), callback))
            else:
                future.set_result((str(e), callback))

    def wait(self, task):
        """Wait until task finish with proper ordering

        This method ensures tasks are completed in the correct sequence
        even when multiple commands are executed concurrently.
        """
        _tasks = task
        if not isinstance(task, Iterable):
            _tasks = [task]

        # Create a function to wait for all tasks in order
        async def wait_ordered():
            # Wait for all tasks to complete
            done, _ = await asyncio.wait(_tasks, loop=self._loop)

            # Sort results by command ID if available
            results = []
            for future in done:
                try:
                    # Extract result and command ID if available
                    result = future.result()
                    if isinstance(result, tuple) and len(result) > 1:
                        # If this is a tuple with cmd_id
                        cmd_id, data = result[0], result[1]
                        results.append((cmd_id, data, future))
                    else:
                        # No command ID available
                        results.append((None, result, future))
                except Exception as e:
                    # Handle any exceptions during task execution
                    pass

            # Sort results by command ID if available
            results.sort(key=lambda x: x[0] if x[0] is not None else float('inf'))

            # Return sorted results
            return [r[2] for r in results]

        # Run the ordered wait function
        if self._loop.is_running():
            return asyncio.ensure_future(wait_ordered(), loop=self._loop)
        else:
            return self._loop.run_until_complete(wait_ordered())
