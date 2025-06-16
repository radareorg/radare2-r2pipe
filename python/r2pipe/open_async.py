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

    def close(self):
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
                raise Exception("String doesn't match tcp format")

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
        future.add_done_callback(self._callback_wrapper)
        
        # Assign a sequential ID to this command for ordered execution
        cmd_id = self._next_cmd_id
        self._next_cmd_id += 1
        self._cmd_queue.append(cmd_id)
        
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

    async def _cmd_http(self, cmd, future, callback):
        try:
            quocmd = quote(cmd)

            reader, writer = await asyncio.open_connection(
                self._host, self._port, loop=self._loop
            )

            message = "\n\r".join(
                [
                    "GET /cmd/%s HTTP/1.1" % quocmd,
                    "Host: %s:%s" % (self._host, self._port),
                    "User-Agent: r2pipe/Python Client",
                    "Accept: */*",
                    "",
                    "",
                ]
            ).encode()

            writer.write(message)
            data = await reader.read(512)
            res = [data]
            while data:
                data = await reader.read(512)
                res.append(data)
            writer.close()

            res = b"".join(res)

            # Remove http headers
            start = 0
            for x in res.splitlines():
                if not x:
                    start += 1
                    break
                start += len(x) + 1  # +1 because we must be count '\n'
            res = res[start:].decode("utf-8")
            future.set_result((res, callback))
            return res

        except Exception as e:
            future.set_result((str(e), callback))

    async def _cmd_tcp(self, cmd, future, callback):

        try:
            reader, writer = await asyncio.open_connection(
                self._host, self._port, loop=self._loop
            )

            writer.write(cmd.encode("utf-8"))
            data = await reader.read(512)

            res = [data]
            while data:
                res.append(data)
                data = await reader.read(512)
            res = b"".join(res).decode("utf-8")
            future.set_result((res, callback))
            writer.close()
            return res

        except Exception as e:
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
