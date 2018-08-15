# -*- coding: utf-8 -*-
"""open_async.py 
This script use code from r2pipe-async/open_p3.py script.

"""
import re
import asyncio

from collections import Iterable
from contextlib import ContextDecorator
from urllib.parse import quote, urlparse

from .open_base import OpenBase, get_radare_path

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

        def __init__(self, filename='', flags=[]):
                super(open, self).__init__(filename, flags)
                watcher = asyncio.get_child_watcher()
                
                self._loop = asyncio.new_event_loop()

                watcher.attach_loop(self._loop)

                self.asyn = True

                if filename.startswith("http"):
                        self._cmd_coro = self._cmd_http
                        self.uri = "/cmd"

                        _tmp = urlparse(filename)
                        self._host = _tmp.hostname
                        self._port = _tmp.port

                elif filename.startswith("ccall://"):
                        self._cmd_coro = self._cmd_native
                        self.uri = filename[7:]

                elif filename.startswith("tcp"):

                        r = re.match(r'tcp://(\d+\.\d+.\d+.\d+):(\d+)/?', filename)
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
                        self._processes = []

                else:
                        self.asyn = False
                        

        def _callback_wrapper(self, future):
                result, callback = future.result()

                if callback:
                        callback(result)

        def _cmd(self, cmd, **kwargs):
                # Get callback, if available
                callback = kwargs.get("callback")
                future = asyncio.Future(loop=self._loop)
                future.add_done_callback(self._callback_wrapper)

                task = self._loop.create_task(self._cmd_coro(cmd, future, callback))

                # Create and start a new task (coroutine)
                self._loop.run_until_complete(task)
                return task

        @asyncio.coroutine
        def _cmd_process(self, cmd, future, callback):
                create = asyncio.create_subprocess_exec(get_radare_path(),
                                                        *self._process_start_cmd,
                                                        shell=False,
                                                        stdin=asyncio.subprocess.PIPE,
                                                        stdout=asyncio.subprocess.PIPE,
                                                        loop=self._loop)

                process = yield from create  # Init the process

                yield from process.stdout.read(1)  # Reads initial \x00

                process.stdin.write(bytes(cmd + '\n', 'utf-8'))

                out = []
                while True:
                        # foo = self.process.stdout.read(1)
                        foo = yield from process.stdout.read(1)
                        if foo == b'\x00':
                                break
                        if len(foo) < 1:
                                return None
                        out.append(foo)

                process.stdin.close()
                process.kill()
                out = b"".join(out).decode('utf-8')
                future.set_result((out, callback))
                return out

        @asyncio.coroutine
        def _cmd_http(self, cmd, future, callback):
                try:
                        quocmd = quote(cmd)

                        reader, writer = yield from asyncio.open_connection(self._host,
                                                                            self._port,
                                                                            loop=self._loop)

                        message = "\n\r".join([
                                'GET /cmd/%s HTTP/1.1' % quocmd,
                                'Host: %s:%s' % (self._host, self._port),
                                'User-Agent: r2pipe/Python Client',
                                'Accept: */*',
                                '',
                                ''
                        ]).encode()

                        writer.write(message)
                        data = yield from reader.read(512)
                        res = [data]
                        while data:
                                data = yield from reader.read(512)
                                res.append(data)
                        writer.close()

                        res = b''.join(res)

                        # Remove http headers
                        start = 0
                        for x in res.splitlines():
                                if not x:
                                        start += 1
                                        break
                                start += len(x) + 1  # +1 because we must be count '\n'
                        res = res[start:].decode('utf-8')
                        future.set_result((res, callback))
                        return res

                except Exception as e:
                        future.set_result((str(e), callback))

        @asyncio.coroutine
        def _cmd_tcp(self, cmd, future, callback):

                try:
                        reader, writer = yield from asyncio.open_connection(self._host,
                                                                            self._port,
                                                                            loop=self._loop)

                        writer.write(cmd.encode('utf-8'))
                        data = yield from reader.read(512)

                        res = [data]
                        while data:
                                res.append(data)
                                data = yield from reader.read(512)
                        res = b''.join(res).decode('utf-8')
                        future.set_result((res, callback))
                        writer.close()
                        return res

                except Exception as e:
                        future.set_result((str(e), callback))

        def wait(self, task):
                """Wait until task finish"""
                _tasks = task
                if not isinstance(task, Iterable):
                        _tasks = [task]

                if self._loop.is_running():
                        asyncio.wait(_tasks, loop=self._loop)
