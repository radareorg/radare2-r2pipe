#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""open_sync.py
This script use code from old __init__.py open object

"""

import re
import signal
import socket
import urllib
import os
from subprocess import Popen, PIPE
from r2pipe.open_base import OpenBase

def no_urlopen():
  raise IOError
try:
  from urllib.error import URLError
  from urllib.request import urlopen
except:
  URLError = IOError
  urlopen = no_urlopen


try:
    import fcntl
except ImportError:
    fcntl = None


class open(OpenBase):
    def __init__(self, filename="", flags=[], radare2home=None):
        super(open, self).__init__(filename, flags)
        self.pipe_read_sleep = 0.001
        self.pending = b''
        if filename.startswith("http://"):
            self._cmd = self._cmd_http
            self.uri = filename + "/cmd"
        elif filename.startswith("ccall://"):
            self._cmd = self._cmd_native
            self.uri = filename[8:]
        elif filename.startswith("tcp://"):
            r = re.match(r"tcp://(\d+\.\d+.\d+.\d+):(\d+)/?", filename)
            if not r:
                raise Exception("String doesn't match tcp format")
            self._cmd = self._cmd_tcp
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((r.group(1), int(r.group(2))))
        elif filename:
            self._cmd = self._cmd_process
            if radare2home is not None:
                if not os.path.isdir(radare2home):
                    raise Exception(
                        "`radare2home` passed is invalid, leave it None or put a valid path to r2 folder"
                    )
                r2e = os.path.join(radare2home, "radare2")
            else:
                r2e = "radare2"
            if os.name == "nt":
                # avoid errors on Windows when subprocess messes with name
                r2e += ".exe"
                hello_cmd = False
            else:
                hello_cmd = True
            cmd = [r2e, "-q0", filename]
            cmd = cmd[:1] + flags + cmd[1:]
            try:
                self.process = Popen(
                    cmd, shell=False, stdin=PIPE, stdout=PIPE, bufsize=0
                )
            except:
                raise Exception("ERROR: Cannot find radare2 in PATH")

            if os.name == "nt":
                # On windows-spawn method we need to read the null byte twice
                self.process.stdout.read(1)  # Reads initial \x00
            if hello_cmd:
                self.process.stdout.read(1)  # Reads initial \x00
                try:
                    self.process.stdin.write(("?V\n").encode("utf8"))
                    self.process.stdin.flush()
                    r = self.process.stdout
                    while True:
                        ch = r.read(1)
                        if ch == b'\x00':
                            break
                except:
                    raise Exception("ERROR: Cannot open %s" % filename)

    @staticmethod
    def __make_non_blocking(fd):
        if fcntl is not None:
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            return True

        if os.name != "nt":
            raise NotImplementedError()

        import msvcrt
        from ctypes import windll, byref
        from ctypes.wintypes import HANDLE, DWORD, BOOL

        try:
            from ctypes import POINTER
        except:
            from ctypes.wintypes import POINTER

        LPDWORD = POINTER(DWORD)
        SetNamedPipeHandleState = windll.kernel32.SetNamedPipeHandleState
        SetNamedPipeHandleState.argtypes = [HANDLE, LPDWORD, LPDWORD, LPDWORD]
        SetNamedPipeHandleState.restype = BOOL

        h = msvcrt.get_osfhandle(fd)

        PIPE_NOWAIT = DWORD(0x00000001)
        res = windll.kernel32.SetNamedPipeHandleState(h, byref(PIPE_NOWAIT), None, None)
        return res != 0

    def _cmd_process(self, cmd):
        cmd = cmd.strip().replace("\n", ";")
        try:
            self.process.stdin.write((cmd + "\n").encode("utf8"))
        except:
            return ''
        r = self.process.stdout
        self.process.stdin.flush()
        out = bytearray()
        foo = None
        while True:
            if self.process.poll() == -11:
                raise RuntimeError(f'Segmentation fault detected {self.process}')
            try:
                null_start = False
                if len(self.pending) > 0:
                    foo = self.pending
                    self.pending = b""
                else:
                    foo = r.read(4096)
                    if os.name == "nt":
                        if foo.startswith(b"\x00"):
                            foo = foo[1:]
                            null_start = True
                if foo:
                    zro = foo.find(b"\x00")
                    if zro != -1:
                        out += foo[0:zro]
                        if zro  < len(foo):
                            self.pending = foo[zro + 1:]
                        break
                    out += foo
                elif null_start:
                    break

            except KeyboardInterrupt:
                os.kill(os.getpid(), signal.SIGINT)
            except:
                pass
        return out.decode("utf-8", errors="ignore")

    def _cmd_http(self, cmd):
        try:
            quocmd = urllib.parse.quote(cmd)
            response = urlopen("{uri}/{cmd}".format(uri=self.uri, cmd=quocmd))
            return response.read().decode("utf-8", errors="ignore")
        except URLError:
            pass
        return None

    def _cmd_tcp(self, cmd):
        res = b""
        self.conn.sendall(str.encode(cmd, "utf-8"))
        data = self.conn.recv(512)
        while data:
            res += data
            data = self.conn.recv(512)
        return res.decode("utf-8", errors="ignore")
