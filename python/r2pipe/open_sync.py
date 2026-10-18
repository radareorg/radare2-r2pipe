#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""open_sync.py
This script use code from old __init__.py open object

"""

import re
import socket
import threading
import urllib
import os
from subprocess import Popen, PIPE
from urllib.error import URLError
from urllib.request import urlopen
from r2pipe.open_base import OpenBase, normalize_open_target


class open(OpenBase):
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self.quit()
        return False
    def __init__(self, filename="", flags=None, radare2home=None):
        filename, file_args = normalize_open_target(filename)

        super().__init__(filename, flags)
        if flags is None:
            flags = []
        self.pending = b''
        self._cmd_lock = threading.Lock()
        if filename.startswith("http://"):
            self._cmd = self._cmd_http
            self.uri = filename + "/cmd"
        elif filename.startswith("ccall://"):
            self._cmd = self._cmd_native
            self.uri = filename[8:]
        elif filename.startswith("tcp://"):
            r = re.match(r"tcp://(\d+\.\d+.\d+.\d+):(\d+)/?", filename)
            if not r:
                raise ValueError("String doesn't match tcp format")
            self._cmd = self._cmd_tcp
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((r.group(1), int(r.group(2))))
        elif filename:
            self._cmd = self._cmd_process
            if radare2home is not None:
                if not os.path.isdir(radare2home):
                    raise ValueError(
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
            r_args = [f"-Rarg{i+1}={a}" for i, a in enumerate(file_args)]
            cmd = [r2e, "-q0", filename]
            cmd = cmd[:1] + flags + r_args + cmd[1:]
            try:
                self.process = Popen(
                    cmd, shell=False, stdin=PIPE, stdout=PIPE, bufsize=0
                )
            except (OSError, FileNotFoundError) as e:
                raise FileNotFoundError("ERROR: Cannot find radare2 in PATH") from e

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
                except (IOError, OSError) as e:
                    raise IOError(f"ERROR: Cannot open {filename}") from e

    def _cmd_process(self, cmd):
        # Acquire lock to ensure commands don't interfere with each other
        with self._cmd_lock:
            old_pending = self.pending
            cmd = cmd.strip().replace("\n", ";")
            self.process.stdin.write((cmd + "\n").encode("utf8"))
            self.process.stdin.flush()
            self.pending = b""
            r = self.process.stdout
            out = bytearray()
            foo = None
            # First read any pending data from previous commands if exists
            if old_pending:
                zro = old_pending.find(b"\x00")
                if zro != -1:
                    # This is a complete response from previous command, process it first
                    out += old_pending[0:zro]
                    if zro + 1 < len(old_pending):
                        self.pending = old_pending[zro + 1:]
                    return out.decode("utf-8", errors="ignore")
            # Main read loop for current command
            while True:
                if self.process.poll() is not None:
                    raise RuntimeError(f"Process terminated unexpectedly trying to run the command {cmd}\n{self.process}")
                null_start = False
                if len(self.pending) > 0:
                    foo = self.pending
                    self.pending = b""
                else:
                    foo = r.read(4096)
                    if not foo:
                        raise ConnectionError("r2pipe connection closed before response terminator")
                    if os.name == "nt":
                        if foo.startswith(b"\x00"):
                            foo = foo[1:]
                            null_start = True
                if foo:
                    zro = foo.find(b"\x00")
                    if zro != -1:
                        out += foo[0:zro]
                        if zro + 1 < len(foo):
                            self.pending = foo[zro + 1:]
                        break
                    out += foo
                elif null_start:
                    break

            return out.decode("utf-8", errors="ignore")

    def _cmd_http(self, cmd):
        try:
            quocmd = urllib.parse.quote(cmd)
            response = urlopen(f"{self.uri}/{quocmd}")
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
