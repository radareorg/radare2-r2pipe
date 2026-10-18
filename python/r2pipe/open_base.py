# /usr/bin/env python3
# -*- coding: utf-8 -*-

"""open_base.py
base class for new open objects from open_sync and open_async. Code derived from __init__.py

"""

import os
import sys
import json
import shutil
import platform
from types import SimpleNamespace

from subprocess import Popen, PIPE

try:
    import r2lang
except ImportError:
    r2lang = None
try:
    from .native import RCore

    has_native = True
except ImportError:
    has_native = False

if os.name == "nt":
    from ctypes import byref, c_ulong, create_string_buffer, windll

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 0x3
    INVALID_HANDLE_VALUE = -1
    ERROR_PIPE_BUSY = 231
    BUFSIZE = 4096
    chBuf = create_string_buffer(BUFSIZE)
    cbRead = c_ulong(0)
    cbWritten = c_ulong(0)


def in_rlang():
    return r2lang is not None and r2lang.cmd is not None

def in_r2():
    """Return wheter r2pipe is called from radare2 environment or the system shell
        """
    try:
        a = int(os.environ["R2PIPE_IN"])
        b = int(os.environ["R2PIPE_OUT"])
        return a > 0 and b > 0
    except (ValueError, KeyError, TypeError):
        return False

def jo2po(jo):
    from collections import namedtuple

    def _json_object_hook(d):
        return namedtuple("X", d.keys(), rename=True)(*d.values())

    def json2obj(data):
        return json.loads(data, object_hook=_json_object_hook)

    return json2obj(jo)


def get_radare_path():
    bin_file = shutil.which("radare2")

    if bin_file and os.path.isfile(bin_file):
        return bin_file
    else:
        _platform = platform.system().lower()

        if _platform.startswith("darwin"):
            bin_file = "/usr/local/bin/radare2"
        else:
            bin_file = "/usr/bin/radare2"

        if os.path.isfile(bin_file):
            return bin_file
        else:
            raise IOError("radare2 can't be found in your system")


def _coerce_path_value(value):
    if isinstance(value, (str, bytes, os.PathLike)):
        return os.fsdecode(value)
    return value


def normalize_open_target(filename):
    file_args = []

    if isinstance(filename, (list, tuple)):
        if len(filename) > 1:
            file_args = [_coerce_path_value(arg) for arg in filename[1:]]
        filename = _coerce_path_value(filename[0] if filename else "")
        return filename, file_args

    original_filename = filename
    filename = _coerce_path_value(filename)

    if isinstance(original_filename, str) and " " in filename \
            and not filename.startswith(("http://", "tcp://", "ccall://", "#!pipe")):
        parts = filename.split(" ")
        filename = parts[0]
        file_args = parts[1:]

    return filename, file_args


class OpenBase:
    """Class representing an r2pipe connection with a running radare2 instance
        Class body derived from __init__.py "open" class.
        """

    def __init__(self, filename="", flags=None):
        """Open a new r2 pipe
                The 'filename' can be one of the following:

                * absolute or relative path to file
                * http://<host>:<port> to connect to an r2 webserver
                * tcp://<host>:<port> to connect to an r2 tcp server
                * #!pipe when launching it from r2 via RLang.pipe

                Args:
                    filename (str): path to filename or uri
                    flags (list of str): arguments, either in comapct form
                        ("-wdn") or sepparated by commas ("-w","-d","-n")
                Returns:
                    Returns an object with methods to interact with r2 via commands
                """
        filename = _coerce_path_value(filename)
        if flags is None:
            flags = []
        self.use_cache = False
        self.cache = {}
        self.asyn = False
        if not filename:
            if in_rlang():
                self._cmd = self._cmd_rlang
                return
            if not in_r2():
                raise EnvironmentError("No R2PIPE_IN or R2PIPE_OUT defined")
        try:
            if os.name == "nt":
                # if r2pipe_path environment is not set then fail below
                mypipename = os.environ["r2pipe_path"] # throws exception if not set
                # this logic is only when using r2pipe from INSIDE r2
                while True:
                    hPipe = windll.kernel32.CreateFileW(
                        mypipename,
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        None,
                        OPEN_EXISTING,
                        0,
                        None,
                    )
                    if hPipe != INVALID_HANDLE_VALUE:
                        break
                    err = windll.kernel32.GetLastError()
                    print("Invalid Handle Value")
                    if err != ERROR_PIPE_BUSY:
                        print("Could not open pipe:", hex(err))
                        return
                    elif (windll.kernel32.WaitNamedPipeW(mypipename, 20000)) == 0:
                        print("Named pipe is busy")
                        return
                self.pipe = [hPipe, hPipe]
            else:
                self.pipe = [
                    int(os.environ["R2PIPE_IN"]),
                    int(os.environ["R2PIPE_OUT"]),
                ]
            self._cmd = self._cmd_pipe
            self.url = "#!pipe"
            return
        except (KeyError, ValueError, OSError, NameError):
            pass
        if filename.startswith("#!pipe"):
            raise EnvironmentError("ERROR: Cannot use #!pipe without R2PIPE_{IN|OUT} env")

    def invalidate_cache(self):
        self.cache = {}

    def _cmd_pipe(self, cmd):
        if self.use_cache and self.cache.get(cmd) is not None:
            return self.cache[cmd]
        out = b""
        cmd = cmd.strip().replace("\n", ";")
        if os.name == "nt":
            cmd = cmd.encode("utf-8")
            windll.kernel32.WriteFile(
                self.pipe[1], cmd, len(cmd), byref(cbWritten), None
            )
            while True:
                windll.kernel32.ReadFile(
                    self.pipe[1], chBuf, BUFSIZE, byref(cbRead), None
                )
                out += chBuf.value
                if ord(chBuf[cbRead.value - 1]) == 0:
                    if len(out) > 0 and out[-1] == 0:
                        out = out[0:-1]
                    break
        else:
            os.write(self.pipe[1], cmd.encode())
            while True:
                res = os.read(self.pipe[0], 4096)
                if not res:
                    raise ConnectionError("r2pipe connection closed before response terminator")
                pos = res.find(b"\x00"[0])
                if pos != -1:
                    out += res[0:pos]
                    break
                out += res
        res = out.decode("utf-8")
        if self.use_cache:
            self.cache[cmd] = res
        return res

    def _cmd_native(self, cmd):
        if self.use_cache and self.cache.get(cmd) is not None:
            return self.cache[cmd]
        cmd = cmd.strip().replace("\n", ";")
        if not has_native:
            raise ImportError("No native ctypes connector available")
        if not hasattr(self, "native"):
            self.native = RCore()
            self.native.cmd_str("o " + self.uri)
        res = self.native.cmd_str(cmd)
        if isinstance(res, bytes):
            res = res.decode()
        if self.use_cache:
            self.cache[cmd] = res
        return res

    def _cmd_rlang(self, cmd):
        if self.use_cache and self.cache.get(cmd) is not None:
            return self.cache[cmd]
        res = r2lang.cmd(cmd)
        if self.use_cache:
            self.cache[cmd] = res
        return res

    def quit(self):
        """Quit current r2pipe session and kill
                """
        # HANGS self.cmd("q!!")
        if hasattr(self, "process"):
            import subprocess

            is_async = not isinstance(self.process, subprocess.Popen)
            if not is_async:
                for f in [self.process.stdin, self.process.stdout]:
                    if f is not None:
                        f.close()
            self.process.terminate()
            self.process.wait()
            delattr(self, "process")

            if is_async:
                import asyncio
                asyncio.get_event_loop().run_until_complete(asyncio.sleep(0.1))

    # r2pipe2
    @staticmethod
    def _r2pipe2_request(cmd, kwargs):
        options = kwargs.copy()
        callback = options.pop("callback", None)
        for name, value in options.items():
            if name not in ("trim", "json"):
                raise TypeError(f"Unexpected r2pipe2 option: {name}")
            if not isinstance(value, bool):
                raise TypeError(f"r2pipe2 option {name} must be a bool")
        if callback is not None and not callable(callback):
            raise TypeError("callback must be callable or None")
        request = {"cmd": cmd}
        request.update(options)
        return request, {"callback": callback} if callback is not None else {}

    def cmd2(self, cmd, **kwargs):
        """Run a JSON request with optional boolean trim/json flags and callback."""
        request, transport_kwargs = self._r2pipe2_request(cmd, kwargs)
        r = self.call(json.dumps(request), **transport_kwargs)
        return json.loads(r, object_hook=lambda d: SimpleNamespace(**d))

    def cmd2j(self, cmd, **kwargs):
        """Run cmd2() with trim/json enabled by default; explicit flags override."""
        kwargs.setdefault("trim", True)
        kwargs.setdefault("json", True)
        return self.cmd2(cmd, **kwargs)

    # r2 commands
    def call(self, cmd, *, callback=None):
        if callback is None:
            return self.cmd("'" + cmd)
        return self.cmd("'" + cmd, callback=callback)

    def cmd(self, cmd, **kwargs):
        """Run an r2 command return string with result
                Args:
                    cmd (str): r2 command
                Returns:
                    Returns an string with the results of the command
                """

        callback = kwargs.get("callback")
        if callback is not None and not callable(callback):
            raise TypeError("callback must be callable or None")
        if not self.asyn:
            kwargs.pop("callback", None)
        res = self._cmd(cmd, **kwargs)
        if not self.asyn and callback is not None:
            callback(res)
        return res

    def cmdj(self, cmd, **kwargs):
        """Same as cmd() but evaluates JSONs and returns an object
                Args:
                    cmdj (str): r2 command
                Returns:
                    Returns a JSON object respresenting the parsed JSON
                """
        result = self.cmd(cmd, **kwargs)
        if result == "":
            result = "{}"
        try:
            data = json.loads(result)
        except (ValueError, KeyError, TypeError) as e:
            sys.stderr.write(f"r2pipe.cmdj.Error: {e}\n")
            data = None
        return data

    def cmdJ(self, cmd, **kwargs):
        """Same as cmdj() but evaluates into a native Python Object
                Args:
                    cmdJ (str): r2 command
                Returns:
                    Returns a Python object respresenting the parsed JSON
                """
        result = self.cmd(cmd, **kwargs)
        try:
            return jo2po(result)
        except (ValueError, KeyError, TypeError) as e:
            sys.stderr.write(f"r2pipe.cmdj.Error: {e}\n")
        return None

    def syscmd(self, cmd):
        """Executes a program and returns the output (stdout only)
                Args:
                    cmd (str): commandline shell command
                Returns:
                    Returns a string with the output
                """
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
        out, _ = p.communicate()
        return out

    def syscmdj(self, cmd):
        """Executes a program and returns an object representing the parsed JSON of the output
                Args:
                    cmd (str): commandline shell command
                Returns:
                    Returns an object constructed by parsing the JSON returned by the command
                """
        try:
            data = json.loads(self.syscmd(cmd))
        except (ValueError, KeyError, TypeError) as e:
            sys.stderr.write(f"r2pipe.syscmdj.Error {e}\n")
            data = None
        return data

    @staticmethod
    def local_sessions():
        """Return list of local r2agent sessions
                Returns:
                    Returns a list of dictionaries containing session information (uri, pid, file)
                """
        try:
            result = Popen("r2agent -Lj", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            out, _ = result.communicate()
            if result.returncode != 0:
                return []
            try:
                data = json.loads(out.decode("utf-8"))
                return data if isinstance(data, list) else []
            except (ValueError, KeyError, TypeError):
                return []
        except OSError:
            return []
