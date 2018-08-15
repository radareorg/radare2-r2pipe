# -*- coding: utf-8 -*-
"""open_sync.py 
This script use code from old __init__.py open object

"""

import re
import socket
import urllib
import urllib2
import os
from subprocess import Popen, PIPE
from .open_base import OpenBase, get_radare_path
urlopen = urllib2.urlopen
URLError = urllib2.URLError
try:
        import fcntl
except ImportError:
        fcntl = None


class  open(OpenBase):
                
        def __init__(self, filename='', flags=[]):
                super(open, self).__init__(filename, flags)
                if filename.startswith("http"):
                        self._cmd = self._cmd_http
                        self.uri = filename + "/cmd"
                elif filename.startswith("ccall://"):
                        self._cmd = self._cmd_native
                        self.uri = filename[7:]
                elif filename.startswith("tcp"):
                        r = re.match(r'tcp://(\d+\.\d+.\d+.\d+):(\d+)/?', filename)
                        if not r:
                                raise Exception("String doesn't match tcp format")
                        self._cmd = self._cmd_tcp
                        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.conn.connect((r.group(1), int(r.group(2))))
                elif filename:
                        self._cmd = self._cmd_process
                        cmd = ["radare2", "-q0", filename]
                        cmd = cmd[:1] + flags + cmd[1:]
                        try:
                               self.process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE)
                        except:
                                raise Exception("ERROR: Cannot find radare2 in PATH")
                        self.process.stdout.read(1)  # Reads initial \x00
                        # make it non-blocking to speedup reading
                        self.nonblocking = True
                        if self.nonblocking:
                                fd = self.process.stdout.fileno()
                                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)        

        def _cmd_process(self, cmd): 
                cmd = cmd.strip().replace("\n", ";")
                self.process.stdin.write(cmd + '\n')
                r = self.process.stdout
                self.process.stdin.flush()
                out = ''
                while True:
                        if self.nonblocking:
                                try:
                                        foo = r.read(4096)
                                except:
                                        continue
                        else:
                                foo = r.read(1)
                        if len(foo) > 0 and foo[-1] == '\x00':
                                out += foo[0:-1]
                                break
                        out += foo
                return out

        def _cmd_http(self, cmd):
                try:
                        try:
                                quocmd = urllib.parse.quote(cmd)
                        except:
                                quocmd = urllib.quote(cmd)
                        response = urlopen('{uri}/{cmd}'.format(uri=self.uri, cmd=quocmd))
                        return response.read().decode('utf-8')
                except URLError:
                         pass
                return None

        def _cmd_tcp(self, cmd):
                res = b''
                self.conn.sendall(str.encode(cmd, 'utf-8'))
                data = self.conn.recv(512)
                while data:
                        res += data
                        data = self.conn.recv(512)
                return res.decode('utf-8')
