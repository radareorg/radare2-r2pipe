# -*- coding: utf-8 -*-

import re
import socket
import urllib
import urllib2

from subprocess import Popen, PIPE

from .open_base import OpenBase, get_radare_path

urlopen = urllib2.urlopen
URLError = urllib2.URLError


class open(OpenBase):
	
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
		else:
			self._cmd = self._cmd_process
			cmd = [get_radare_path(), "-q0", filename]
			cmd = cmd[:1] + flags + cmd[1:]
			self.process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE)
			self.process.stdout.read(1)  # Reads initial \x00

	def _cmd_process(self, cmd):
		self.process.stdin.write(cmd + '\n')
		self.process.stdin.flush()

		out = b''
		while True:
			foo = self.process.stdout.read(1)
			if foo == b'\x00':
				break
			if len(foo) < 1:
				return None
			out += foo

		return out.decode('utf-8')

	def _cmd_http(self, cmd):
		try:
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
