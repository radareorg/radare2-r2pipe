#/usr/bin/env python

import os
import re
import sys
import time
import json
import socket
from subprocess import Popen, PIPE

if sys.version_info >= (3,0):
	import urllib.request
	urlopen = urllib.request.urlopen
	import urllib.error
	URLError = urllib.error.URLError
else:
	import urllib2
	urlopen = urllib2.urlopen
	URLError = urllib2.URLError

class r2pipeException(Exception):
	pass

def version():
	return "0.4"

class open:
	def __init__(self, filename, writeable=False, bininfo=True):
		try:
			self.pipe = [ int(os.environ['R2PIPE_IN']), int(os.environ['R2PIPE_OUT']) ]
			self._cmd = self._cmd_pipe
			self.url = "#!pipe"
			return
		except:
			pass
		if filename.startswith("#!pipe"):
			print("ERROR: Cannot use #!pipe without R2PIPE_{IN|OUT} env")
			return
		if filename.startswith("http"):
			self._cmd = self._cmd_http
			self.uri = filename + "/cmd"
		elif filename.startswith("tcp"):
			r = re.match(r'tcp://(\d+\.\d+.\d+.\d+):(\d+)/?', filename)
			if not r:
				raise r2pipeException("String doesn't match tcp format")
			self._cmd = self._cmd_tcp
			self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.conn.connect((r.group(1), int(r.group(2))))
		else:
			self._cmd = self._cmd_process
			cmd = ["r2", "-q0", filename]
			if writeable:
				cmd = cmd[:1] + ["-w"] + cmd[1:]
			if not bininfo:
				cmd = cmd[:1] + ["-n"] + cmd[1:]
			self.process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE)
			self.process.stdout.read(1) # Reads initial \x00

	def _cmd_process(self, cmd):
		if sys.version_info >= (3,0):
			self.process.stdin.write(bytes(cmd+'\n','utf-8'))
		else:
			self.process.stdin.write(cmd+'\n')
		self.process.stdin.flush()
		out = b''
		while True:
			foo = self.process.stdout.read(1)
			if foo == b'\x00':
				break
			if len(foo)<1:
				return None
			out += foo
		return out[:-1].decode('utf-8')

	def _cmd_tcp(self, cmd):
		res = b''
		self.conn.sendall(str.encode(cmd, 'utf-8'))
		data = self.conn.recv(512)
		while data:
			res += data
			data = self.conn.recv(512)
		return res.decode('utf-8')

	def _cmd_pipe(self, cmd):
		out = ''
		os.write (self.pipe[1], cmd)
		while True:
			res = os.read (self.pipe[0], 1024)
			if (len(res)<1):
				break
			out += res
			if res[-1] == b'\x00':
				break
		return out[:-1].decode('utf-8')

	def _cmd_http(self, cmd):
		try:
			response = urlopen('{uri}/{cmd}'.format(uri=self.uri, cmd=cmd))
			return response.read().decode('utf-8')
		except URLError:
			pass
		return None

	# r2 commands
	def cmd(self, cmd):
		return self._cmd(cmd)

	def cmdj(self, cmd):
		return self.cmd_json(cmd)

	def cmd_json(self, cmd):
		try:
			data = json.loads(self.cmd(cmd))
		except (ValueError, KeyError, TypeError) as e:
			sys.stderr.write ("r2pipe.cmd_json.Error: %s\n"%(e))
			data = None
		return data

	# system commands
	def syscmd(self, cmd):
		p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
		out, err = p.communicate()
		return out

	def syscmdj(self, cmd):
		return self.syscmd_json(cmd)

	def syscmd_json(self, cmd):
		try:
			data = json.loads(self.syscmd(cmd))
		except (ValueError, KeyError, TypeError) as e:
			sys.stderr.write ("r2pipe.syscmd_json.Error %s\n"%(e))
			data = None
		return data

# Hello World
if __name__ == "__main__":
	print("[+] Spawning r2 tcp and http servers")
	system ("pkill r2")
	system ("r2 -qc.:9080 /bin/ls &")
	system ("r2 -qc=h /bin/ls &")
	time.sleep(1)
	# Test r2pipe with local process
	print("[+] Testing python r2pipe local")
	rlocal = open("/bin/ls")
	print(rlocal.cmd("pi 5"))
	#print rlocal.cmd("pn")
	info = rlocal.cmd_json("ij")
	print ("Architecture: " + info['bin']['machine'])

	# Test r2pipe with remote tcp process (launch it with "r2 -qc.:9080 myfile")
	print("[+] Testing python r2pipe tcp://")
	rremote = open("tcp://127.0.0.1:9080")
	disas = rremote.cmd("pi 5")
	if not disas:
		print("Error with remote tcp conection")
	else:
		print(disas)

	# Test r2pipe with remote http process (launch it with "r2 -qc=H myfile")
	print("[+] Testing python r2pipe http://")
	rremote = open("http://127.0.0.1:9090")
	disas = rremote.cmd("pi 5")
	if not disas:
		print("Error with remote http conection")
	else:
		print(disas)
	system ("pkill -INT r2")
