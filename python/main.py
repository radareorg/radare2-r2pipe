#/usr/bin/env python
import pexpect
import json

class R2:
  def __init__(self, filename):
    self.process = pexpect.spawn('r2', ['-q0', filename])
    self._expect_eof_()
  
  def _expect_eof_(self):
    self.process.expect("\x00")
  
  def cmd(self, cmd):
    self.process.sendline(cmd)
    self._expect_eof_()
    return self.process.before

  def cmd_json(self, cmd):
    return json.loads(self.cmd(cmd))

if __name__ == "__main__":
  r3 = R2("/bin/ls")
  print ("PI: "+r3.cmd("pi 5"))
  print (r3.cmd("pn"))
  info = r3.cmd_json("ij")
  print ("Architecture: " + info['bin']['machine'])
