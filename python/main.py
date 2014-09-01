#/usr/bin/env python
import pexpect

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

if __name__ == "__main__":
  r3 = R2("/bin/ls")
  print ("PI: "+r3.cmd("pi 5"))
  print (r3.cmd("pn"))
