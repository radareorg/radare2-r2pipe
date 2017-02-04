import os
import r2pipe

r2 = r2pipe.open("/bin/ls")
print r2pipe.__file__
r2.cmd('aa')
#print r2.cmdj('aflj')
print (r2.cmd("pd 10"));
r2.quit()
