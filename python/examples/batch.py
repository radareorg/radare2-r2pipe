import os
import r2pipe

r2 = r2pipe.open("http://cloud.radare.org")
print(r2.cmd("?e one"))
r2.quit()

r2 = r2pipe.open("/bin/ls")
print(r2.cmd("?e one"))
print(r2.cmd("?e two"))
r2.quit()

r2 = r2pipe.open("/bin/ls")
os.system("ps auxw| grep radare2")
print(r2.cmd("?e tri"))
r2.quit()

os.system("ps auxw| grep radare2")
