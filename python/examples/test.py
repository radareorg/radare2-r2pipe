import os
import r2pipe

r2 = r2pipe.open("/bin/ls")

print(r2pipe.__file__)
print(r2pipe.VERSION)

r2.cmd('aa')

pi1 = r2.cmd("pi 1 @e:scr.color=0").strip()
if pi1 == "push rbp":
	print("OK")
else:
	print("FAIL")
print(pi1)
#print (r2.cmd("pd 10"));
r2.quit()
