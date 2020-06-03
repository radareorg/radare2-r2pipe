#!/usr/bin/env python
import sys
import r2pipe

r2p = r2pipe.open()
num = int(sys.argv[1])
if num == 0x80:
    r = r2p.cmdj("arj")
    if r["eax"] == 1:
        print "[SYSCALL EXIT] %d" % (r["ebx"])
    elif r["eax"] == 4:
        msg = r2p.cmd("psz %d@%d" % (r["edx"], r["ecx"]))
        print "[WRITE SYSCALL] ==> %s" % (msg)
elif num == 3:
    print "[INT3]"
else:
    print ("[unhandled SYSCALL %d]" % num)
