#!/usr/bin/env python3

import r2pipe
import sys

r = r2pipe.open("/bin/ls")
try:
    print("r2 version: %s" % r.cmd("?V"))
    pid = int(r.cmd("?vi $p"))
    print("Killing r2 PID %d" % (pid))
    r.cmd('"!(sleep 1; kill -9 %d) &"' % pid)
    r.cmd("!sleep 3")
    print(r.cmd("x"))
    r.cmd("q")
    print("This was not expected!")
except:
    print("r2 was killed as expected")
    sys.exit(0)

sys.exit(1)
