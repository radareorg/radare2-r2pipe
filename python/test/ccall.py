import r2pipe
r=r2pipe.open("ccall:///bin/ls")
print(r.cmd("x"))
r = None
