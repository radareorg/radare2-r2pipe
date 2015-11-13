import r2pipe

r2=r2pipe.open("/bin/ls", False, False, True)
for a in range(1,10):
	regs = r2.cmdj("drj")
	print "0x%x  0x%x"%(regs['rip'],regs['rsp'])
	r2.cmd("ds")
