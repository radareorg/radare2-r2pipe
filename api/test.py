#!/usr/bin/env python

import r2pipe
from r2api import R2Api

r2q = R2Api(r2pipe.open("/bin/ls"))
if r2q.info().stripped:
	print "This binary is stripped"

r2q.searchIn('io.sections.exec')
r2q.analyzeCalls()
print r2q.at('entry0').hexdump(16)
print r2q.at('sym.imp.setenv').hexdump(16)

print r2q.at('entry0').disassemble(10)

print r2q.seek('entry0');
print r2q.analyzeFunction()
print r2q.disassembleFunction()
for fcn in r2q.functions():
	print fcn.name

r2q.quit()
