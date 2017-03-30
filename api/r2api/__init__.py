def ResultArray(o):
	self = []
	for a in o:
		self.append(Result(a))
	return self

class Result:
	def __init__(self, o):
		try:
			for a in o['bin']:
				if type(a) is dict:
					self[a] = {}
				else:
					setattr(self, a, o['bin'][a])
		except:
			for a in o:
				if type(a) is dict:
					setattr(self, a, {})
				else:
					setattr(self, a, o[a])

def r2_info(r2, cmd):
	return Result(r2.cmdj(cmd))

def session(r2):
	obj = {}
	obj.r2 = r2
	obj.info = r2_info
	return obj

class R2Api:
	def __init__(self, r2):
		self.r2 = r2
		# todo autogenerate methods here
		#self.info = lambda: self.r2.cmdj('ij')
		self._tmp_off = ''
		self.info = lambda: r2_info(self.r2, 'ij')
		self.searchIn = lambda x: self.r2.cmd('e search.in=%s'%(x))
		self.analyzeCalls = lambda: self.r2.cmd('aac')
		self.functions = lambda: ResultArray(self.r2.cmdj('aflj'))
		self.seek = lambda x: self.r2.cmd('s %s'%(x))

	def analyzeFunction(self):
		res = self.r2.cmd('af %s|'%(self._tmp_off))
		self._tmp_off = ''
		return res

	def disassembleFunction(self):
		res = self.r2.cmd('pdr %s|'%(self._tmp_off))
		self._tmp_off = ''
		return res

	def disassemble(self, x):
		res = self.r2.cmd('pd %s%s|'%(x,self._tmp_off))
		self._tmp_off = ''
		return res

	def hexdump(self, x):
		res = self.r2.cmd('px %s%s|'%(x,self._tmp_off))
		self._tmp_off = ''
		return res

	def at(self, x):
		self._tmp_off = "@ %s"%(x)
		return self
		
	def quit(self):
		self.r2.quit()
		self.r2 = None
