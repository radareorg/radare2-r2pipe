#/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from ctypes import *
from ctypes.util import find_library

if sys.platform.startswith('win'):
	lib = WinDLL (find_library ('r_core'))
else:
	lib = CDLL (find_library ('r_core'))

class AddressHolder(object):
	def __get__(self, obj, type_):
		if getattr(obj, '_address', None) is None:
			obj._address = addressof(obj)
		return obj._address

	def __set__(self, obj, value):
		obj._address = value

class WrappedRMethod(object):
	def __init__(self, cname, args, ret):
		self.cname = cname
		self.args = args
		self.ret = ret
		self.args_set = False
		self.method = getattr(lib, cname)

	def __call__(self, *a):
		if not self.args_set:
			if self.args:
				self.method.argtypes = [eval(x.strip()) for x in self.args.split(',')]
			self.method.restype = eval(self.ret) if self.ret else None
			self.args_set = True
		return self.method(*a)

class WrappedApiMethod(object):
	def __init__(self, method, ret2, last):
		self.method = method
		self._o = None
		self.ret2 = ret2
		self.last = last

	def __call__(self, *a):
		result = self.method(self._o, *a)
		if self.ret2:
			result = eval(self.ret2)(result)
		if self.last:
			return getattr(result, self.last)
		return result

	def __get__(self, obj, type_):
		self._o = obj._o
		return self

def register(cname, args, ret):
	ret2 = last = None
	if ret:
		if ret[0]>='A' and ret[0]<='Z':
			x = ret.find('<')
			if x != -1:
				ret = ret[0:x]
			last = 'contents'
			ret = 'POINTER('+ret+')'
		else:
			last = 'value'
			ret2 = ret
			
	method = WrappedRMethod(cname, args, ret)
	wrapped_method = WrappedApiMethod(method, ret2, last)
	return wrapped_method, method


class RCore(Structure): #1
	def __init__(self):
		Structure.__init__(self)
		r_core_new = lib.r_core_new
		r_core_new.restype = c_void_p
		self._o = r_core_new ()

	_o = AddressHolder()

	cmd_str, r_core_cmd_str = register('r_core_cmd_str','c_void_p, c_char_p','c_char_p')
	free, r_core_free = register('r_core_free','c_void_p', 'c_void_p')

#c = RCore()
#c.cmd_str("o /bin/ls")
#print c
#print c.cmd_str("s entry0;pd 20");
#c.free();

