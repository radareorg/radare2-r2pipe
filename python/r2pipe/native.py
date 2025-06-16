#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from ctypes import Structure, addressof, c_char_p, c_void_p, c_int, c_uint, c_float, c_double, c_long, POINTER
from ctypes.util import find_library

try:
    from ctypes import CDLL
except ImportError:
    pass

try:
    from ctypes import WinDLL
except ImportError:
    pass

lib = None

# Safe mapping of type names to actual types
CTYPES_MAP = {
    'c_void_p': c_void_p,
    'c_char_p': c_char_p,
    'c_int': c_int,
    'c_uint': c_uint,
    'c_float': c_float,
    'c_double': c_double,
    'c_long': c_long,
    'POINTER': POINTER
}

def get_ctype_from_name(name):
    """Safely convert a string type name to an actual ctypes type"""
    name = name.strip()
    if name in CTYPES_MAP:
        return CTYPES_MAP[name]
    elif name.startswith('POINTER(') and name.endswith(')'):
        # Handle pointer types like POINTER(c_void_p)
        inner_type = name[8:-1]  # Extract the inner type
        if inner_type in CTYPES_MAP:
            return POINTER(CTYPES_MAP[inner_type])
    # If we don't know this type, raise an error
    raise ValueError(f"Unsupported type: {name}")

def r2lib():
    global lib
    if lib is not None:
        return lib
    lib_name = find_library("r_core")
    if lib_name is None:
        return None
    try:
        if sys.platform.startswith("win"):
            lib = WinDLL(lib_name)
        else:
            lib = CDLL(lib_name)
        return lib
    except OSError as err:
        # print(err)
        pass
    return None

class AddressHolder(object):
    def __get__(self, obj, type_):
        if getattr(obj, "_address", None) is None:
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
        r2 = r2lib()
        if r2 is not None:
            self.method = getattr(r2, cname)
        else:
            raise ImportError("Cannot use ccall")

    def __call__(self, *a):
        if not self.args_set:
            if self.args:
                self.method.argtypes = [get_ctype_from_name(x) for x in self.args.split(",")]
            self.method.restype = get_ctype_from_name(self.ret) if self.ret else None
            self.args_set = True
        a = list(a)
        for i, argt in enumerate(self.method.argtypes):
            if argt is c_char_p:
                a[i] = a[i].encode()
        res = self.method(*a)
        if isinstance(res, bytes):
            return res.decode()
        return res

class WrappedApiMethod(object):
    def __init__(self, method, ret2, last):
        self.method = method
        self._o = None
        self.ret2 = ret2
        self.last = last

    def __call__(self, *a):
        result = self.method(self._o, *a)
        if self.ret2:
            if self.ret2 == "c_char_p":
                return result
            else:
                result = get_ctype_from_name(self.ret2)(result)
        if self.last:
            return getattr(result, self.last)
        return result

    def __get__(self, obj, type_):
        self._o = obj._o
        return self

def register(cname, args, ret):
    ret2 = last = None
    if ret:
        if ret[0] >= "A" and ret[0] <= "Z":
            x = ret.find("<")
            if x != -1:
                ret = ret[0:x]
            last = "contents"
            ret = "POINTER(" + ret + ")"
        else:
            last = "value"
            ret2 = ret

    method = WrappedRMethod(cname, args, ret)
    wrapped_method = WrappedApiMethod(method, ret2, last)
    return wrapped_method, method

class RCore(Structure):
    def __init__(self):
        Structure.__init__(self)
        r2 = r2lib()
        if r2 is None:
            return
        r_core_new = r2.r_core_new
        r_core_new.restype = c_void_p
        self._o = r_core_new()
        self._r_core_cmd_str = register(
            "r_core_cmd_str", "c_void_p, c_char_p", "c_char_p"
        )
        self._r_core_free = register("r_core_free", "c_void_p", "c_void_p")
    def __del__(self):
        self.free()
    def free(self):
        self._r_core_free[0](self._o)
    def cmd_str(self, cmd):
        return self._r_core_cmd_str[1](self._o, cmd)

### self._o = AddressHolder()
#  c = r2pipe.native.RCore()
#  c.cmd_str("o /bin/ls")
#  print(c)
#  print(c.cmd_str("s entry0;pd 20"))
#  c.free();
