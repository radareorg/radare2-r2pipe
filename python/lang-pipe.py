#!/usr/bin/env python3
import r2pipe

r2 = r2pipe.open("#!pipe")

_dis = r2.cmd("pd 5")
print(_dis)
_hex = r2.cmd("px 64")
print(_hex)
