#!/usr/bin/env python3
#
# Author: pancake@nopcode.org // radare2 2015
#
# $ r2 -qc '#!pipe python ipython.py' /bin/ls
#

import os
import sys
import r2pipe
import IPython

r2 = None
try:
    pipes = [int(os.environ["R2PIPE_IN"]), int(os.environ["R2PIPE_OUT"])]
    r2 = r2pipe.open("#!pipe")
except:
    print("This script must be run from inside r2:")
    print(" $ r2 -qi ipython.py /bin/ls")
    sys.exit(1)


class RadareBin:
    r2 = None

    def __init__(self, r2):
        self.r2 = r2
        self.baddr = 0
        self.filename = r2.cmd("i~file:0[1]").strip()

    def imports(self):
        if self.baddr != 0:
            return self.r2.syscmdj(
                "rabin2 -B %d -ij '%s'" % (self.baddr, self.filename)
            )["imports"]
        else:
            return self.r2.syscmdj("rabin2 -ij '%s'" % (self.filename))["imports"]

    def symbols(self):
        if self.baddr != 0:
            return self.r2.syscmdj(
                "rabin2 -B %d -sj '%s'" % (self.baddr, self.filename)
            )["symbols"]
        else:
            return self.r2.syscmdj("rabin2 -sj '%s'" % (self.filename))["symbols"]

    def entries(self):
        if self.baddr != 0:
            return self.r2.syscmdj(
                "rabin2 -B %d -ej '%s'" % (self.baddr, self.filename)
            )["entries"]
        else:
            return self.r2.syscmdj("rabin2 -ej '%s'" % (self.filename))["entries"]


class Radare:
    r2 = None
    Bin = None

    def __init__(self, r2):
        self.r2 = r2
        self.Bin = RadareBin(r2)

    def seek(self, address):
        if type(address) == int:
            address = str(address)
        self.r2.cmd("s %s" % (address))
        return self

    def disasm(self, *arg):  # address, count):
        address = ""
        count = 16
        if len(arg) > 0:
            address = arg[0]
            if type(address) == int:
                address = str(address)
            if len(arg) > 1:
                count = arg[1]
        print(self.r2.cmd("e scr.color=true;pd %d @ %s" % (count, address)))
        return self

    def hexdump(self, address, count):
        if type(address) == int:
            address = str(address)
        print(self.r2.cmd("e scr.color=true;px %d @ %s" % (count, address)))
        return self


r = Radare(r2)
r.disasm("entry0", 10)
r.hexdump("entry0", 10)

# Enter the shell
IPython.embed()
