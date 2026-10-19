#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""r2pipe

This module provides an API to interact with the radare2
commandline interface from Python using a pipe.

The pipe can be connected to the parent process to run
Python scripts from the radare2 shell itself, or it can
spawn a new process, connect via HTTP to a remote r2 http
server, etc.

Some r2 commands display the information in JSON, that's
why r2pipe provides `-j` methods to directly parse it
and return a native Python object.

Example:
  $ python
  > import r2pipe
  > r = r2pipe.open("/bin/ls")
  > print(r.cmd("pd 10"))
  > print(r.cmdj("aoj")[0]['size']) > r.quit()
"""

import re

from r2pipe.open_sync import open
from r2pipe.open_base import OpenBase, in_r2, in_rlang, r2lang

VERSION = "2.1.0"


def parse_address(address):
    """Decode a hexadecimal wire address or a legacy integer as an exact uint64."""
    if isinstance(address, str):
        if not re.fullmatch(r"0[xX][0-9a-fA-F]+", address):
            raise ValueError("Address must be a hexadecimal string")
        address = int(address, 16)
    elif type(address) is not int:
        raise TypeError("Address must be an integer or hexadecimal string")
    if not 0 <= address <= 0xffffffffffffffff:
        raise ValueError("Address is outside the unsigned 64-bit range")
    return address


def version():
    """Return string with the version of the r2pipe library
        """
    return VERSION

def local_sessions():
    """Return list of local r2agent sessions
        Returns:
            Returns a list of dictionaries containing session information (uri, pid, file)
        """
    return OpenBase.local_sessions()


if __name__ == "__main__":
    import sys

    with open(sys.argv[1] if len(sys.argv) > 1 else "-", flags=["-N"]) as r2:
        print(r2.cmd("pi 5"))
        print(r2.cmdj("ij"))
