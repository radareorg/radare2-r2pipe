#!/usr/bin/env python
# TODO: add structs in pf
# TODO: specify flag sizes acordingly
# TODO: walk the dom using the api

import pfp
import sys
import os

if len(sys.argv) > 1:
    template = sys.argv[1]
    try:
        binfile = os.environ["FILE"]
    except:
        try:
            binfile = sys.argv[2]
        except:
            print "Missing file to parse"
            sys.exit(1)
else:
    print "Usage: 010-to-r2.py [template.bt] ([file])"
    print "> .!python 010-to-r2.py JPEGTemplate.bt"
    sys.exit(1)

# XXX pfp.parse show noisy messages
dom = pfp.parse(data_file=binfile, template_file=template)


def filterFlagName(x):
    x = x.replace("[", "_")
    x = x.replace("]", "_")
    return x


rows = dom._pfp__show(include_offset=True)
structName = ""
for line in rows.split("\n"):
    isStruct = line.find("struct") != -1
    line = line.strip()
    line = line.split("=")[0]
    if line[0] == "}":
        continue
    line = "0x" + line
    cols = line.split(" ")
    if isStruct:
        structName = cols[1]
    else:
        fn = structName + "." + cols[1]
        flagName = "struct." + filterFlagName(fn)
        print "f " + flagName + " = " + cols[0]
