import r2pipe
import sys
import os

r2 = r2pipe.open("/bin/ls")
libpath = ["", ".", "/lib", "/usr/lib"]
output = "aa"
# output = 'dot'

done = {}


def findlib(lib):
    if os.path.isfile(lib):
        return lib
    for a in libpath:
        if os.path.isfile("%s/%s" % (a, lib)):
            return "%s/%s" % (a, lib)
    return []


def getlibs(lib):
    return r2.syscmdj("rabin2 -lj %s" % (lib))["libs"]


def filter(s):
    return s.replace("-", "_").replace("+", "x")


def makeNode(name):
    r2.cmd("agn %s" % (filter(name)))


def makeEdge(f, t):
    r2.cmd("age %s %s" % (filter(f), filter(t)))


def graphlibs(src, root):
    hs = src.replace("/", "_")
    hs = hs.replace("-", "_")
    hs = hs.replace("+", "x")
    try:
        if done[hs]:
            return
    except:
        done[hs] = True
    src = findlib(src)
    makeNode(src)
    for lib in getlibs(src):
        lib = findlib(lib)
        makeNode(lib)
        makeEdge(src, lib)
        graphlibs(lib, src)


if len(sys.argv) > 1:
    path = sys.argv[1]
    graphlibs(path, None)
    if output == "dot":
        print r2.cmd("aggd")
    else:
        print r2.cmd("e scr.color=true;agg")
    r2.quit()
else:
    print "Usage: libgraph.py [path-to-bin]"
    sys.exit(1)
