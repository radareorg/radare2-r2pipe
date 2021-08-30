import r2pipe
import sys

# _pipe = r2pipe.open("ccall://" + sys.argv[1], flags=["-2", "-S"])
_pipe = r2pipe.open(sys.argv[1], flags=["-2"]) #, "-S"])
res = _pipe.cmdj('iIj')
if res is None:
    print("{} - FAIL".format(sys.argv[1]))
