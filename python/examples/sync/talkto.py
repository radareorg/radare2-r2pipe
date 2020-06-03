#
# Author:
# - Sergi Alvarez
# - pancake@nopcode.org
#
# Requires:
# - r2 from git
# - r2pipe 0.9.0
# - r2pm -i lang-python
# - Python 2 or 3
#
# HowTo:
# - Run r2 -c=h /bin/ls
# - Run r2 -C http://localhost:9090/cmd/
# - Run r2 -i talkto.py /bin/ls
#

import r2pipe

try:
    r2 = r2pipe.open()
    r2.cmd("e cfg.user=pancake")
    r2.cmd("e cfg.log=true")

    r2.cmd("T this is me")
    r2.cmd("CC hello world")
    logs = r2.cmd("T")
    print (logs)
except:
    print ("You need r2pm -i lang-python")
    pass

last = ""
last2 = ""
r2r = r2pipe.open("http://localhost:9090")
r2r.cmd("e cfg.log=true")
print r2r.cmd("o")


def pull():
    global last2
    print "PULL"
    items = r2r.cmdj("Tj%s" % (last2))
    print "Syncing %s" % (last2)
    if len(items) > 0:
        print "ITEMS"
        for (id, msg) in items:
            print ("MUST RUN IN LOCAL %s" % (msg))
            r2.cmd("e cfg.log=0")
            r2.cmd(msg[1:])
            r2.cmd("e cfg.log=1")
            if id > last2 or last2 == "":
                last2 = id
        last2 = last2 + 1


def runmsg(msg):
    if msg[0] == ":":
        print ("RUN REMOTE %s" % (msg))
        r2r.cmd(msg[1:])
    elif msg[0] == "<":
        print ("CHAT %s" % (msg))
    else:
        print ("UNK %s" % (msg))


def sync():
    global last
    print "Syncing %s" % (last)
    items = r2.cmdj("Tj%s" % (last))
    if len(items) > 0:
        print "ITEMS"
        for (id, msg) in items:
            runmsg(msg)
            if id > last or last == "":
                last = id
        last = last + 1
        print ("LAST %s" % (last))
    pull()


# initialize
r2.cmd('"e cmd.log=#!python -e sync()"')
r2.cmd('"e cmd.prompt=#!python -e sync()"')
r2.cmd('"e cmd.vprompt=#!python -e sync()"')
