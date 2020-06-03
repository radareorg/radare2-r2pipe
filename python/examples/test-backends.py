# /usr/bin/env python

import r2pipe
from os import system
import time

if __name__ == "__main__":
    print("[+] Spawning r2 tcp and http servers")
    system("pkill r2")
    system("radare2 -qc.:9080 /bin/ls &")
    system("radare2 -qc=h /bin/ls &")
    time.sleep(1)

    # Test r2pipe with local process
    print("[+] Testing python r2pipe local")
    rlocal = r2pipe.open("/bin/ls")
    print(rlocal.cmd("pi 5"))
    # print rlocal.cmd("pn")
    info = rlocal.cmdj("ij")
    print("Architecture: " + info["bin"]["machine"])

    # Test r2pipe with remote tcp process (launch it with "radare2 -qc.:9080 myfile")
    print("[+] Testing python r2pipe tcp://")
    rremote = r2pipe.open("tcp://127.0.0.1:9080")
    disas = rremote.cmd("pi 5")
    if not disas:
        print("Error with remote tcp conection")
    else:
        print(disas)

    # Test r2pipe with remote http process (launch it with "radare2 -qc=H myfile")
    print("[+] Testing python r2pipe http://")
    rremote = r2pipe.open("http://127.0.0.1:9090")
    disas = rremote.cmd("pi 5")
    if not disas:
        print("Error with remote http conection")
    else:
        print(disas)
    system("pkill -INT r2")
