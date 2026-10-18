import sys
import r2pipe

r2 = r2pipe.open(sys.argv[1] if len(sys.argv) > 1 else "malloc://2M", flags=[
    "-N", "-e", "scr.interactive=false", "-a", "arm", "-b", "32", "-e", "cfg.bigendian=true",
])
try:
    r2.cmd("e io.va=true")
    r2.cmd("e asm.emu=true")
    r2.cmd("on malloc://16K 0x10000000 rwx")
    r2.cmd("omn 0x10000000 sram_1")
    r2.cmd("on malloc://128M 0x20000000 rwx")
    r2.cmd("omn 0x20000000 sram_2")

    # Specify the virtual size explicitly: 4 MiB.
    before = {d["fd"] for d in r2.cmdj("oj")}
    r2.cmd('on "r2pipe://node test-r2io-plugin.js" 0x3c000000 rw 0x400000')
    added = [d["fd"] for d in r2.cmdj("oj") if d["fd"] not in before]
    assert len(added) == 1, added
    fd = added[0]
    r2.cmd("omn 0x3c000000 virtual_io")

    maps = [m for m in r2.cmdj("omj") if m["fd"] == fd]
    assert len(maps) == 1, maps
    assert maps[0]["from"] == 0x3c000000, maps
    assert maps[0]["to"] == 0x3c3fffff, maps
    assert r2.cmdj("pxj 4 @ 0x3c000000") == [1, 2, 3, 0]
    r2.cmd("wx deadbeef @ 0x3c000010")
    assert r2.cmdj("pxj 4 @ 0x3c000010") == [0xde, 0xad, 0xbe, 0xef]
    r2.cmd("wx a5 @ 0x3c3fffff")
    assert r2.cmdj("pxj 1 @ 0x3c3fffff") == [0xa5]
    # Exercise a transfer larger than the old 1024-byte backend limit.
    payload = bytes((i * 17 + i // 256) & 0xff for i in range(2048))
    for offset in range(0, len(payload), 512):
        r2.cmd(f"wx {payload[offset:offset + 512].hex()} @ {0x3c001000 + offset}")
    assert r2.cmdj("pxj 2048 @ 0x3c001000") == list(payload)
    print(r2.cmd("om"))
    print(r2.cmd("px 32 @ 0x3c000000"))
finally:
    r2.quit()
