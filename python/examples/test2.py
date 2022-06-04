import r2pipe

r2 = r2pipe.open("-")
r2.cmd("aa")
hello = r2.cmd("?e hello").strip()
if hello != "hello":
    exit(1)
print(hello)
world = r2.cmd("?e world").strip()
if world != "world":
    exit(1)
print(world)
r2.quit()

r2 = r2pipe.open("-")
hello = r2.cmd("?e hello").strip()
if hello != "hello":
    exit(1)
print(hello)
world = r2.cmd("?e world").strip()
if world != "world":
    exit(1)
print(world)
