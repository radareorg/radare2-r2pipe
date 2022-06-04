import r2pipe

r2 = r2pipe.open("-")
# r2.cmd("aa")
hello = r2.cmd("?e hello")
print(hello)
hello = r2.cmd("?e world")
print(hello)
