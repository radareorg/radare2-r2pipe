import r2pipe

r2 = r2pipe.open("native:///bin/ls")
# r2 = r2pipe.open("/bin/ls")
print r2.cmd("x")
r2.quit()
