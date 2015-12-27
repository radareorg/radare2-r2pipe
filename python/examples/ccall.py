import r2pipe

r2 = r2pipe.open("ccall:///bin/ls")
# r2 = r2pipe.open("/bin/ls")
# r2.cmd("o /bin/ls")
print r2.cmd("pd 10")
r2.quit()
