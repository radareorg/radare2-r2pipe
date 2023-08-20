CFLAGS+=-Xcc -I/usr/local/include/libr
CFLAGS+=-Xcc -L/usr/local/lib

all:
	swiftc $(CFLAGS) -emit-library -module-name r2swift struct.c coreplugin.swift
# swiftc -O -o main coreplugin.swift main.swift
	swiftc $(CFLAGS) -o main struct.c coreplugin.swift main.swift
	mkdir -p $(shell r2 -H R2_USER_PLUGINS)
	cp -f libr2swift.dylib $(shell r2 -H R2_USER_PLUGINS)
	r2 -qc 'swift jeje' /bin/ls
