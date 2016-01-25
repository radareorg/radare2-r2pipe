TARGET=ios
TARGET=osx

SDKROOT=SDKROOT="$(shell xcrun --show-sdk-path --sdk ${SDK})"
SC=$(SDKROOT) xcrun -sdk $(SDK) swiftc
SFILES=r2pipe.swift

USE_SPAWN=1
USE_CCALL=1
USE_NSURL_SESSION=1
USE_ENV_PIPE=1

ifeq ($(TARGET),ios)
SDK=iphoneos
CPU=arm64
IOS=9.2
# IOS=9.0 # deprecates Sync methods? Use Just library?
SC+=-target $(CPU)-apple-ios$(IOS)
USE_NSURL_SESSION=1
else
SDK=macosx
endif

SFLAGS=
ifeq ($(USE_CCALL),1)
SFLAGS+=-D USE_CCALL
SFLAGS+=-Iccall
SFLAGS+=-L/usr/local/lib
endif
ifeq ($(USE_ENV_PIPE),1)
SFLAGS+=-D USE_ENV_PIPE
endif
ifeq ($(USE_SPAWN),1)
SFLAGS+=-D USE_SPAWN
SFILES+=r2pipeNative.swift
endif
ifeq ($(USE_NSURL_SESSION),1)
SFLAGS+=-D USE_NSURL_SESSION
endif

all:
	$(SC) $(SFLAGS) main.swift $(SFILES)

repl: lib
	@echo
	@echo
	@echo "import R2Pipe;"
	@echo "/* let r2p = R2Pipe(url:\"/bin/ls\")!; */"
	@echo "let r2p = R2Pipe(url:\"http://cloud.radare.org/cmd/\")!;"
	@echo "print(r2p.cmdSync(\"x\")!);"
	@echo
	@echo
	swift -I . -L . -lR2Pipe -module-link-name R2Pipe

lib:
	swiftc -emit-library -emit-object -module-name R2Pipe $(SFLAGS) $(SFILES)
	ar rcs libR2Pipe.a r2pipe.o r2pipeNative.o
	swiftc -emit-library -emit-module -module-name R2Pipe $(SFLAGS) $(SFILES)

clean:
	rm -f main
	rm -rf main.dSYM

.PHONY: lib repl all clean
