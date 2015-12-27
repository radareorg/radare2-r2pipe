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
IOS=8.4
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

clean:
	rm -f main
	rm -rf main.dSYM
