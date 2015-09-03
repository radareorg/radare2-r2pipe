TARGET=ios
TARGET=osx

SDKROOT=SDKROOT="$(shell xcrun --show-sdk-path --sdk ${SDK})"
SWIFTC=$(SDKROOT) xcrun -sdk $(SDK) swiftc 
SWIFT_FILES=r2pipe.swift

HAVE_SPAWN=1
USE_NSURL_SESSION=0
USE_ENV_PIPE=1

ifeq ($(TARGET),ios)
SDK=iphoneos
CPU=arm64
IOS=8.4
# IOS=9.0 # deprecates Sync methods? Use Just library?
SWIFTC+=-target $(CPU)-apple-ios$(IOS)
USE_NSURL_SESSION=1
else
SDK=macosx
endif

SWIFTFLAGS=
ifeq ($(USE_ENV_PIPE),1)
SWIFTFLAGS+=-D USE_ENV_PIPE
endif
ifeq ($(HAVE_SPAWN),1)
SWIFTFLAGS+=-D HAVE_SPAWN
SWIFT_FILES+=r2pipeSpawn.swift
endif
ifeq ($(USE_NSURL_SESSION),1)
SWIFTFLAGS+=-D USE_NSURL_SESSION
endif

all:
	$(SWIFTC) $(SWIFTFLAGS) main.swift $(SWIFT_FILES)
