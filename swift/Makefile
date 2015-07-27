TARGET=ios
TARGET=osx

SDKROOT=SDKROOT="$(shell xcrun --show-sdk-path --sdk ${SDK})"
SWIFTC=$(SDKROOT) xcrun -sdk $(SDK) swiftc 

ifeq ($(TARGET),ios)
SDK=iphoneos
CPU=arm64
IOS=8.3
SWIFTC+=-target $(CPU)-apple-ios$(IOS)
else
SDK=macosx
endif

all:
	$(SWIFTC) main.swift r2pipe.swift
