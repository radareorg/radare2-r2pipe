EXT_SO=$(shell r2 -H R2_LIBEXT)
OUT=libr2pipe-jni.$(EXT_SO)
JVH=org_radare_r2pipe_R2PipeJNI.h

JAVA_HOME?=$(shell /usr/libexec/java_home)
ifeq ($(JAVA_HOME),)
JAVA_HOME ?= $(shell dirname $(shell dirname $(shell readlink -f $(shell which javac))))
endif
JNI_INCLUDE = -I$(JAVA_HOME)/include
ifeq ($(shell uname),Darwin)
JNI_INCLUDE+= -I$(JAVA_HOME)/include/darwin
else
JNI_INCLUDE+= -I$(JAVA_HOME)/include/linux
endif

JNIFLAGS+=$(JNI_INCLUDE)
# /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.14.sdk/System/Library/Frameworks/JavaVM.framework/Headers/
# JNIFLAGS+=-I /System/Library/Frameworks/JavaVM.framework/Headers/

all: $(JVH)
	$(CC) -o $(OUT) -dynamiclib -fPIC $(JNIFLAGS) r2pipe-jni.c
#	-framework JavaVM

$(JVH): ../src/main/java/org/radare/r2pipe/R2PipeJNI.class
	javac -h . -d . ../src/main/java/org/radare/r2pipe/R2PipeJNI.java
#javac -h . org.radare.r2pipe.R2PipeJNI
# javah -cp ../r2pipe.jar -d . org.radare.r2pipe.R2PipeJNI

clean:
	rm -f $(JVH) $(OUT)
