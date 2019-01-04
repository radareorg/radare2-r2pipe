OUT=libr2pipe-jni.jnilib
JVH=org_radare_r2pipe_R2PipeJNI.h

JNIFLAGS+=-I /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.14.sdk/System/Library/Frameworks/JavaVM.framework/Headers/
JNIFLAGS+=-I /System/Library/Frameworks/JavaVM.framework/Headers/

all: $(JVH)
	$(CC) -o $(OUT) -dynamiclib -fPIC $(JNIFLAGS) r2pipe-jni.c -framework JavaVM

$(JVH): ../org/radare/r2pipe/R2PipeJNI.class
	javah -cp ../r2pipe.jar -d . org.radare.r2pipe.R2PipeJNI

clean:
	rm -f $(JVH) $(OUT)
