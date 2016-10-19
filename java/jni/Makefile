OUT=libr2pipe-jni.jnilib
JVH=org_radare_r2pipe_R2PipeJNI.h

all: $(JVH)
	$(CC) -o $(OUT) -dynamiclib -fPIC \
		-I /System/Library/Frameworks/JavaVM.framework/Headers/ \
		r2pipe-jni.c -framework JavaVM

$(JVH): ../org/radare/r2pipe/R2PipeJNI.class
	javah -cp ../r2pipe.jar -d . org.radare.r2pipe.R2PipeJNI

clean:
	rm -f $(JVH) $(OUT)
