/* jni interface for r2pipe -- pancake 2016 */

#include "org_radare_r2pipe_R2PipeJNI.h"
#include <string.h>
#include <dlfcn.h>
#include <jni.h>

static void* (*r_core_new)(void) = NULL;
static void (*r_core_free)(void *core);
static char* (*r_core_cmd_str)(void *core, const char *cmd);

static bool initLibrary() {
	if (r_core_new) {
		return true;
	}
	void *rCore = dlopen ("/usr/local/lib/libr_core.dylib", RTLD_LAZY);
	if (!rCore) {
		perror ("dlopen");
		return false;
	}
	r_core_new = dlsym (rCore, "r_core_new");
	r_core_free = dlsym (rCore, "r_core_free");
	r_core_cmd_str = dlsym (rCore, "r_core_cmd_str");
	return r_core_new != NULL;
}

JNIEXPORT jlong JNICALL Java_org_radare_r2pipe_R2PipeJNI_r2pipeNew (JNIEnv *env, jobject thiz) {
	if (initLibrary ()) {
		return (jlong) (size_t) r_core_new ();
	}
	return 0;
}

JNIEXPORT jstring JNICALL Java_org_radare_r2pipe_R2PipeJNI_r2pipeCmd
(JNIEnv *env, jobject thiz, jlong core, jstring cmd) {
	if (core) {
		void *cCore = (void*) (size_t) core;
		const char *cCmd = (*env)->GetStringUTFChars(env, cmd, NULL);
		return (*env)->NewStringUTF(env, r_core_cmd_str (cCore, cCmd));
	}
	return (*env)->NewStringUTF(env, "");
}

JNIEXPORT void JNICALL Java_org_radare_r2pipe_R2PipeJNI_r2pipeFree(JNIEnv *env, jobject thiz, jlong core) {
	if (core) {
		void *c = (void*) (size_t) core;
		r_core_free (c);
	}
}
