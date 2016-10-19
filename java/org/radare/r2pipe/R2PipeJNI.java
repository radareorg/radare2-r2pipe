package org.radare.r2pipe;

import java.io.*;
import java.net.*;

public class R2PipeJNI {
	static {
		try {
			System.loadLibrary("r2pipe-jni");
		} catch (UnsatisfiedLinkError e) {
			/* do nothing here */
		}
	}

	private static native long r2pipeNew();
	private static native String r2pipeCmd(long core, String cmd);
	private static native void r2pipeFree(long core);

	private long core = 0;

	public R2PipeJNI() throws Exception {
		this.core = r2pipeNew();
		if (this.core == 0) {
			throw new Exception("Cannot initialize r2pipe-jni");
		}
	}

	public R2PipeJNI(String file) throws Exception {
		this();
		this.cmd("o " + file);
	}

	public String cmd(String str) throws Exception {
		return r2pipeCmd(this.core, str);
	}

	protected void finalize() throws Throwable {
		quit();
	}

	public void quit() throws Exception {
		r2pipeFree(this.core);
		this.core = 0;
	}
}
