package org.radare.r2pipe;

import java.io.*;
import java.net.*;

public class R2Pipe {
	private boolean viaHttp;
	private String file;

	Process process;
	InputStream stdout;
	OutputStream stdin;

	public R2Pipe(String file) throws Exception {
		// spawn process here
		spawnProcess(file);
	}

	public void spawnProcess (String file) throws Exception {
		process = Runtime.getRuntime ().exec("/usr/bin/r2 -q0 "+file);
		stdin = process.getOutputStream ();
		stdout = process.getInputStream ();
		byte[] b = new byte[1];
// read until \0 is found
		while (stdout.read (b) == 1) {
			if (b[0] == '\0')
				break;
		}
	}

	public R2Pipe(String file, boolean viaHttp) throws Exception {
		this.file = file;
		if (viaHttp) {
			this.viaHttp = viaHttp;
		} else {
			spawnProcess(file);
		}
	}

	public String cmd(String str) throws Exception {
		if (this.viaHttp)
			return httpCmd (str);

		stdin.write ((str+"\n").getBytes());
		stdin.flush();
		StringBuffer sb = new StringBuffer();
		byte[] b = new byte[1];
		while (stdout.read (b) == 1) {
			if (b[0] == 0)
				break;
			sb.append ((char)b[0]);
		}
		return sb.toString();
	}

	public String httpCmd(String str) {
		String output = "";
		try {
			// TODO: do proper URL encoding here
			str = str.replaceAll(" ", "%20");
			URL uri = new URL(this.file+""+str);
			URLConnection yc = uri.openConnection();
			BufferedReader in = new BufferedReader(
					new InputStreamReader(
						yc.getInputStream()));
			String inputLine;
			while ((inputLine = in.readLine()) != null) {
				output += inputLine + "\n";
			}
			in.close();
		} catch (Exception e) {
			System.err.println (e);
		}
		return output;
	}

	protected void finalize() throws Throwable {
		quit();
	}

	public void quit() throws Exception {
		if (!viaHttp)
			cmd ("q");
	}
}
