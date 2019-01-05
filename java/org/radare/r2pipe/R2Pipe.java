package org.radare.r2pipe;

import java.io.*;
import java.net.*;

// java7
import javax.json.*;

public class R2Pipe {
	private boolean viaHttp;
	private String file;
	Process process;
	InputStream stdout;
	OutputStream stdin;
	private String r2path = "radare2";

	public R2Pipe(String file) throws Exception {
		spawnProcess(file);
	}

	public R2Pipe(String file, String r2path, boolean viaHTTP) throws Exception {
		this.r2path = r2path;
		this.viaHttp = viaHttp;
		spawnProcess(file);
	}

	public void spawnProcess (String file) throws Exception {
		final String cmd = r2path + " -q0 " + file;
		process = Runtime.getRuntime ().exec(cmd);
		stdin = process.getOutputStream ();
		stdout = process.getInputStream ();
		byte[] b = new byte[1];
		// read until \0 is found
		while (stdout.read (b) == 1) {
			if (b[0] == '\0') {
				break;
			}
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

	public String cmd(String command) throws Exception {
		if (this.viaHttp) {
			return httpCmd (command);
		}
		stdin.write ((command+ "\n").getBytes());
		stdin.flush();
		StringBuffer sb = new StringBuffer();
		byte[] b = new byte[1];
		while (stdout.read (b) == 1) {
			if (b[0] == 0) {
				break;
			}
			sb.append ((char)b[0]);
		}
		return sb.toString();
	}

	public JsonObject cmdj(String command) throws Exception {
        	JsonReader reader = Json.createReader(new StringReader(this.cmd(command)));
		return reader.readObject();
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
		if (!viaHttp) {
			cmd ("q");
		}
	}
}
