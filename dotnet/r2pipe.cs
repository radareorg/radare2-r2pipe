using System;
using System.Text;
using System.IO;
using System.Threading;
using System.Diagnostics;

using System.Collections.Generic;

namespace r2pipe {
	public delegate void CmdCallback (string res);

	public class CmdQueue {
		public string Command;
		public CmdCallback Callback;

		public CmdQueue(string cmd, CmdCallback cb) {
			this.Command = cmd;
			this.Callback = cb;
		}
		public override string ToString() {
			return Command;
		}
	}

	public class R2Pipe {
		List<CmdQueue> queue;
		StringBuilder outputBuilder;
		ProcessStartInfo psi;
		Process p;

		/*
		// Use this method for the synchronous api.. or just use a thread
		   private static string ReadToChar(StreamReader sr, char splitCharacter) {        
		   char nextChar;
		   StringBuilder line = new StringBuilder();
		   while (sr.Peek() > 0) {               
		   nextChar = (char)sr.Read();
		   if (nextChar == splitCharacter) return line.ToString();
		   line.Append(nextChar);
		   }
		   return line.Length == 0 ? null : line.ToString();
		   }
		 */

		public R2Pipe(string file = null) {
			this.queue = new List<CmdQueue> ();
			if (file == null)
				file = "-";
			psi = new ProcessStartInfo ();
			psi.CreateNoWindow = true;
			psi.RedirectStandardOutput = true;
			psi.RedirectStandardInput = true;
			psi.UseShellExecute = false;
			psi.Arguments = "-q0 "+file;
			psi.FileName = "/usr/bin/r2";

			p = new Process();
			p.StartInfo = psi;
			p.EnableRaisingEvents = true;
			queue.Add (new CmdQueue ("init", (x) => {
						Console.WriteLine ("Initialization is done");
					}));
			p.OutputDataReceived += new DataReceivedEventHandler (
					delegate (object sender, DataReceivedEventArgs e) {
					int token = e.Data.IndexOf ('\0');
					if (token != -1) {
						if (token >0) {
							string rest = e.Data.Substring (0, token);
							outputBuilder.Append (rest+"\n");
						}

						CmdQueue cq = queue[0];
						if (cq.Callback != null) {
							cq.Callback (""+outputBuilder);
						}
						queue.RemoveAt (0);

						outputBuilder = new StringBuilder();
						outputBuilder.Append (e.Data.Substring (token)+"\n");
					} else {
						//Console.WriteLine ("No token yet. go on");
						outputBuilder.Append (e.Data+"\n");
					}
				});
			p.Start ();
			// there's no way to read byte per byte asyncronously?
			p.BeginOutputReadLine();
		}

		public void Cmd(string c, CmdCallback cb = null) {
			StreamWriter sw = p.StandardInput;
			queue.Add (new CmdQueue (c, cb));
			// ;?e is a hackaround to bypass the imposibility to read byte-per-byte
			sw.WriteLine (c+";?e");
		}
		public void Quit () {
			this.Cmd ("q!");
			p.WaitForExit();
		}
	}
}
