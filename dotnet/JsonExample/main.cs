using r2pipe;
using System;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace R2Net {
	public class Rasm2 {
		private IR2Pipe r2 = null;

		public string GetVersion() {
			return Cmd("?V").Trim();
		}

		public JObject CmdJ(string cmd) {
			string result = Cmd(cmd);
			return JObject.Parse(result);
		}

		public JArray CmdA(string cmd) {
			string result = Cmd(cmd);
			return JArray.Parse(result);
		}

		public string Cmd(string cmd) {
			if (r2 != null) {
				return r2.RunCommand(cmd);
			}
			return "";
		}

		public string GetInfo() {
			var info = CmdJ("ij");
			var a = info["core"]["type"];
			return info.ToString();;
		}

		public JArray Disasm() {
			return CmdA("pdj 4");
		}

		public void Kill() {
			this.r2 = null;
		}

		public Rasm2(string file) {
			this.r2 = new R2Pipe(file);
		}

		public static void Main(string[] args) {
			try {
				Rasm2 e = new Rasm2(args[0]);
				Console.WriteLine("r2 version: "+ e.GetVersion());
				Console.WriteLine("--> " + e.GetInfo());
				Console.WriteLine("--> " + e.Disasm().ToString());
				do {
					Console.Write("> ");
					var line = Console.ReadLine();
					if (line == "q") {
						break;
					}
					Console.WriteLine(e.Cmd(line));
				} while (true);

				e.Kill();
			} catch (Exception e) {
				Console.WriteLine(e.ToString());
			}
		}
	}
}
