using System;
using System.Threading;
using System.Threading.Tasks;
using r2pipe;

public class MainClass {
	public static int Main(String[] args) {
		var doAsync = true;
/*
		var web = new R2PipeHttp("http://cloud.rada.re/cmd/");
		//r2p.Cmd
		web.Cmd("?V", (version) => {
			Console.WriteLine ("Version: {0}", version);
		});
*/
		R2Pipe r2p = new R2Pipe("/bin/ls", doAsync);
		if (doAsync) {
			//r2p.Cmd ("e scr.color=false;?e pop");
			r2p.Cmd ("e scr.color=false");
			r2p.Cmd ("x", (res) => {
					Console.WriteLine ("RESULT 'x' {\n"+res+"\n}");
					});
			r2p.Cmd ("pi 10", (res) => {
					Console.WriteLine ("RESULT 'pi 10' {\n"+res+"\n}");
					});
			r2p.Quit ();
		} else {
			// Cant mix sync and async
			Console.WriteLine ("Hello r2! "+ r2p.CmdSync("?V"));
			Console.WriteLine ("Hexdump!\n"+ r2p.CmdSync("px"));
			//r2p.QuitSync ();
		}
		return 0;
	}
}
