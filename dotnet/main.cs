using System;
using r2pipe;

public class MainClass {
	public static int Main(String[] args) {
		Console.WriteLine ("Hello r2!");
		R2Pipe r2p = new R2Pipe();
		//r2p.Cmd ("e scr.color=false;?e pop");
		r2p.Cmd ("e scr.color=false");
		r2p.Cmd ("x", (res) => {
			Console.WriteLine ("RESULT 'x' {\n"+res+"\n}");
		});
		r2p.Cmd ("pi 10", (res) => {
			Console.WriteLine ("RESULT 'pi 10' {\n"+res+"\n}");
		});
		r2p.Quit ();
		return 0;
	}
}
