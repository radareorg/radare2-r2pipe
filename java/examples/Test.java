import org.radare.r2pipe.R2Pipe;

public class Test {
	public static void main (String[] args) {
		try {
			R2Pipe r2p = new R2Pipe ("/bin/ls");
			//R2Pipe r2p = new R2Pipe ("http://cloud.rada.re/cmd/", true);
			System.out.println (r2p.cmd ("pd 10"));
			System.out.println ("==============");
			System.out.println (r2p.cmd ("px 32"));
			r2p.quit();
		} catch (Exception e) {
			System.err.println (e);
		}
	}
}
