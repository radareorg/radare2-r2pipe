import org.radare.r2pipe.R2PipeJNI;

public class TestJNI {
	public static void main (String[] args) {
		try {
			R2PipeJNI r2 = new R2PipeJNI ();
			r2.cmd ("o /bin/ls");
			System.out.println (r2.cmd ("pd 10"));
			System.out.println ("==============");
			System.out.println (r2.cmd ("px 32"));
			r2.quit();
		} catch (Exception e) {
			System.err.println (e);
		}
	}
}
