extern crate r2pipe;
use r2pipe::R2Pipe;

fn main() {
	if let Some(_) = R2Pipe::in_session() {
		let r2p = R2Pipe::open();
		println!("{}", r2p.cmd("?e Hello World"));
		let json = r2p.cmdj("ij");
		println!("{}", json.pretty());
		println!("ARCH {}", json.find_path(&["bin","arch"]).unwrap());
		r2p.close();
	} else {
		let mut r2p = R2Pipe::spawn("/bin/ls");
		println!("{}", r2p.cmd("?e Hello World"));
		let json = r2p.cmdj("ij");
		println!("{}", json.pretty());
		println!("ARCH {}", json.find_path(&["bin","arch"]).unwrap());
		r2p.close();
	}
}
