#[macro_use]
extern crate r2pipe;
use r2pipe::R2Pipe;

fn main() {
	let mut r2p = open_pipe!("/bin/ls").unwrap();
	println!("{}", r2p.cmd("?e Hello World"));
	let json = r2p.cmdj("ij");
	println!("{}", json.pretty());
	println!("ARCH {}", json.find_path(&["bin","arch"]).unwrap());
	r2p.close();
}
