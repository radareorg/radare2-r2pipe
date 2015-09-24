#[macro_use]
extern crate r2pipe;
use r2pipe::R2Pipe;

fn main() {
	//let mut r2p = open_pipe!(None).unwrap();
	let mut r2p = match R2Pipe::in_session() {
		Some (_) => R2Pipe::open(),
		None => R2Pipe::spawn("/bin/ls".to_owned())
	}.unwrap();

	println!("{}", r2p.cmd("?e Hello World").unwrap());

	let json = r2p.cmdj("ij").unwrap();
	println!("{}", json.pretty());
	println!("ARCH {}", json.find_path(&["bin","arch"]).unwrap());

	// println!("BITS 0x{:x}",json.find_path(&["bin","bits"]).unwrap().as_u64().unwrap());
	if let Some(bits) = json.find_path(&["bin","bits"]) {
		if let Some(n_bits) = bits.as_u64() {
			println!("BITS 0x{:x}",n_bits);
		}
	}
	println!("Disasm:\n{}", r2p.cmd ("pd 20").unwrap());
	println!("Hexdump:\n{}", r2p.cmd ("px 64").unwrap());
	r2p.close();
}
