#[macro_use]
extern crate r2pipe;
use r2pipe::R2Pipe;

fn main() {
	let mut r2p = R2Pipe::spawn("/bin/ls".to_owned()).unwrap();
	println!("{}", r2p.cmd("?e Hello").unwrap());
	if let Err(_) = r2p.cmd("q") { // !killall r2") {
		println!("Quit happens!");
	} else {
		println!("Quit failed/ignored!");
		if let Ok(msg) = r2p.cmd("?e World") {
			println!("{}", msg);
			r2p.close();
		} else {
			println!("FAIL");
		}
	}
	println!("Byebye");
}
