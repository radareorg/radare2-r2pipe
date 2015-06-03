extern crate r2pipe;
use r2pipe::pipe::R2pipe;

fn main() {
    let mut r2 = R2pipe::new("/bin/ls");
    let mut res: String;
    r2.cmd("aa");
    res = r2.cmd("a?");
    println!("{}", res);
}
