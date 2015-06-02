extern crate r2pipe;
use r2pipe::pipe::R2pipe;

fn main() {
    let p = String::from("-");
    let mut r2 = R2pipe::new(p);
    let mut cmd = String::from("aa");
    r2.cmd(cmd);
    let mut cmd = String::from("a?");
    let s = r2.cmd(cmd);
    println!("{}", s);
}
