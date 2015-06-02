extern crate libc;
use libc::{ c_void };
use std::str;
use std::env;
use std::thread;


#[allow(improper_ctypes)]

fn atoi(k: &str) -> i32 {
  match k.parse::<i32>() {
    Ok(val) => val,
    Err(_) => 0
  }
}

fn getenv(k: &str) -> i32 {
  match env::var(k) {
  Ok(val) => atoi(&val),
  Err(_) => 0,
  }
}

  let fd_in = 9; //getenv("R2PIPE_IN");
  let fd_out = 12; //getenv("R2PIPE_OUT");

  if fd_in == 0 || fd_out == 0 {
    println!("Run this from r2 plz");
    return;
  }
  unsafe {
    let mut buf: [u8; 1024] = [0;1024];
    let cmd = "?e Hello World\n";

    let r = libc::write (fd_out, 
        cmd.as_ptr() as *const c_void,
        cmd.len() as u64);
    let ret = libc::write (fd_out, "\x00".as_ptr() as *const c_void, 1);

    let ret = libc::read (fd_in,
        buf.as_ptr() as *mut c_void,
        buf.len() as u64);

    let s = std::str::from_utf8(&buf).unwrap();
    println!("RD {} ->({})\n", ret, s);
  }
/*
  let mut f = FileDesc::new(fd_in, true);
  let buf = "Hello, world!\n".as_bytes();
  f.inner_write(buf);
*/
    println!("Using {} {} in rust!", fd_in, fd_out);

  unsafe {
    // -------- //
    libc::close (fd_in);
    libc::close (fd_out);
  }
fn main() {
  r2pipe::new
}
