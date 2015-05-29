extern crate libc;
use libc::{ c_void };
use std::env;


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

fn main() {
  let fd_in = getenv("R2PIPE_IN");
  let fd_out = getenv("R2PIPE_OUT");

  if fd_in == 0 || fd_out == 0 {
    println!("Run this from r2 plz");
    return;
  }
  unsafe {
let mut data = [0;1024];
    let mut buf: [u8; 1024] = [0;1024];
    let cmd = "?e Hello World\n";

    let r = libc::write (fd_out, 
        cmd.as_ptr() as *const c_void,
        cmd.len() as u64);

    libc::write (fd_out, "\x00".as_ptr() as *const c_void, 1);

    println!("WR {} exp {}", r, cmd.len());
    //libc::perror("libc::write".as_ptr() as *const i8);
    
    let ret = libc::read (fd_in,
        buf.as_ptr() as *mut c_void,
        buf.len() as u64);
    println!("RD {}\n", ret);
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
}
