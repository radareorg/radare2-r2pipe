//! Provides functionality to connect with radare2.
//!
//! Please check crate level documentation for more details and example.

extern crate libc;
use self::libc::{ c_void };
use rustc_serialize::json::Json;

use std::process::Command;
use std::process::Stdio;
use std::process;
use std::env;
use std::str;
use std::path::Path;
use std::io::prelude::*;

/// File descriptors to the parent r2 process.
pub struct R2PipeLang {
	fd_in: i32,
	fd_out: i32
}

/// Stores descriptors to the spawned r2 process.
pub struct R2PipeSpawn {
	read: process::ChildStdout,
	write: process::ChildStdin,
}

/// Provides abstraction between the two invocation methods.
pub enum R2Pipe {
	Pipe(R2PipeSpawn),
	Lang(R2PipeLang),
}

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

#[macro_export]
macro_rules! open_pipe {
	($x:expr) => (R2Pipe::spawn($x));
	() => (R2Pipe::open());
}

impl R2Pipe {
	pub fn open() -> Result<R2Pipe, &'static str> {
		let (fin, fout) = match R2Pipe::in_session() {
			Some(x) => x,
			None => return Err("Pipe not open. Please run from r2"),
		};

		let _res = R2PipeLang { fd_in: fin, fd_out: fout };
		Ok(R2Pipe::Lang(_res))
	}

	pub fn cmd(&mut self, cmd: &str) -> String {
		match *self {
			R2Pipe::Pipe(ref mut x) => x.cmd(cmd),
			R2Pipe::Lang(ref mut x) => x.cmd(cmd),
		}
	}

	pub fn cmdj(&mut self, cmd: &str) -> Json {
		match *self {
			R2Pipe::Pipe(ref mut x) => x.cmdj(cmd),
			R2Pipe::Lang(ref mut x) => x.cmdj(cmd),
		}
	}

	pub fn close(&mut self) {
		match *self {
			R2Pipe::Pipe(ref mut x) => x.close(),
			R2Pipe::Lang(ref mut x) => x.close(),
		}
	}

	// XXX: must support windows
	pub fn in_session() -> Option<(i32, i32)> {
		let fin = getenv("R2PIPE_IN");
		let fout = getenv("R2PIPE_OUT");

		if fin == 0 || fout == 0 {
			return None;
		}

		return Some((fin, fout));
	}

	/// Creates a new R2PipeSpawn.
	pub fn spawn(_name: &str) -> Result<R2Pipe, &'static str> {
		if let Some(_) = R2Pipe::in_session() {
			return R2Pipe::open();
		}

		let name = _name.to_string();
		let path = Path::new(&*name);
		let child = match Command::new("r2")
			.arg("-q0")
			.arg(path)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.spawn() {
				Ok(c) => c,
				Err(_) => return Err("Unable to spawn r2."),
			};

		let sin: process::ChildStdin;
		let mut sout: process::ChildStdout;

		{
			sin = child.stdin.unwrap();
			sout = child.stdout.unwrap();
			// flush out the initial null byte.
			let mut w = [0;1];
			sout.read(&mut w).unwrap();
		}

		let _res = R2PipeSpawn {
			read: sout,
			write: sin
		};

		Ok(R2Pipe::Pipe(_res))
	}
}

impl R2PipeSpawn {
	pub fn cmd(&mut self, cmd: &str) -> String {
		let cmd_ = cmd.to_owned() + "\n";
		if let Err(e) = self.write.write(cmd_.as_bytes()) {
			panic!("{}", e);
		}
		// Read in block size of 2048.
		let mut s = [0; 2048];
		let mut res: String = String::new();

		loop { 
			let count = self.read.read(&mut s).unwrap();
			for c in s[..count].iter() {
				res = res + &*format!("{}", *c as char);
			}
			if count < 2048 {
				break;
			}
		}

		let len = res.len() - 1;
		res.truncate(len);
		res
	}

	pub fn cmdj(&mut self, cmd: &str) -> Json {
		let res = &self.cmd(cmd).replace("\n","");
		Json::from_str(res).unwrap()
	}

	pub fn close(&mut self) {
		self.cmd("q!");
	}
}

impl R2PipeLang {
	pub fn cmd(&mut self, cmd: &str) -> String {
		let buf: [u8; 1024] = [0;1024];
		unsafe {
			libc::write (self.fd_out, cmd.as_ptr() as *const c_void, cmd.len() as u64);
			libc::write (self.fd_out, "\x00".as_ptr() as *const c_void, 1);
			let len = libc::read (self.fd_in, buf.as_ptr() as *mut c_void, buf.len() as u64) as usize;
			let buf2 : Box<&[u8]> = Box::new(&buf[0..len-1]);
			let s = str::from_utf8(&buf2).unwrap();
			s.to_string()
		}
	}

	pub fn cmdj(&mut self, cmd: &str) -> Json {
		let res = &self.cmd(cmd).replace("\n","");
		Json::from_str(res).unwrap()
	}

	pub fn close(&mut self) {
		unsafe {
			libc::close (self.fd_in);
			libc::close (self.fd_out);
		}
	}
}
