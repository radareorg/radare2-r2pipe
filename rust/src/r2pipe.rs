//! Provides functionality to connect with radare2.
//!
//! Please check crate level documentation for more details and example.

use std::os::unix::io::FromRawFd;
use rustc_serialize::json::Json;

use libc;
use std::process::Command;
use std::process::Stdio;
use std::process;
use std::env;
use std::str;
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

/// File descriptors to the parent r2 process.
pub struct R2PipeLang {
	read: BufReader<File>,
	write: File,
}

/// Stores descriptors to the spawned r2 process.
pub struct R2PipeSpawn {
	read: BufReader<process::ChildStdout>,
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
		Err(_) => -1 
	}
}

fn getenv(k: &str) -> i32 {
	match env::var(k) {
		Ok(val) => atoi(&val),
		Err(_) => -1,
	}
}

fn process_result(res:Vec<u8>) -> Result<String, String> {
	let len = res.len();
	let out = if len > 0 {
		let res_without_zero = &res[..len-1];
		if let Ok (utf8str) = str::from_utf8(res_without_zero) {
			String::from(utf8str)
		} else {
			return Err("Failed".to_owned());
		}
	} else {
		"".to_owned()
	};
	Ok(out)
}

#[macro_export]
macro_rules! open_pipe {
	($x: expr) => {
		match $x {
			Some(path) => R2Pipe::spawn(path),
			None => R2Pipe::open(),
		}
	}
}

impl R2Pipe {
	pub fn open() -> Result<R2Pipe, &'static str> {
		let (fin, fout) = match R2Pipe::in_session() {
			Some(x) => x,
			None => return Err("Pipe not open. Please run from r2"),
		};
		let _res = unsafe {
			/* dup file descriptors to avoid from_raw_fd ownership issue */
			let (din, dout) = (libc::dup(fin), libc::dup(fout));
			R2PipeLang {
				read: BufReader::new(File::from_raw_fd(din)),
				write: File::from_raw_fd(dout)
			}
		};
		Ok(R2Pipe::Lang(_res))
	}

	pub fn cmd(&mut self, cmd: &str) -> Result<String,String> {
		match *self {
			R2Pipe::Pipe(ref mut x) => x.cmd(cmd),
			R2Pipe::Lang(ref mut x) => x.cmd(cmd),
		}
	}

	pub fn cmdj(&mut self, cmd: &str) -> Result<Json,String> {
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
		if fin < 0 || fout < 0 {
			return None;
		}
		return Some((fin, fout));
	}

	/// Creates a new R2PipeSpawn.
	pub fn spawn(name: String) -> Result<R2Pipe, &'static str> {
		if name == "" {
			if let Some(_) = R2Pipe::in_session() {
				return R2Pipe::open();
			}
		}

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

		let sin = child.stdin.unwrap();
		let mut sout = child.stdout.unwrap();

		// flush out the initial null byte.
		let mut w = [0;1];
		sout.read(&mut w).unwrap();

		let _res = R2PipeSpawn {
			read: BufReader::new(sout),
			write: sin
		};

		Ok(R2Pipe::Pipe(_res))
	}
}

impl R2PipeSpawn {
	pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
		let cmd_ = cmd.to_owned() + "\n";
		if let Err(e) = self.write.write(cmd_.as_bytes()) {
			return Err(e.to_string())
		}

		let mut res: Vec<u8> = Vec::new();
		if let Err(e) = self.read.read_until(0u8, &mut res) {
			return Err(e.to_string())
		}
		process_result (res)
	}

	pub fn cmdj(&mut self, cmd: &str) -> Result<Json, String> {
		let res = &self.cmd(cmd).unwrap();
		Ok(Json::from_str(res).unwrap())
	}

	pub fn close(&mut self) {
		let _ = self.cmd("q!");
	}
}

impl R2PipeLang {
	pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
		self.write.write(cmd.as_bytes()).unwrap();
		let mut res: Vec<u8> = Vec::new();
		self.read.read_until(0u8, &mut res).unwrap();
		process_result (res)
	}

	pub fn cmdj(&mut self, cmd: &str) -> Result<Json, String> {
		let res = try!(self.cmd(cmd));
		Ok(Json::from_str(&res).unwrap())
	}

	pub fn close(&mut self) {
		// self.read.close();
		// self.write.close();
	}
}
