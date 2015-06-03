use std::process::Command;
use std::process::Stdio;
use std::process;
use std::path::Path;
use std::io::prelude::*;

pub struct R2pipe {
    file: String,
    read: process::ChildStdout,
    write: process::ChildStdin,
}

impl R2pipe {
    pub fn new(name: &str) -> R2pipe {
        let path = Path::new(name);
        let child = Command::new("r2")
                             .arg("-q0")
                             .arg(path)
                             .stdin(Stdio::piped())
                             .stdout(Stdio::piped())
                             .spawn()
                             .unwrap_or_else( |e| { panic!("failed to execute child: {}", e) });

        let sin: process::ChildStdin;
        let mut sout: process::ChildStdout;
        
        {
            sin = child.stdin.unwrap();
            sout = child.stdout.unwrap();
            // flush out the initial null byte.
            let mut w = [0;1];
            sout.read(&mut w).unwrap();
        }
        
        R2pipe { file: path.to_str().unwrap().to_string(), read: sout, write: sin }
    }

    pub fn cmd(&mut self, cmd: &str) -> String {
        let cmd_ = cmd.to_string() + "\n";
        if let Err(e) = self.write.write(cmd_.as_bytes()) {
            panic!("{}", e);
        }

        // Read in block size of 2048.
        let mut s = [0; 2048];
        let mut res: String = String::new();
        loop { 
            let count = self.read.read(&mut s).unwrap();
            for c in s.iter() {
                res = res + &*format!("{}", *c as char);
            }
            if count < 2048 {
                break;
            }
        }
        res
    }

    pub fn close(&mut self) {
        self.cmd("q!");
    }
}
