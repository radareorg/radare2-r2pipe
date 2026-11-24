module main

import os
import r2pipe

fn main() {
	target := if os.args.len > 1 { os.args[1] } else { '-' }
	mut pipe := r2pipe.open(target) or { panic(err) }
	defer { pipe.close() }
	print(pipe.cmd('?e Hello from V') or { panic(err) })
	println(pipe.cmdj('ij') or { panic(err) })
}
