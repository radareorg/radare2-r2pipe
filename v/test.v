module main

import radare.r2

fn main() {
  c := r2.new()
  print(c.cmd('?E Hello'))
  c.free()
}
