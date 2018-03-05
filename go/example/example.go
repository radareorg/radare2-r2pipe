// radare - LGPL - Copyright 2017 - pancake

package main

import ".."

func main() {
	r2p, err := r2pipe.NewPipe("/bin/ls")
	if err != nil {
		print("ERROR: ", err)
		return
	}
	defer r2p.Close()

	disasm, err := r2p.Cmd("pd 20")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "\n")
	}
}
