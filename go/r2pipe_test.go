// radare - LGPL - Copyright 2015 - nibble

package r2pipe

import "testing"

func TestCmd(t *testing.T) {
	r2p, err := NewPipe("malloc://256")
	if err != nil {
		t.Fatal(err)
	}
	defer r2p.Close()

	check := "Hello World"

	_, err = r2p.Cmd("w " + check)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := r2p.Cmd("ps")
	if err != nil {
		t.Fatal(err)
	}
	if buf != check {
		t.Errorf("buf=%v; want=%v", buf, check)
	}
}
