// radare - LGPL - Copyright 2015 - nibble

package r2pipe

import "testing"

func TestRun(t *testing.T) {
	r2p, err := Open("malloc://256")
	if err != nil {
		t.Fatal(err)
	}
	defer r2p.Close()

	check := "Hello World"

	_, err = r2p.Run("w " + check)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := r2p.Run("ps")
	if err != nil {
		t.Fatal(err)
	}
	if buf != check {
		t.Errorf("buf=%v; want=%v", buf, check)
	}
}

func TestSetVar(t *testing.T) {
	r2p, err := Open("malloc://256")
	if err != nil {
		t.Fatal(err)
	}
	defer r2p.Close()

	checks := []string{"arm", "x86"}

	for _, check := range checks {
		if err := r2p.SetVar("asm.arch", check); err != nil {
			t.Fatal(err)
		}
		arch, err := r2p.Var("asm.arch")
		if err != nil {
			t.Fatal(err)
		}
		if arch != check {
			t.Errorf("arch=%v; want=%v", arch, check)
		}
	}
}
