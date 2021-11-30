// radare - LGPL - Copyright 2021 - pancake

package r2pipe

// #cgo CFLAGS: -I/usr/local/include/libr
// #cgo CFLAGS: -I/usr/local/include/libr/sdb
// #cgo LDFLAGS: -L/usr/local/lib -lr_core
// #include <stdio.h>
// #include <stdlib.h>
// extern void r_core_free(void *);
// extern void *r_core_new(void);
// extern char *r_core_cmd_str(void*, const char *);
//
import "C"

import (
	"unsafe"
)

func (r2p *Pipe) ApiCmd(cmd string) (string, error) {
	res := C.r_core_cmd_str(r2p.Core, C.CString(cmd))
	return C.GoString(res), nil
}

func (r2p *Pipe) ApiClose() error {
	C.r_core_free(unsafe.Pointer(r2p.Core))
	r2p.Core = nil
	return nil
}

func NewApiPipe(file string) (*Pipe, error) {
	r2 := C.r_core_new()
	r2p := &Pipe{
		File: file,
		Core: r2,
		cmd: func(r2p *Pipe, cmd string) (string, error) {
			return r2p.ApiCmd(cmd)
		},
		close: func(r2p *Pipe) error {
			return r2p.ApiClose()
		},
	}
	if file != "" {
		r2p.ApiCmd("o " + file)
	}
	return r2p, nil
}
