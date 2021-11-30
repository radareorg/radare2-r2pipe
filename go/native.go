// radare - LGPL - Copyright 2017 - pancake

package r2pipe

//#cgo linux LDFLAGS: -ldl
//#include <stdio.h>
//#include <dlfcn.h>
// #include <stdlib.h>
// void *gor_core_new(void *f) {
// 	void *(*rcn)();
// 	rcn = (void *(*)())f;
// 	return rcn();
// }
//
// void gor_core_free(void *f, void *arg) {
// 	void (*fr)(void *);
// 	fr = (void (*)(void *))f;
// 	fr(arg);
// }
//
// char *gor_core_cmd_str(void *f, void *arg, char *arg2) {
// 	char *(*cmdstr)(void *, char *);
// 	cmdstr = (char *(*)(void *, char *))f;
// 	return cmdstr(arg, arg2);
// }
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

type Ptr = unsafe.Pointer

// *struct{}

var (
	lib            Ptr = nil
	r_core_new     func() Ptr
	r_core_free    func(Ptr)
	r_core_cmd_str func(Ptr, string) string
)

type DL struct {
	handle unsafe.Pointer
	name   string
}

func dlOpen(path string) (*DL, error) {
	var ret DL
	switch runtime.GOOS {
	case "darwin":
		path = path + ".dylib"
	case "windows":
		path = path + ".dll"
	default:
		path = path + ".so" //linux/bsds
	}
	cpath := C.CString(path)
	if cpath == nil {
		return nil, errors.New("Failed to get cpath")
	}
	//r2pioe only uses flag 0
	ret.handle = C.dlopen(cpath, 0)
	ret.name = path
	C.free(unsafe.Pointer(cpath))
	if ret.handle == nil {
		return nil, errors.New(fmt.Sprintf("Failed to open %s", path))
	}
	return &ret, nil
}

func dlSym(dl *DL, name string) (unsafe.Pointer, error) {
	cname := C.CString(name)
	if cname == nil {
		return nil, errors.New("Fail")
	}
	handle := C.dlsym(dl.handle, cname)
	C.free(unsafe.Pointer(cname))
	if handle == nil {
		return nil, errors.New("Fail")
	}
	return handle, nil
}

func NativeLoad() error {
	if lib != nil {
		return nil
	}
	lib, err := dlOpen("libr_core")
	_ = lib
	if err != nil {
		return err
	}
	handle1, _ := dlSym(lib, "r_core_new")
	r_core_new = func() Ptr {
		a := (Ptr)(C.gor_core_new(handle1))
		return a
	}
	handle2, _ := dlSym(lib, "r_core_free")
	r_core_free = func(p Ptr) {
		C.gor_core_free(handle2, unsafe.Pointer(p))
	}
	handle3, _ := dlSym(lib, "r_core_cmd_str")
	r_core_cmd_str = func(p Ptr, s string) string {
		a := C.CString(s)
		b := C.gor_core_cmd_str(handle3, unsafe.Pointer(p), a)
		C.free(unsafe.Pointer(a))
		return C.GoString(b)
	}
	return nil
}

func (r2p *Pipe) NativeCmd(cmd string) (string, error) {
	res := r_core_cmd_str(r2p.Core, cmd)
	return res, nil
}

func (r2p *Pipe) NativeClose() error {
	r_core_free(r2p.Core)
	r2p.Core = nil
	return nil
}

func NewNativePipe(file string) (*Pipe, error) {
	if err := NativeLoad(); err != nil {
		return nil, err
	}
	r2 := r_core_new()
	r2p := &Pipe{
		File: file,
		Core: r2,
		cmd: func(r2p *Pipe, cmd string) (string, error) {
			return r2p.NativeCmd(cmd)
		},
		close: func(r2p *Pipe) error {
			return r2p.NativeClose()
		},
	}
	if file != "" {
		r2p.NativeCmd("o " + file)
	}
	return r2p, nil
}
