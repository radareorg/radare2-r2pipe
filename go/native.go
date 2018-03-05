// radare - LGPL - Copyright 2017 - pancake

package r2pipe

import "github.com/rainycape/dl"
import "errors"

type Ptr = *struct{}

var lib Ptr = nil
var r_core_new func() Ptr
var r_core_free func(Ptr)
var r_mem_free func(interface{})
var r_core_cmd_str func(Ptr, string) string

func NativeLoad() error {
	if lib != nil {
		return nil
	}
	lib, err := dl.Open("libr_core", 0)
	if err != nil {
		return err
	}
	if lib.Sym("r_core_new", &r_core_new) != nil {
		return errors.New("Missing r_core_new")
	}
	if lib.Sym("r_core_cmd_str", &r_core_cmd_str) != nil {
		return errors.New("Missing r_core_cmd_str")
	}
	if lib.Sym("r_core_free", &r_core_free) != nil {
		return errors.New("Missing r_core_free")
	}
	if lib.Sym("r_mem_free", &r_mem_free) != nil {
		return errors.New("Missing r_mem_free")
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
