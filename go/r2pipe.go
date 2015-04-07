// radare - LGPL - Copyright 2015 - nibble

package r2pipe

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type Pipe struct {
	File   string
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func Open(file string) (*Pipe, error) {
	cmd := exec.Command("r2", "-q0", file)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Read initial data
	if _, err := bufio.NewReader(stdout).ReadString('\x00'); err != nil {
		return nil, err
	}

	r2p := &Pipe{
		File:   file,
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
	}
	return r2p, nil
}

func (r2p *Pipe) Write(p []byte) (n int, err error) {
	return r2p.stdin.Write(p)
}

func (r2p *Pipe) Read(p []byte) (n int, err error) {
	return r2p.stdout.Read(p)
}

func (r2p *Pipe) Run(cmd string) (output string, err error) {
	if _, err := fmt.Fprintln(r2p, cmd); err != nil {
		return "", err
	}
	buf, err := bufio.NewReader(r2p).ReadString('\x00')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(buf, "\n\x00"), nil
}

func (r2p *Pipe) SetVar(name, value string) error {
	_, err := r2p.Run("e " + name + "=" + value)
	return err
}

func (r2p *Pipe) Var(name string) (value string, err error) {
	return r2p.Run("e " + name)
}

func (r2p *Pipe) Close() error {
	if _, err := r2p.Run("q!"); err != nil {
		return err
	}
	return r2p.cmd.Wait()
}
