// radare - LGPL - Copyright 2015 - nibble

/*
Package r2pipe allows to call r2 commands from Go. A simple hello world would
look like the following snippet:

	package main

	import (
		"fmt"

		r2pipe "github.com/radare/radare2-bindings/r2pipe/go"
	)

	func main() {
		r2p, err := r2pipe.NewPipe("malloc://256")
		if err != nil {
			panic(err)
		}
		defer r2p.Close()

		_, err = r2p.Run("w Hello World")
		if err != nil {
			panic(err)
		}
		buf, err := r2p.Run("ps")
		if err != nil {
			panic(err)
		}
		fmt.Println(buf)
	}
*/
package r2pipe

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// A Pipe represents a communication interface with r2 that will be used to
// execute commands and obtain their results.
type Pipe struct {
	File   string
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

// NewPipe returns a new r2 pipe and initializes an r2 core that will try to
// load the provided file or URI. This pipe acts as a communication interface
// between Go and r2.
func NewPipe(file string) (*Pipe, error) {
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

// Write implements the standard Write interface: it writes data to the r2
// pipe, blocking until r2 have consumed all the data.
func (r2p *Pipe) Write(p []byte) (n int, err error) {
	return r2p.stdin.Write(p)
}

// Read implements the standard Read interface: it reads data from the r2
// pipe, blocking until the previously issued commands have finished.
func (r2p *Pipe) Read(p []byte) (n int, err error) {
	return r2p.stdout.Read(p)
}

// Run is a helper that allows to run r2 commands and receive their output.
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

// SetVar sets the value of an r2 variable.
func (r2p *Pipe) SetVar(name, value string) error {
	_, err := r2p.Run("e " + name + "=" + value)
	return err
}

// Var returns the value of an r2 variable.
func (r2p *Pipe) Var(name string) (value string, err error) {
	return r2p.Run("e " + name)
}

// Close shuts down r2, closing the created pipe.
func (r2p *Pipe) Close() error {
	if _, err := r2p.Run("q!"); err != nil {
		return err
	}
	return r2p.cmd.Wait()
}
