package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type R2Pipe struct {
	File string
	// private
	stdin        io.WriteCloser
	stdout       io.ReadCloser
	stdoutReader *bufio.Reader
	cmd          *exec.Cmd
}

func NewR2Pipe(file string) *R2Pipe {
	var r2p R2Pipe
	var err error

	r2p.File = file
	r2p.cmd = exec.Command("r2", "-q0", file)

	// setup stdin
	r2p.stdin, err = r2p.cmd.StdinPipe()
	if err != nil {
		panic(err)
	}

	// setup stdout
	r2p.stdout, err = r2p.cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}
	r2p.stdoutReader = bufio.NewReader(r2p.stdout)

	// start process
	r2p.cmd.Start()

	// read initial stuff
	_, err = r2p.stdoutReader.ReadString(0)
	if err != nil {
		panic(err)
	}

	return &r2p
}

func (r2p *R2Pipe) Cmd(cmd string) (string, error) {
	r2p.stdin.Write([]byte(cmd + "\n"))
	res, err := r2p.stdoutReader.ReadString(0)
	if err == nil {
		res = res[:len(res)-1]
	}
	return res, err
}

func (r2p *R2Pipe) Config(key, val string) {
	r2p.Cmd("e " + key + "=" + val)
}

func (r2p *R2Pipe) GetConfig(key string) string {
	res, _ := r2p.Cmd("e " + key)
	return res
}

func (r2p *R2Pipe) Quit() {
	r2p.Cmd("q!")
	r2p.cmd.Wait()
}

// test program //
func run(r2p *R2Pipe, cmd string) string {
	res, err := r2p.Cmd(cmd)
	if err != nil {
		panic(err)
	}
	return res
}

func jsonRun(r2p *R2Pipe, cmd string) []interface{} {
	var dat []interface{}

	res, _ := r2p.Cmd(cmd)

	if err := json.Unmarshal([]byte(res), &dat); err != nil {
		panic(err)
	}
	//	fmt.Println(dat)
	return dat
}

func main() {
	r2 := NewR2Pipe("/bin/ls")

	fmt.Println("Default Arch: ", r2.GetConfig("asm.arch"))

	r2.Config("asm.arch", "arm")
	r2.Config("asm.bits", "16")

	fmt.Println(r2.File)
	fmt.Println(strings.Repeat("-", len(r2.File)))
	out := jsonRun(r2, "pdj 4")
	for i, u := range out {
		fmt.Println(i, u)
	}
	fmt.Println(run(r2, "pd 4"))
	fmt.Println(run(r2, "?e Hello World"))
	fmt.Println(run(r2, "px 64"))

	r2.Quit()
}
