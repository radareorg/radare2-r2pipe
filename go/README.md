r2pipe.go
=========

Go module to interact with radare2


## How to use?

### Code
```go
package test

import (
	"github.com/radare/radare2-r2pipe/go"
)

func main() {
  r2p, err := r2pipe.NewPipe("malloc://256")
}
```

### Compiling
```sh
$ go get
$ go build test.go
```
