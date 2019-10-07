# r2pipe.clj

`"Know only Clojure and want to work with r2? I got you fam."`

r2pipe.clj is a Clojure library to interact with [radare2](https://github.com/radareorg/radare2). This requires you to have r2 installed on your system. It spawns a new process and communicates with it over pipes.

## Installation

In Leiningen:

[![Clojars Project](https://img.shields.io/clojars/v/org.clojars.chinmay_dd/r2pipe.svg)](https://clojars.org/org.clojars.chinmay_dd/r2pipe)

## Usage

```clojure
;; Start up the REPL and include r2 pipe lib
user=> (require '[r2pipe.core :refer :all])

;; Configure the r2 path. It will default to "/usr/bin/r2".
user=> (configure-path "/usr/bin/r2")

;; Open the file into r2
user=> (r2open "binary")
#'r2pipe.core/pipe

;; Execute a command in r2
user=> (r2cmd "pi 5")
"xor ebp, ebp\npop esi\nmov ecx, esp\nand esp, 0xfffffff0\npush eax\n"
```

### Todo

A lot of things!
