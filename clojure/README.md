# r2pipe.clj

`"Know Clojure and want to work with r2? I got you fam."`

r2pipe is a Clojure library to interact with [radare2](https://github.com/radareorg/radare2). This requires you to have r2 installed on your system. It spawns a new process and communicates with it over pipes.

## Installation

In Leiningen:

TBD

## Usage

The basic usage for this is to use a default r2 instance.

```clojure
;; Basic usage:
(use 'r2pipe.core)

(r2open "spawn:///./program.bin")    ; for spawning r2, opening this file
(r2open "tcp://127.0.0.1:1337")      ; for using a TCP connection
(r2open "http://127.0.0.1:9090/cmd") ; for using HTTP

(cmd "pd" "8")   ; returns a string representation
(cmdj "pdj" "8") ; returns a Clojure map

(close) ; closes/cleans the pipe

;; To allow inquiries (i.e: "pd?")
(require '[r2pipe.proto :as proto])
(proto/set-deny-inquiry false)

;; To change the default location of the radare2 binary
(configure-path "/usr/bin/r2")
```

Alternatively, if you would like to use a specific protocol, or to have multiple
instances, the library can be used like this:


```clojure
(require '[r2pipe.proto :as r2]) ; necessary for 'cmd' and 'cmdj'

;;
;; Spawning example
;;

(require '[r2pipe.spawn :as spawn])
(def i (spawn/r2open "/bin/ls" "/usr/bin/r2"))

(r2/cmd i "pd" "8")
(r2/cmdj i "pdj" "8")

(.close i)

;;
;; TCP example
;;

;; Note: radare2 drops the connection after a command, so for
;; each write there will be an opened connection, and after 
;; a read, the connection is closed

(require '[r2pipe.tcp :as tcp]) ; for TCP
(def i (tcp/r2open "127.0.0.1" 1337))

(r2/cmd i "pd" "8")
(r2/cmdj i "pdj" "8")

(.close i)

;;
;; HTTP example
;;

(require '[r2pipe.http :as http]) ; for HTTP
(def i (http/r2open "http://127.0.0.1:9090/cmd"))

(r2/cmd i "pd" "8")
(r2/cmdj i "pdj" "8")

(.close i)
```

For the pipe instances, you can also manually send
the commands, by using the `R2Pipe` protocol's methods:

N.B: queues for messages are not supported yet except
for spawning pipes (more or less by accident? they're not even queues tbh),
i.e: you can only read one message after a write, and nothing if no
write occured

```clojure
(.r2-write i "pdj 8")
(.r2-read i)
(.close i)
```

### TODO

- Queues
- Tests
- ClojureScript support
- Async (only for TCP and HTTP most probably)
- RAP
