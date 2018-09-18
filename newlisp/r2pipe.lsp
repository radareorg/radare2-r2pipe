#!/usr/bin/env newlisp

;;; r2 -i

(context 'r2pipe)

(define (cmd x)
	(set 'i (int (env "R2PIPE_IN")))
	(set 'o (int (env "R2PIPE_OUT")))
	(if (not i) (throw-error "You must run this from r2"))
	(write o (append x "\n"))
	(set 'res (read i buf 9999))
	(chop buf)
)

(define (cmdj x)
	(set 'i (r2pipe:cmd x))
	(json-parse i)
)

;;; http

(context 'r2pipe-http)

(define (cmd u x)
	(get-url (string u "/" x))
)

(define (cmdj u x)
	(json-parse (cmd u x))
)

;;; spawn

(context 'r2pipe-spawn)

(define (r2pipe-spawn:new filePath r2path)
	(map set '(myin bcout) (pipe))
	(map set '(bcin myout) (pipe))
	(if (not r2path) (set 'r2path (first (exec "which radare2"))))
	(set 'pid (process (string r2path " -q0 " filePath) bcin bcout))
	;; XXX is this a bug in newLisp? process never returns -1
	; (if (= -1 pid) (throw-error "Cannot spawn r2"))
	(read myin buf 1)
	(list myin myout pid)
)

(define (cmd core x)
	(print (string "pre " x "\x00"))
	(write (core 1) (string x "\n\x00"))
	;; TODO: read until \x00 instead of the whole 999 buffer
	(read (core 0) buf 9999)
	(chop buf)
)

(define (cmdj core x)
	(json-parse (cmd core x))
)

(define (quit core)
	(close (core 0))
	(close (core 1))
	(destroy (core 2))
)

;;; native

(context 'r2pipe-lib)

(set 'r_core_new 0)
(set 'r_core_free 0)
(set 'r_core_cmd_str 0)
(set 'free 0)

(define (r2pipe-lib:new x)
	(set 'files (list
		(string x "/libr_core.dylib")
		(string x "/libr_core.so")
		"/usr/local/lib/libr_core.dylib"
		"/usr/lib/libr_core.so"
		"libr_core.dll"
	))
	(set 'librcore (files (or
		(find true (map file? files))
		(throw-error "cannot find libr_core"))))
	(set 'r_core_new (import librcore "r_core_new"))
	(set 'r_core_cmd_str (import librcore "r_core_cmd_str"))
	(set 'r_core_free (import librcore "r_core_free"))
	(set 'free (import librcore "free"))
	(set 'core (r_core_new))
	core
)

(define (cmd core x)
	(set 'r (r_core_cmd_str core (string x)))
	(if (not r) (throw-error "r_core_cmd_str return null"))
	(set 'res (get-string r))
	(free r)
	res
)

(define (cmdj core x)
	(json-parse (cmd core x))
)

(define (quit core)
	(r_core_free core)
)

(context MAIN)
