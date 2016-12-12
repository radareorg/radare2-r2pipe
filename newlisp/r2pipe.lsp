#!/usr/bin/env newlisp

(context 'r2pipe)

(define (r2pipe:cmd x)
	(set 'i (int (env "R2PIPE_IN")))
	(set 'o (int (env "R2PIPE_OUT")))
	(write o (append x "\n"))
	(set 'res (read i buf 9999))
	(chop buf)
)

(define (r2pipe:cmdj x)
	(set 'i (r2pipe:cmd x))
	(json-parse i)
)
