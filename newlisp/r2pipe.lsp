#!/usr/bin/env newlisp

(context 'r2pipe)

(define (r2pipe:cmd cmd)
	(set 'i (int (env "R2PIPE_IN")))
	(set 'o (int (env "R2PIPE_OUT")))
	(write o (append cmd "\n"))
	(set 'res (read i buf 9999))
	(chop buf)
)
