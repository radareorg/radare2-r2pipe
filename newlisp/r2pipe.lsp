#!/usr/bin/env newlisp

;;; r2 -i

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

;;; http

(context 'r2pipe-http)

((define (r2pipe-http:cmd u x)
	(get-url (string u "/" x)))
)

((define (r2pipe-http:cmdj u x)
	(json-parse (get-url (string u "/" x))))
)
