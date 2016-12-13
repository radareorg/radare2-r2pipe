#!/usr/bin/env newlisp
;-- main

(load "r2pipe.lsp")

(println "pd 3:\n" (r2pipe:cmd "pd 3"))

(define (aoj addr) (first (r2pipe:cmdj (string "aoj @ " addr))))

(set 'opinfo (aoj "entry0"))
(println (lookup "opcode" opinfo))
(println (lookup "esil" opinfo))

; (println opinfo)
(exit 0)
