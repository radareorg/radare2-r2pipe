;; native r2pipe api example
(load "r2pipe.lsp")
(context 'r2pipe-spawn)
(let (r2 (r2pipe-spawn:new "/bin/ls"))
	(println (cmd r2 "?V"))
	(println (cmdj r2 "ij"))
	(quit r2)
)
(exit)
