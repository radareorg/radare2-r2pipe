all:
	@echo Run `make sync` to clone code from Go and Rust repos

sync:
	rm -rf r2pipe.rs r2pipe.go
	git clone https://github.com/radare/r2pipe.rs
	git clone https://github.com/radare/r2pipe.go
	rm -rf rust/*
	rm -rf go/*
	cp -rf r2pipe.rs/* rust/
	cp -rf r2pipe.go/* go/
	rm -rf r2pipe.rs r2pipe.go
	git add rust go
	git commit -m "update external r2pipe bindings from git"
