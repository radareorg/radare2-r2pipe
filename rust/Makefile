all:
	cargo build

clean:
	cargo clean

doc:
	cargo doc --no-deps

run:
	r2 -qc '#!pipe target/debug/r2pipe' /bin/ls
	target/debug/r2pipe
