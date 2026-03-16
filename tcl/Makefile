TCLSH ?= tclsh
R2 ?= r2

build: build-load

build-load:
	printf '%s\n' 'source r2pipe.tcl' | $(TCLSH)

test: test-spawn test-pipe

test-spawn:
	$(TCLSH) test.tcl spawn

test-pipe:
	$(R2) -qi test.tcl /bin/ls
	$(R2) -qc '#!pipe $(TCLSH) test.tcl pipe' /bin/ls

clean:

.PHONY: build build-load test test-spawn test-pipe clean
