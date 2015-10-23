NODE=node

all: node r2

node:
	@cd node ; for a in * ; do $(NODE) $$a ; done

r2:
	@cd r2 ; for a in * ; do r2 -qi $$a ../b/ls ; done

clean:

.PHONY: all node r2
