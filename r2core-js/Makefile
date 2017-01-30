FILES= Makefile README.md package.json index.js r2core.js test.js webtest.html

all: r2core.js

r2core.js: radare2.closure.ugly.js
	cp -f radare2.closure.ugly.js r2core.js

radare2.closure.ugly.js: radare2.closure.js
	node --max-old-space-size=4096 node_modules/.bin/uglifyjs \
		< radare2.closure.js > radare2.closure.ugly.js || rm -f radare2.closure.ugly.js

radare2.closure.js:
	# we need at least 2GB of heap
	node_modules/.bin/ccjs radare2.js --xmx=4096m > radare2.closure.js

clean:
	rm -f r2core.js
	rm -f radare2.closure.js
	rm -f radare2.closure.ugly.js

pub:
	mkdir r2core
	cp $(FILES) r2core
	cd r2core ; npm publish
	rm -rf r2core

dist:
	mkdir r2core
	cp $(FILES) r2core
	tar czvf r2core.tar.gz r2core
	rm -rf r2core
