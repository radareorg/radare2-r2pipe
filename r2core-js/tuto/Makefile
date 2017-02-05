all:
	node make.js > tuto01.js
	node_modules/.bin/browserify loadbro.js > loadbro-browser.js

pub:
	rsync -e 'ssh -p 2299' -avz * cloud.rada.re:prg/r2cloud/www/asmjs/tuto
