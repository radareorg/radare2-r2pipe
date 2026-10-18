TSC=./node_modules/.bin/tsc

all:
	$(TSC)
	$(TSC) -p tsconfig.tests.json
	node --test tests/addresses.test.cjs
	node --test test-http-encoding.cjs
	node test-spawn.js
	r2 -q -i test-local.js /bin/ls

vs vsc:
	open -a "Visual Studio Code" .

test:
	make -C examples/hello

lint:
	npm run lint -- --fix
pub:
	npm pub
