TSC=./node_modules/.bin/tsc

all:
	$(TSC)
	$(TSC) -p tsconfig.tests.json
	node test-spawn.js
	r2 -q -i test-local.js /bin/ls

vs vsc:
	open -a "Visual Studio Code" .

test:
	make -C examples/hello

lint:
	./node_modules/.bin/eslint --fix r2pipe/*.ts
pub:
	npm pub
