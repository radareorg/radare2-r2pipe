TSC=./node_modules/.bin/tsc

all:
	$(TSC)
	$(TSC) --ignoreConfig test-spawn.ts
	node test-spawn.js
	$(TSC) --ignoreConfig test-local.ts
	r2 -q -i test-local.js /bin/ls

vs vsc:
	open -a "Visual Studio Code" .

test:
	make -C examples/hello

lint:
	./node_modules/.bin/eslint --fix r2pipe/*.ts
pub:
	npm pub
