all:
	tsc
	tsc -d r2pipe/index.ts
#	tsc
	tsc test-spawn.ts
	node test-spawn.js
	tsc test-local.ts
	r2 -q -i test-local.js /bin/ls

vs vsc:
	open -a "Visual Studio Code" .

test:
	make -C examples/hello

lint:
	./node_modules/.bin/eslint --fix r2pipe/*.ts
