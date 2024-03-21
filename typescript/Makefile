all:
	tsc -d r2pipe/index.ts
#	tsc
	tsc test.ts
	node test.js
	tsc lo.ts
	r2 -q -i lo.js /bin/ls
#	r2 -q -c '#!pipe node --inspect lo.js' /bin/ls

vs vsc:
	open -a "Visual Studio Code" .

test:
	make -C examples/hello
