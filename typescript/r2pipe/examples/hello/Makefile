all:
	rm -f r2pipe
	ln -fs ../.. r2pipe
	r2frida-compile -So index.r2.js index.ts
	r2 -qi index.r2.js -
	tsc index.ts
	r2 -qi index.js -
