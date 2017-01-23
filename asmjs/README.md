r2pipe.asmjs
============

Build radare2.tiny.js with radare2-release

	r2pm -r r2rls docker_asmjs

Notice that compilation line at the end of the build:

	$ make EMSCRIPTEN=1 COMPILER=emscripten  ANDROID=1
	emcc -pie -s EXPORTED_FUNCTIONS='["_r2_asmjs_cmd","_r2_asmjs_openurl"]'  -MD
	...

Then uglify it

	node --max-old-space-size=4096 $(npm bin)/uglifyjs < radare2.js > radare2.tiny.js

or get it from:

	http://cloud.rada.re/asmjs/radare2.tiny.js

You can now use this file from nodejs or the browser

	open webtest.html

	node nodetest.js
