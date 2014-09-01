NodeJS bindings for r2.js
=========================

Hackaround to enable r2cmd api for nodejs. This way it is possible
to reuse scripts written for duktape or the webui from nodejs

	var r2 = require ("r2.js");
	var r2node = require ("r2node.js");
	r2node.launch ("/bin/ls", function(r2cmd) {
		console.log (r2cmd ("pd 3"));
		console.log (r2.cmd ("pd 3"));
	});

	r2node.connect ("http://cloud.rada.re/", function (r2cmd) {
		
	});
