'use strict';

var r2pipe = require('../..');
var ts = require('..');

function testSync(fin) {
	try {
		var count = 5;
		var r2p = r2pipe.openSync('../b/ls');
		if (r2p) {
			fin(r2p.cmd('?e hello world'));
		}
	} catch (e) {
		fin(e.toString());
	}
}

ts.addTest('testSync', testSync, 'hello world\n', {broken:true});

ts.inSerial();
//ts.inParalel();
