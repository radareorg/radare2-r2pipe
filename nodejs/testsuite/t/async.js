'use strict';

var r2pipe = require('../..');
var ts = require('..');

function testAsync5(fin) {
	let result = '';
	try {
		var count = 5;
		r2pipe.open('../b/ls', function (r2) {
			var intrv = setInterval(function() {
				if (count == 0) {
					r2.quit();
				} else {
					r2.cmd('?e a', (x)=> {
						result += x;
						count--;
						if (count == 0) {
							clearInterval (intrv);
							r2.quit();
							fin(result);
						}
					});
				}
			}, 10);
		});
	} catch (e) {
		console.error(e);
	}
	return result;
}

function testAsyncFor5(fin) {
	let result = '';
	try {
		var count = 5;
		r2pipe.open('../b/ls', function (r2) {
			for (let i = 0; i < 5; i++) {
				if (count == 0) {
					r2.quit();
				} else {
					r2.cmd('?e a', (x)=> {
						result += x;
						count--;
						if (count == 0) {
							r2.quit();
							fin(result);
						}
					});
				}
			}
		});
	} catch (e) {
		console.error('error', e);
	}
	return result;
}

ts.addTest('testAsync5', testAsync5, 'a\na\na\na\na\n');
ts.addTest('testAsyncFor5', testAsyncFor5, 'a\na\na\na\na\n');

ts.inSerial();
ts.inParalel();
