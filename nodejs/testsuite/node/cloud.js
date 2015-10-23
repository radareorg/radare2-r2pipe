'use strict';

var r2p = require('../..');
var ts = require('..');

function testCloud(fin) {
	try {
		r2p.connect('http://cloud.radare.org/cmd/', (r2) => {
			r2.cmd('?e hello world', function(res) {
				fin(res);
				r2.quit();
			});
		});
	} catch (e) {
		fin(e.toString());
	}
}

function testCloudOK(fin) {
	try {
		r2p.connect('http://cloud.rada.re/cmd/', function(r2) {
			r2.cmd('?e hello world', function(res) {
				fin(res);
				r2.quit();
			});
		});
	} catch (e) {
		fin(e.toString());
	}
}

ts.addTest('testCloud', testCloud, 'hello world\n', {broken:true});
ts.addTest('testCloudOK', testCloudOK, 'hello world\n');

//ts.inSerial();
ts.inParalel();
