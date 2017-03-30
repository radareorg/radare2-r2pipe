'use strict';

var r2pipe = require('../..');
var ts = require('..');

function testSync (fin) {
  try {
    var r2 = r2pipe.open('../b/ls'); // async open with no callback
    // var r2 = r2pipe.openSync('../b/ls'); // async open with no callback
    if (r2) {
      fin(r2.cmd('?e hello world'));
      r2.quit();
    }
  } catch (e) {
    fin(e.toString());
  }
}

ts.addTest('testSync', testSync, 'hello world\n', {
  broken: true
});

ts.inSerial();
// ts.inParalel();
