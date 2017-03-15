'use strict';

var r2pipe = require('../..');
var ts = require('..');

ts.addTest('testJSON', function (fin) {
  try {
    var r2 = r2pipe.openSync('../b/ls');
    if (r2) {
      fin(r2.cmdj('ij').core.file);
      r2.quit();
    }
  } catch (e) {
    fin(e.toString());
  }
}, '../b/ls');

ts.inParalel();
