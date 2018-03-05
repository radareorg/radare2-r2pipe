/*  Small tests for r2pipe */

var r2pipe = require('../');

function doSomeStuff (err, r2) {
  if (err) throw err;
  r2.cmdj('aij entry0+2', function (err, o) {
    if (err) throw err;
    console.log(o);
  });

  r2.cmd('af @ entry0', function (err, o) {
    if (err) throw err;
    r2.cmd('pdf @ entry0', function (err, o) {
      if (err) throw err;
      console.log(o);
      r2.quit();
    });
  });
}

r2pipe.pipe('/bin/ls', doSomeStuff);
// r2pipe.launch('/bin/ls', doSomeStuff);
// r2pipe.connect('http://cloud.rada.re/cmd/', doSomeStuff);
