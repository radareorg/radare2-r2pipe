/* Common-Javascript API for R2  --pancake 2014 */

/* This is a NodeJS program that uses the generic r2 api
   which is also compatible with the WebUI and Duktape.
   Enabling you to write Javascript extensions for r2
   that run in the shell, the web or inside r2 */

/* require the nodejs api */
var r2jsapi = './r2.js';
var r2node = require('../');

function doSomeStuff (r) {
  var r2 = require(r2jsapi)(r);
  r2.analOp('entry0', function (op) {
    console.log(op.size, op.opcode, op.esil);
  });
  r2.cmd('af @ entry0', function (o) {
    r2.cmd('pdf @ entry0', function (o) {
      console.log(o);
      r.quit();
    });
  });
  r2.cmdj('aij entry0+2', function (o) {
    console.log(o);
  });
}

r2node.pipe('/bin/ls', doSomeStuff);
r2node.launch('/bin/ls', doSomeStuff);
/*
r2node.connect ("http://cloud.rada.re/cmd/", doSomeStuff);
r2node.launch ("/bin/ls", function (r) {
  var r2 = require (r2jsapi)(r);
  r2.cmd (["?v $s", "p8 10", "pi 3"], function(res) {
    console.log (res);
    r.quit ();
  });
});
*/
