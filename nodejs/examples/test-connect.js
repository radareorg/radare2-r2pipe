/* Common-Javascript API for R2  --pancake 2014 */

/* This is a NodeJS program that uses the generic r2 api
   which is also compatible with the WebUI and Duktape.
   Enabling you to write Javascript extensions for r2
   that run in the shell, the web or inside r2 */

/* require the nodejs api */
var r2pipe = require ("../");

function doSomeStuff(r2) {
  r2.cmd('pd 4', function(res) {
    console.log(res);
  });
}

r2pipe.connect ("http://cloud.rada.re/cmd/", doSomeStuff);

