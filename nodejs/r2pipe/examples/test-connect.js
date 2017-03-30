/* Common-Javascript API for R2  --pancake 2014 */

/* This is a NodeJS program that uses the generic r2 api
   which is also compatible with the WebUI and Duktape.
   Enabling you to write Javascript extensions for r2
   that run in the shell, the web or inside r2 */

/* require the nodejs api */
var r2pipe = require('../');

function doSomeStuff (err, r2) {
  if (err) {
    return console.error(err.toString());
  }
  r2.cmd('pd 4', function (err, res) {
    if (err) throw err;
    console.log(res);
    r2.quit();
  });
}

r2pipe.connect('http://cloud.rada.re/cmd/', doSomeStuff);
