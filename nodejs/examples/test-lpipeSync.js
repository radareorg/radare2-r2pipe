/*  Small tests for r2pipe */
// return true;

var r2pipe = require ("./../");


var r2 = r2pipe.lpipeSync ();
var res = r2.cmd('pd 4');
var resj = r2.cmdj('pdj 4');

console.log('Normal output');
console.log(res);

console.log('JSON output');
console.log(resj);
r2.quit();
