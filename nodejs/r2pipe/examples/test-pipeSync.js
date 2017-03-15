/*  Small tests for r2pipe */
// return true;

var r2pipe = require('./../');

var r2 = r2pipe.pipeSync('/bin/ls');
var res = r2.cmd('pd 4');
var resj = r2.cmdj('pdj 4');

var sys = r2.syscmd('rabin2 -zz /bin/ls');
var sysj = r2.syscmdj('rabin2 -j -zz /bin/ls');

console.log('Normal output');
console.log(res);

console.log('JSON output');
console.log(resj);

console.log('\nSyscmd normal output');
console.log(sys);

console.log('Syscmd JSON output');
console.log(sysj);

r2.quit();
