const r2asmjs = require('./');

const c = new r2asmjs();
console.log(c.cmd("e asm.arch=?"));
c.cmd("e asm.arch=x86");
c.cmd("o malloc://1024");
c.cmd("w hello world");
console.log(c.cmd("pd 10"));
console.log(c.cmd("p8 10"));

const c2 = new r2asmjs();
c2.cmd("e asm.arch=x86;e asm.bits=32");
c2.cmd("o malloc://1024");
console.log(c2.cmd("p8 10"));
console.log(c.cmd("p8 10"));
