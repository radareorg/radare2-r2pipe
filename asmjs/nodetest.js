const r2 = require("./radare2")
r2.cmd = r2.cwrap('r2_asmjs_cmd', 'string', ['string']);
r2.openurl = r2.cwrap('r2_asmjs_openurl', 'void', ['string']);

//r2.openurl("http://radare.org/r/index.html");
r2.cmd('o malloc://1024');
r2.cmd('w hello world');
console.log(r2.cmd('x 32'));
console.log(r2.cmd('e asm.arch=?'));

