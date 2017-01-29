const r2 = require("./radare2")

// ffi
const coreNew = r2.cwrap('r2_asmjs_new', 'number', []);
const coreFree = r2.cwrap('r2_asmjs_free', 'void', ['number']);
const coreCmd = r2.cwrap('r2_asmjs_cmd', 'string', ['numnber', 'string']);
const openurl = r2.cwrap('r2_asmjs_openurl', 'void', ['number', 'string']);

function r2pipeAsmJS() {
	var r2i = coreNew();
	return {
		cmd: function(c) {
			return coreCmd(r2i, c);
		},
		free: function() {
			coreFree(r2i);
			r2i = 0;
		}
	};
}

//r2.openurl("http://radare.org/r/index.html");
r2.cmd('o malloc://1024');
r2.cmd('w hello world');
console.log(r2.cmd('x 32'));
console.log(r2.cmd('e asm.arch=?'));

