/* pancake @ nopcode.org - 2017 */
const r2core = require("./r2core")

// ffi
const coreNew = r2core.cwrap('r2_asmjs_new', 'number', []);
const coreFree = r2core.cwrap('r2_asmjs_free', 'void', ['number']);
const coreCmd = r2core.cwrap('r2_asmjs_cmd', 'string', ['number', 'string']);
const openurl = r2core.cwrap('r2_asmjs_openurl', 'void', ['number', 'string']);

module.exports = function () {
	var r2i = coreNew();
	return {
		open: function(url) {
			openurl(r2i, url);
		},
		cmd: function(c) {
			return coreCmd(r2i, c);
		},
		cmdj: function(c) {
			return JSON.parse(cmd(c));
		},
		free: function() {
			coreFree(r2i);
			r2i = 0;
		}
	};
}
