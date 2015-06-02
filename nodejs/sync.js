var fs = require('fs');
var proc = require('child_process');

var BUFLEN = 1024;


function runSysCmdSync(cmd) {
    
}

function runCmdSync(ls, cmd) {
    var result = '';
    var buf = new Buffer(BUFLEN);
    var bread = 0;

    fs.writeSync(ls.syncStdin, cmd + '\n');
    while ((bread = fs.readSync(ls.syncStdout, buf, 0, BUFLEN, null)) > 0) {
        /* check for cmd end */
        if (buf[bread-1] !== 0x00) {
            result += buf.slice(0, bread).toString();
        } else {
            result += buf.slice(0, bread-1).toString();
            break;
        }
    }

    return result;
}


function parseJSON(func, cmd) {
    var res = func(cmd);
    if (res === null)
        return res;

    try {
        return JSON.parse(res);
    } catch ( e ) {
        return null;
    }
}


function r2bind(ls, r2cmd) {
    var buf = new Buffer(1024);

    /* Wait for radare2 to start */
    if (r2cmd === 'pipe')
        fs.readSync(ls.syncStdout, buf, 0, 1024, null);

    var r2 = {

        /* Run R2 cmd */
        cmd: function(cmd) {
            return runCmdSync(ls, cmd);
        },

        /* Run cmd and return JSON output */
        cmdj: function(cmd) {
            return parseJSON(r2.cmd, cmd);
        },

        /* Run system cmd */
        syscmd: function(command, cb2) {
            return proc.execSync(command).toString();
        },

        syscmdj: function(cmd) {
            return parseJSON(r2.syscmd, cmd);
        },

        /* Quit CMD */
        quit: function() {
            if (ls.stdin && ls.stdin.end)
                ls.stdin.end();
            ls.kill ('SIGINT');
        }
    }

    return r2;
}

module.exports.r2bind = r2bind;
