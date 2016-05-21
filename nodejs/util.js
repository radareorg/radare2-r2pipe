'use strict';

function cleanCmd(cmd) {
    let pos;

    cmd = cmd.trim();

    /* Check for new lines / multiple cmds */
    pos = cmd.indexOf('\n')
    if (pos !==-1) {
        cmd = cmd.replace('\n', '\\n')
        throw new Error('Invalid character at pos: ' + pos + ' ('+ cmd +')');
    }

    /* Check for non printable characters */
    if (/[\x00-\x08\x0A-\x1F]/.test(cmd)) {
        var buff = new Buffer(cmd);
        throw new Error('Invalid character at cmd: ' + JSON.stringify(buff));
    }

    return cmd;
}

module.exports.cleanCmd = cleanCmd;

