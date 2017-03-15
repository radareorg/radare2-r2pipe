'use strict';

function cleanCmd (cmd) {
  cmd = cmd.trim();

  /* Check for new lines / multiple cmds */
  const pos = cmd.indexOf('\n');
  if (pos !== -1) {
    cmd = cmd.replace('\n', '\\n');
    throw new Error('Invalid character at pos: ' + pos + ' (' + cmd + ')');
  }

  const ascii = /^[ -~]+$/;
  if (!ascii.test(cmd)) {
    /* Check for non printable characters */
    const buff = new Buffer(cmd);
    throw new Error('Invalid character at cmd: ' + JSON.stringify(buff));
  }

  return cmd;
}

module.exports.cleanCmd = cleanCmd;
