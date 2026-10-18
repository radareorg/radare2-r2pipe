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

// Normalize a wire address without rounding any of its 64 bits.
function parseAddress (address) {
  if ((typeof address === 'number' && !Number.isSafeInteger(address)) ||
      (typeof address === 'string' && !/^0[xX][0-9a-fA-F]+$/.test(address)) ||
      !['number', 'string', 'bigint'].includes(typeof address)) {
    throw new TypeError('Address must be a safe integer, bigint or hexadecimal string');
  }
  const value = BigInt(address);
  if (value < BigInt(0) || value > BigInt('0xffffffffffffffff')) {
    throw new RangeError('Address is outside the unsigned 64-bit range');
  }
  return value;
}

module.exports.parseAddress = parseAddress;
