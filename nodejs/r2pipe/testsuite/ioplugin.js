'use strict';

const assert = require('assert');
const { spawn } = require('child_process');

if (process.argv[2] === '--backend') {
  require('../').ioplugin((io, message) => io.send({ result: message.cmd }));
} else {
  const child = spawn(process.execPath, [__filename, '--backend'], {
    env: Object.assign({}, process.env, { R2PIPE_IN: '3', R2PIPE_OUT: '4' }),
    stdio: ['ignore', 'ignore', 'inherit', 'pipe', 'pipe']
  });
  const expected = ['first', 'second', 'split 😀 request', 'legacy'];
  let pending = '';
  let ready = false;
  let received = 0;
  const timeout = setTimeout(() => {
    child.kill();
    throw new Error('IO plugin framing test timed out');
  }, 5000);
  child.stdio[4].setEncoding('utf8');
  child.stdio[4].on('data', data => {
    pending += data;
    let end;
    while ((end = pending.indexOf('\0')) !== -1) {
      const message = pending.slice(0, end);
      pending = pending.slice(end + 1);
      if (!ready) {
        assert.strictEqual(message, '');
        ready = true;
        // Multiple requests in one pipe write, including an empty line.
        child.stdio[3].write('{"cmd":"first"}\n\n{"cmd":"second"}\n');
        const split = Buffer.from('{"cmd":"split 😀 request"}\n');
        const offset = split.indexOf(Buffer.from('😀')) + 1;
        child.stdio[3].write(split.slice(0, offset));
        // Split both a JSON frame and a UTF-8 character across writes.
        setTimeout(() => {
          child.stdio[3].write(split.slice(offset));
          child.stdio[3].write('{"cmd":"legacy"}\n\0');
        }, 20);
      } else {
        assert.notStrictEqual(message, '', 'only one startup NUL');
        assert.deepStrictEqual(JSON.parse(message), { result: expected[received++] });
        if (received === expected.length) {
          child.stdio[3].end();
        }
      }
    }
  });
  child.on('error', error => { throw error; });
  child.on('exit', code => {
    clearTimeout(timeout);
    assert.strictEqual(code, 0);
    assert.strictEqual(received, expected.length);
    assert.strictEqual(pending, '');
    console.log('IO plugin framing: OK');
  });
}
