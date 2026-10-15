const assert = require('node:assert/strict');
const { test } = require('node:test');
const { EventEmitter } = require('node:events');
const { Writable, PassThrough } = require('node:stream');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { R2PipeQueue } = require('../dist/queue.js');
const { R2PipeSpawn } = require('../dist/spawn.js');
const { R2PipeLocal } = require('../dist/local.js');

function queueFixture(t, startup = false) {
  const writes = [];
  const input = new Writable({
    write(data, _encoding, done) {
      writes.push(data.toString());
      done();
    }
  });
  const output = new PassThrough();
  const queue = new R2PipeQueue(input, output, startup);
  t.after(() => queue.dispose());
  return { queue, input, output, writes };
}

function command(queue, text = 'command') {
  return new Promise((resolve, reject) => {
    queue.cmd(text, (error, result) => error ? reject(error) : resolve(result));
  });
}

test('queue frames startup, empty results and split UTF-8 independently of chunks', async (t) => {
  const { queue, output, writes } = queueFixture(t, true);
  const empty = command(queue, 's 1');
  const unicode = command(queue, '?e €');
  output.write(Buffer.from([0, 0, 0xe2]));
  output.write(Buffer.from([0x82]));
  output.write(Buffer.from([0xac]));
  output.write(Buffer.from([0]));
  assert.equal(await empty, '');
  assert.equal(await unicode, '€');
  assert.deepEqual(writes, ['s 1\n', '?e €\n']);
});

test('queue accepts a standalone startup handshake before the first command', async (t) => {
  const { queue, output } = queueFixture(t, true);
  output.write(Buffer.from([0]));
  const result = command(queue);
  output.write(Buffer.from('answer'));
  output.write(Buffer.from([0]));
  assert.equal(await result, 'answer');
});

test('queue removes completed commands before callbacks and dispatches each once', () => {
  const writes = [];
  const input = new Writable({ write(data, _encoding, done) {
    writes.push(data.toString());
    done();
  } });
  const output = new PassThrough();
  const queue = new R2PipeQueue(input, output);
  const results = [];
  queue.cmd('first', (error, value) => {
    assert.ifError(error);
    results.push(value);
    queue.cmd('third', (error, value) => {
      assert.ifError(error);
      results.push(value);
    });
  });
  queue.cmd('second', (error, value) => {
    assert.ifError(error);
    results.push(value);
  });
  output.write(Buffer.from('one\0two\0three\0'));
  assert.deepEqual(results, ['one', 'two', 'three']);
  assert.deepEqual(writes, ['first\n', 'second\n', 'third\n']);
  queue.dispose();
});

test('queue compacts a large pending queue without losing or duplicating commands', async (t) => {
  const { queue, output, writes } = queueFixture(t);
  const commands = Array.from({ length: 4096 }, (_, index) => command(queue, String(index)));
  output.write(Buffer.alloc(commands.length));
  assert.deepEqual(await Promise.all(commands), Array(commands.length).fill(''));
  assert.deepEqual(writes, commands.map((_, index) => `${index}\n`));
});

for (const [name, trigger] of [
  ['input errors', ({ input }) => input.destroy(new Error('broken input'))],
  ['output errors', ({ output }) => output.destroy(new Error('broken output'))],
  ['input closure', ({ input }) => input.destroy()],
  ['output closure', ({ output }) => output.destroy()],
  ['output EOF', ({ output }) => output.end()],
  ['disposal', ({ queue }) => queue.dispose()]
]) {
  test(`queue rejects pending and future commands on ${name}`, async (t) => {
    const fixture = queueFixture(t);
    const results = Promise.all([
      assert.rejects(command(fixture.queue, 'first')),
      assert.rejects(command(fixture.queue, 'second'))
    ]);
    trigger(fixture);
    await results;
    await assert.rejects(command(fixture.queue, 'later'));
    assert.equal(fixture.input.destroyed, true);
    assert.equal(fixture.output.destroyed, true);
    fixture.queue.dispose();
  });
}

test('queue propagates synchronous write failures', async (t) => {
  const { queue, input } = queueFixture(t);
  t.mock.method(input, 'write', () => { throw new Error('write failed'); });
  await assert.rejects(command(queue), /write failed/);
  await assert.rejects(command(queue), /write failed/);
});

test('queue propagates asynchronous write callback failures', async () => {
  const input = new Writable({ write(_data, _encoding, done) {
    done(new Error('write callback failed'));
  } });
  const output = new PassThrough();
  const queue = new R2PipeQueue(input, output);
  await assert.rejects(command(queue), /write callback failed/);
  await assert.rejects(command(queue), /write callback failed/);
  queue.dispose();
});

test('queue fails explicitly on unsolicited extra response frames', async (t) => {
  const { queue, output } = queueFixture(t);
  const result = command(queue);
  output.write(Buffer.from('answer\0extra\0'));
  assert.equal(await result, 'answer');
  await assert.rejects(command(queue), /without a pending command/);
});

function fakeChild(t) {
  const child = new EventEmitter();
  child.writes = [];
  child.stdin = new Writable({ write(data, _encoding, done) {
    child.writes.push(data.toString());
    done();
  } });
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kills = [];
  child.kill = (signal) => { child.kills.push(signal); return true; };
  t.mock.method(childProcess, 'spawn', () => child);
  return child;
}

test('spawn shares response framing and drains diagnostics', async (t) => {
  const child = fakeChild(t);
  const pipe = new R2PipeSpawn('-');
  t.after(() => pipe.quit());
  child.stderr.write(Buffer.alloc(4 * 1024 * 1024, 'x'));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(child.stderr.readableLength, 0);
  const empty = pipe.cmd('s 1');
  const unicode = pipe.cmd('?e €');
  child.stdout.write(Buffer.from([0, 0, 0xe2]));
  child.stdout.write(Buffer.from([0x82, 0xac, 0]));
  assert.equal(await empty, '');
  assert.equal(await unicode, '€');
  await pipe.quit();
  await pipe.quit();
  assert.deepEqual(child.kills, ['SIGINT']);
  await assert.rejects(pipe.cmd('later'), /closed/);
});

for (const event of ['error', 'close']) {
  test(`spawn propagates child ${event} to pending and future commands`, async (t) => {
    const child = fakeChild(t);
    const pipe = new R2PipeSpawn('-');
    t.after(() => pipe.quit());
    const results = Promise.all([assert.rejects(pipe.cmd('first')), assert.rejects(pipe.cmd('second'))]);
    if (event === 'error') {
      child.emit('error', new Error('cannot launch'));
    } else {
      child.emit('close', 1, null);
    }
    await results;
    await assert.rejects(pipe.cmd('later'));
  });
}

test('spawn rejects commands when the executable does not exist', { timeout: 5000 }, async (t) => {
  const pipe = new R2PipeSpawn('-', path.join(os.tmpdir(), 'r2pipe-missing-executable-' + process.pid));
  t.after(() => pipe.quit());
  await assert.rejects(pipe.cmd('ij'), /ENOENT/);
  await assert.rejects(pipe.cmd('ij'));
});

test('local Windows connection uses the complete named pipe path and quit preserves the caller', async (t) => {
  const socket = new PassThrough();
  const pipePath = '\\\\.\\pipe\\r2pipe-test';
  const previousPath = process.env.R2PIPE_PATH;
  process.env.R2PIPE_PATH = pipePath;
  t.after(() => {
    if (previousPath === undefined) delete process.env.R2PIPE_PATH;
    else process.env.R2PIPE_PATH = previousPath;
  });
  t.mock.method(os, 'platform', () => 'win32');
  let connectedPath;
  t.mock.method(net, 'connect', (value) => { connectedPath = value; return socket; });
  t.mock.method(process, 'kill', () => { assert.fail('local quit must not signal the caller'); });
  const pipe = new R2PipeLocal();
  assert.equal(connectedPath, pipePath);
  const pending = assert.rejects(pipe.cmd('pending'));
  await pipe.quit();
  await pending;
  await pipe.quit();
  await assert.rejects(pipe.cmd('later'), /closed/);
});

test('local Windows connection rejects a missing named pipe path', (t) => {
  const previousPath = process.env.R2PIPE_PATH;
  delete process.env.R2PIPE_PATH;
  t.after(() => {
    if (previousPath !== undefined) process.env.R2PIPE_PATH = previousPath;
  });
  t.mock.method(os, 'platform', () => 'win32');
  assert.throws(() => new R2PipeLocal(), /R2PIPE_PATH/);
});

const r2 = childProcess.spawnSync('radare2', ['-v'], { stdio: 'ignore' });
const hasR2 = !r2.error && r2.status === 0;

test('real radare2 spawn completes empty and UTF-8 responses', { skip: !hasR2, timeout: 10000 }, async (t) => {
  const pipe = new R2PipeSpawn('-');
  t.after(() => pipe.quit());
  assert.equal(await pipe.cmd('s 1'), '');
  assert.equal((await pipe.cmd('?e €')).trim(), '€');
});

test('real radare2 local quit lets the caller continue and both processes exit', {
  skip: !hasR2 || os.platform() === 'win32', timeout: 10000
}, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'r2pipe-local-test-'));
  try {
    const script = path.join(directory, 'local.cjs');
    const modulePath = path.resolve(__dirname, '../dist/local.js');
    fs.writeFileSync(script, `
      const assert = require('node:assert/strict');
      const { R2PipeLocal } = require(${JSON.stringify(modulePath)});
      (async () => {
        const pipe = new R2PipeLocal();
        assert.equal((await pipe.cmd('?e local-ok')).trim(), 'local-ok');
        await pipe.quit();
        await pipe.quit();
        await assert.rejects(pipe.cmd('later'));
        console.log('continued-after-quit');
      })().catch(error => { console.error(error); process.exitCode = 1; });
    `);
    const result = childProcess.spawnSync('radare2', ['-q', '-c', `#!pipe ${process.execPath} ${script}`, '-'], {
      encoding: 'utf8', timeout: 5000
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /continued-after-quit/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
