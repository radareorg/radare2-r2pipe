const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const { open } = require('../dist/index.js');

const fixture = path.join(__dirname, 'fixtures/wasm-api.wasm');

function instances(t) {
  const exports = [];
  const instantiate = WebAssembly.instantiate;
  t.mock.method(WebAssembly, 'instantiate', async (...args) => {
    const result = await instantiate(...args);
    exports.push(result.instance.exports);
    return result;
  });
  return exports;
}

test('other backends load and run without WebAssembly or WASI', () => {
  const result = spawnSync(process.execPath, ['-e', `
    const assert = require('node:assert/strict');
    const Module = require('node:module');
    const load = Module._load;
    Module._load = function(name, ...args) {
      assert.ok(!['wasi', 'node:wasi'].includes(name), 'WASI must remain optional');
      return load.call(this, name, ...args);
    };
    delete globalThis.WebAssembly;
    const { EventEmitter } = require('node:events');
    const { PassThrough } = require('node:stream');
    const child = new EventEmitter();
    child.pid = 12345;
    child.exitCode = null;
    child.signalCode = null;
    child.stdin = new PassThrough();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = signal => {
      process.nextTick(() => {
        child.signalCode = signal;
        child.emit('close', null, signal);
      });
      return true;
    };
    require('node:child_process').spawn = () => child;
    const { open } = require('./dist/index.js');
    (async () => {
      assert.equal(await open('http://localhost:9090').quit(), true);
      const pipe = open('malloc://16');
      const pending = pipe.cmd('?e native-without-wasm');
      child.stdout.write(Buffer.from('\\0native-without-wasm\\0'));
      assert.equal(await pending, 'native-without-wasm');
      await pipe.quit();
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `], { cwd: path.join(__dirname, '..'), encoding: 'utf8', timeout: 10000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stderr, /WASI/);
});

test('WASM is opt-in and initializes once on the first command', async (t) => {
  const loaded = instances(t);
  const pipe = open('malloc://16', { wasm: { path: fixture } });
  t.after(() => pipe.quit());
  assert.equal(loaded.length, 0);
  assert.deepEqual(await Promise.all(['first', '', 'grow €😀'].map(command => pipe.cmd(command))), [
    'first', '', 'grow €😀',
  ]);
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].created_cores(), 1);
  assert.equal(loaded[0].allocated_strings(), loaded[0].freed_strings());
  await pipe.quit();
  await pipe.quit();
  assert.equal(loaded[0].freed_cores(), 1);
  await assert.rejects(pipe.cmd('later'), /closed/);
});

test('WASM cmdj uses the shared lossless and custom JSON parsers', async (t) => {
  const pipe = open('', { wasm: { path: fixture } });
  const native = open('', { wasm: { path: fixture }, jsonParser: JSON.parse });
  t.after(() => Promise.all([pipe.quit(), native.quit()]));
  assert.deepEqual(await pipe.cmdj('json'), { offset: 18446744073709551615n });
  assert.deepEqual(await native.cmdj('json'), { offset: Number('18446744073709551615') });
});

test('WASM frees command strings on errors and remains usable', async (t) => {
  const loaded = instances(t);
  const pipe = open('', { wasm: { path: fixture } });
  t.after(() => pipe.quit());
  await assert.rejects(pipe.cmd('!null'), /null string/);
  await assert.rejects(pipe.cmd('a\0b'), /NUL/);
  await assert.rejects(pipe.cmd('a'.repeat(65536)), /allocate/);
  assert.equal(await pipe.cmd('after error'), 'after error');
  assert.equal(loaded[0].allocated_strings(), loaded[0].freed_strings());
});

test('WASM quit drains accepted commands and rejects new commands', async (t) => {
  const loaded = instances(t);
  const pipe = open('', { wasm: { path: fixture } });
  const first = pipe.cmd('first');
  const second = pipe.cmd('second');
  const quit = pipe.quit();
  assert.equal(pipe.quit(), quit);
  await assert.rejects(pipe.cmd('late'), /closed/);
  assert.deepEqual(await Promise.all([first, second, quit]), ['first', 'second', true]);
  assert.equal(loaded[0].freed_cores(), 1);
});

test('WASM closes an unused backend without loading its module', async () => {
  const pipe = open('', { wasm: { path: '/does/not/exist.wasm' } });
  assert.equal(await pipe.quit(), true);
  await assert.rejects(pipe.cmd('late'), /closed/);
});

test('WASM failed file initialization frees its core and caches the error', async (t) => {
  const loaded = instances(t);
  const pipe = open('!missing', { wasm: { path: fixture } });
  await assert.rejects(pipe.cmd('first'), /Cannot open.*preopens/);
  await assert.rejects(pipe.cmd('again'), /Cannot open.*preopens/);
  await pipe.quit();
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].freed_cores(), 1);
  assert.equal(loaded[0].allocated_strings(), loaded[0].freed_strings());
});

test('WASM reports unsupported runtimes, missing paths, and non-API modules', async (t) => {
  assert.throws(() => open('', { wasm: {} }), /requires a path/);
  const runtime = globalThis.WebAssembly;
  globalThis.WebAssembly = undefined;
  try {
    const pipe = open('', { wasm: { path: fixture } });
    await assert.rejects(pipe.cmd(''), /requires WebAssembly support/);
    await pipe.quit();
  } finally {
    globalThis.WebAssembly = runtime;
  }
  const missing = open('', { wasm: { path: '/does/not/exist.wasm' } });
  await assert.rejects(missing.cmd(''), /ENOENT/);
  await missing.quit();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'r2pipe-wasm-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const empty = path.join(directory, 'empty.wasm');
  fs.writeFileSync(empty, Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
  const pipe = open('', { wasm: { path: empty } });
  await assert.rejects(pipe.cmd(''), /Missing WASM export.*wasi-api/);
  await pipe.quit();
});

test('released radare2 WASM supports memory IO, UTF-8, JSON and explicit file access', {
  skip: !process.env.R2PIPE_WASM, timeout: 30000,
}, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'r2pipe-wasm-real-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, 'file ; €'), Buffer.from('9090c3', 'hex'));
  const wasm = { path: process.env.R2PIPE_WASM };
  const pipe = open('malloc://16', { wasm });
  t.after(() => pipe.quit());
  assert.equal(await pipe.cmd('s 0'), '');
  assert.equal((await pipe.cmd('?e €😀')).trim(), '€😀');
  await pipe.cmd('wx 9090c3');
  assert.equal((await pipe.cmd('p8 3')).trim(), '9090c3');
  await pipe.cmd('e asm.arch=x86');
  assert.equal((await pipe.cmdj('aoj 1'))[0].mnemonic, 'nop');
  await pipe.cmd('f exact @ 0x20000000000001');
  assert.equal((await pipe.cmdj('fj')).find(flag => flag.name === 'exact').addr, 9007199254740993n);
  const file = open('/data/file ; €', { wasm: { ...wasm, preopens: { '/data': directory } } });
  t.after(() => file.quit());
  assert.equal((await file.cmd('p8 3')).trim(), '9090c3');
  const denied = open(path.join(directory, 'file ; €'), { wasm });
  t.after(() => denied.quit());
  await assert.rejects(denied.cmd('p8 3'), /Cannot open/);
});
