const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { open, parseJson } = require('../dist/index.js');
const { R2PipeBase } = require('../dist/base.js');

class StaticPipe extends R2PipeBase {
  constructor(output) {
    super();
    this.output = output;
  }
  async cmd() { return this.output; }
  async quit() { return true; }
}

test('JSON preserves exact unsafe integers, including signed and 64-bit boundaries', () => {
  assert.deepEqual(parseJson('[9007199254740991,9007199254740992,9007199254740993,-9007199254740993,18446744073709551615,-9223372036854775808]'), [
    9007199254740991, 9007199254740992n, 9007199254740993n, -9007199254740993n,
    18446744073709551615n, -9223372036854775808n,
  ]);
  assert.equal(parseJson('9'.repeat(400)), BigInt('9'.repeat(400)));
});

test('JSON retains fractions, exponent notation, primitives and escaped strings', () => {
  assert.equal(parseJson('null'), null);
  assert.equal(parseJson('true'), true);
  assert.equal(parseJson('"9007199254740993"'), '9007199254740993');
  assert.deepEqual(parseJson('[0,-0,1.5,9007199254740993.0,9007199254740993e0,1e100]'), [
    0, -0, 1.5, Number('9007199254740993.0'), Number('9007199254740993e0'), 1e100,
  ]);
  const text = JSON.stringify({ escaped: '\\"9007199254740993\n', unicode: '€😀' });
  assert.deepEqual(parseJson(text), JSON.parse(text));
});

test('JSON rewrites cannot collide with user strings or mutate __proto__ properties', () => {
  const text = '{"__proto__":{"offset":9007199254740993},"marker":"\\u0000r2pipe.bigint:0","escaped":"\\\"9007199254740993","array":[18446744073709551615]}';
  const parsed = parseJson(text);
  assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
  assert.equal(Object.hasOwn(parsed, '__proto__'), true);
  assert.equal(parsed.__proto__.offset, 9007199254740993n);
  assert.equal(parsed.marker, '\0r2pipe.bigint:0');
  assert.equal(parsed.escaped, '"9007199254740993');
  assert.deepEqual(parsed.array, [18446744073709551615n]);
});

test('JSON rejects malformed source instead of repairing unsafe numeric tokens', () => {
  for (const text of ['{9007199254740993:0}', '09007199254740993', '[9007199254740993,]', '+9007199254740993', '9007199254740993e', '"unterminated', '{"x":9007199254740993} trailing']) {
    assert.throws(() => parseJson(text), SyntaxError, text);
  }
});

test('cmdj defaults to lossless parsing and retains custom parser errors as causes', async () => {
  const pipe = new StaticPipe('9007199254740993');
  assert.equal(await pipe.cmdj(''), 9007199254740993n);
  pipe.jsonParser = JSON.parse;
  assert.equal(await pipe.cmdj(''), 9007199254740992);
  const cause = new Error('custom parser failed');
  pipe.jsonParser = () => { throw cause; };
  await assert.rejects(pipe.cmdj(''), (error) => error.cause === cause);
});

async function serverFor(t, handler) {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise((resolve) => {
    server.closeAllConnections();
    server.close(resolve);
  }));
  return `http://127.0.0.1:${server.address().port}`;
}

test('HTTP encodes commands, preserves dot commands and normalizes base paths', { timeout: 5000 }, async (t) => {
  const requests = [];
  const url = await serverFor(t, (req, res) => {
    requests.push(req.url);
    res.end('ok');
  });
  const commands = ['?e # %41 / + & ?\n€😀', '.', '..', ''];
  const pipe = open(`${url}/prefix///`);
  for (const command of commands) {
    assert.equal(await pipe.cmd(command), 'ok');
  }
  assert.deepEqual(requests, commands.map((command) => `/prefix/cmd/${encodeURIComponent(command)}`));
  const root = open(`${url}/`);
  assert.equal(await root.cmd('i'), 'ok');
  assert.equal(requests.at(-1), '/cmd/i');
  assert.equal(await pipe.quit(), true);
});

test('HTTP rejects aborted and failed responses', { timeout: 5000 }, async (t) => {
  const url = await serverFor(t, (req, res) => {
    if (req.url.endsWith('/status')) {
      res.writeHead(503);
      res.end('unavailable');
    } else {
      res.writeHead(200, { 'Content-Length': 100 });
      res.write('partial');
      setImmediate(() => res.destroy());
    }
  });
  const pipe = open(url);
  await assert.rejects(pipe.cmd('partial'), /aborted|closed|socket hang up|reset/i);
  await assert.rejects(pipe.cmd('status'), /Status Code: 503/);
});

test('open configures JSON parsing for HTTP backends', { timeout: 5000 }, async (t) => {
  const url = await serverFor(t, (_req, res) => res.end('9007199254740993'));
  assert.equal(await open(url).cmdj(''), 9007199254740993n);
  assert.equal(await open(url, { jsonParser: JSON.parse }).cmdj(''), 9007199254740992);
});
