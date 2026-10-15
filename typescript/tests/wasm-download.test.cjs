const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const { main, selectRelease } = require('../wasm-download.cjs');

function release(tag, api = true, extra = {}) {
  return { tag_name: tag, assets: api ? [{
    name: `radare2-${tag}-wasi-api.zip`, browser_download_url: 'https://example.test/api.zip',
  }] : [{ name: `radare2-${tag}-wasi.zip` }], ...extra };
}

test('download selection paginates and skips CLI builds, drafts and prereleases', async (t) => {
  const first = Array.from({ length: 100 }, (_, i) => release(`cli-${i}`, false));
  const second = [release('draft', true, { draft: true }), release('next', true, { prerelease: true }), release('stable')];
  const urls = [];
  t.mock.method(globalThis, 'fetch', async url => {
    urls.push(url);
    return Response.json(new URL(url).searchParams.get('page') === '1' ? first : second);
  });
  assert.equal((await selectRelease('latest')).tag_name, 'stable');
  assert.equal(urls.length, 2);
  assert.match(urls[1], /page=2$/);
});

test('download selection uses explicit tags and rejects missing API assets or HTTP failures', async (t) => {
  let requested;
  t.mock.method(globalThis, 'fetch', async url => {
    requested = url;
    return Response.json(release('6.2.0'));
  });
  assert.equal((await selectRelease('6.2.0')).tag_name, '6.2.0');
  assert.match(requested, /\/tags\/6\.2\.0$/);
  t.mock.method(globalThis, 'fetch', async () => Response.json(release('6.2.4', false)));
  await assert.rejects(selectRelease('6.2.4'), /has no wasi-api build/);
  t.mock.method(globalThis, 'fetch', async () => new Response('', { status: 404 }));
  await assert.rejects(selectRelease('missing'), /HTTP 404/);
});

test('download helper lists all releases and marks those without API builds', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => Response.json([release('6.2.4', false), release('6.2.0')]));
  const lines = [];
  t.mock.method(console, 'log', line => lines.push(line));
  await main(['--list']);
  assert.deepEqual(lines, ['6.2.4\t(no API build)', '6.2.0\tradare2-6.2.0-wasi-api.zip']);
});

// A single stored ZIP entry, so tests need no ZIP library or zip executable.
function zipEntry(name, data) {
  const filename = Buffer.from(name);
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  crc = (crc ^ 0xffffffff) >>> 0;
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50);
  local.writeUInt16LE(20, 4);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(filename.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(filename.length, 28);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length + filename.length, 12);
  end.writeUInt32LE(local.length + filename.length + data.length, 16);
  return Buffer.concat([local, filename, data, central, filename, end]);
}

test('download helper extracts the WASM file and preserves existing output on failure', {
  skip: spawnSync('unzip', ['-v'], { stdio: 'ignore' }).status !== 0,
}, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'r2pipe-wasm-download-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const output = path.join(directory, 'selected.wasm');
  const wasm = fs.readFileSync(path.join(__dirname, 'fixtures/wasm-api.wasm'));
  let archive = zipEntry('radare2-version-wasi-api/radare2.wasm', wasm);
  t.mock.method(globalThis, 'fetch', async url => url.endsWith('api.zip')
    ? new Response(archive) : Response.json(release('6.2.0')));
  t.mock.method(console, 'log', () => {});
  t.mock.method(console, 'error', () => {});
  await main(['6.2.0', output]);
  assert.deepEqual(fs.readFileSync(output), wasm);
  archive = zipEntry('radare2.wasm', Buffer.from('not wasm'));
  await assert.rejects(main(['6.2.0', output]), /did not contain a WASM module/);
  assert.deepEqual(fs.readFileSync(output), wasm);
  archive = zipEntry('other.wasm', wasm);
  await assert.rejects(main(['6.2.0', output]), /exactly one radare2.wasm/);
  assert.deepEqual(fs.readdirSync(directory), ['selected.wasm']);
});
