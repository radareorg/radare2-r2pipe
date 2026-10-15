#!/usr/bin/env node
// Release management stays separate from the runtime backend: no implicit downloads.
const fs = require('node:fs/promises');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const api = 'https://api.github.com/repos/radareorg/radare2/releases';

function apiAsset(release) {
  return release.assets.find(asset => /^radare2-.*-wasi-api\.zip$/.test(asset.name));
}

async function request(url) {
  const response = await fetch(url, { headers: { 'User-Agent': 'r2pipe-ts', Accept: 'application/vnd.github+json' } });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} fetching ${url}`);
  }
  return response;
}

async function* releases() {
  for (let page = 1; ; page++) {
    const entries = await (await request(`${api}?per_page=100&page=${page}`)).json();
    yield* entries.filter(release => !release.draft);
    if (entries.length < 100) return;
  }
}

async function selectRelease(version) {
  if (version !== 'latest') {
    const release = await (await request(`${api}/tags/${encodeURIComponent(version)}`)).json();
    if (!apiAsset(release)) throw new Error(`Release ${version} has no wasi-api build`);
    return release;
  }
  for await (const release of releases()) {
    if (!release.prerelease && apiAsset(release)) return release;
  }
  throw new Error('No release with a wasi-api build was found');
}

async function main(args) {
  if (args[0] === '--help' || args[0] === '-h') {
    console.log('Usage: wasm-download.cjs --list | [latest|VERSION] [OUTPUT.wasm]\nDefaults: newest stable release with a wasi-api build, ./radare2.wasm\nRequires Node.js 20+ and unzip for downloads.');
    return;
  }
  if (args[0] === '--list' && args.length === 1) {
    for await (const release of releases()) {
      console.log(`${release.tag_name}\t${apiAsset(release)?.name ?? '(no API build)'}`);
    }
    return;
  }
  if (args.length > 2 || args[0]?.startsWith('-')) {
    throw new Error('Usage: wasm-download.cjs --list | [latest|VERSION] [OUTPUT.wasm]');
  }
  const release = await selectRelease(args[0] ?? 'latest');
  const asset = apiAsset(release);
  const destination = path.resolve(args[1] ?? 'radare2.wasm');
  const directory = await fs.mkdtemp(path.join(path.dirname(destination), '.r2pipe-wasm-'));
  try {
    console.error(`Downloading ${asset.name} from radare2 ${release.tag_name}`);
    const archive = path.join(directory, 'release.zip');
    await fs.writeFile(archive, new Uint8Array(await (await request(asset.browser_download_url)).arrayBuffer()));
    const listing = spawnSync('unzip', ['-Z1', archive], { encoding: 'utf8' });
    if (listing.error) throw listing.error;
    if (listing.status !== 0) throw new Error(`Cannot list release archive: ${listing.stderr}`);
    const entries = listing.stdout.split(/\r?\n/).filter(name => /(^|\/)radare2\.wasm$/.test(name));
    if (entries.length !== 1) throw new Error('Expected exactly one radare2.wasm in the API archive');
    const wasmFile = path.join(directory, 'radare2.wasm');
    const file = await fs.open(wasmFile, 'wx+');
    try {
      const extraction = spawnSync('unzip', ['-p', archive, entries[0]], { stdio: ['ignore', file.fd, 'pipe'] });
      if (extraction.error) throw extraction.error;
      if (extraction.status !== 0) throw new Error(`Cannot extract radare2.wasm: ${extraction.stderr}`);
      const header = Buffer.alloc(8);
      await file.read(header, 0, 8, 0);
      if (!header.equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]))) {
        throw new Error('The release archive did not contain a WASM module');
      }
    } finally {
      await file.close();
    }
    await fs.rename(wasmFile, destination);
    console.log(destination);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}

module.exports = { main, selectRelease };
if (require.main === module) {
  main(process.argv.slice(2)).catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
