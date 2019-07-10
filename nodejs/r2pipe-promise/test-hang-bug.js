const r2pipePromise = require('r2pipe-promise');
const r2pipe = require('r2pipe');

// Async hangs
async function test () {
  const r2 = await r2pipePromise.open();
  const msg = await r2.cmd('?E hello');
  console.log(msg);
  await r2.quit();
}

async function testSync () {
  const r2 = r2pipe.openSync();
  const msg = r2.cmd('?E hello');
  console.log(msg);
  r2.quit();
}

// hangs
test().then(console.log).catch(console.error);
// works
//testSync().then(console.log).catch(console.error);
bare().then(console.log).catch(console.error);
