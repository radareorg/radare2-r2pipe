const r2pipe = require('..');
const co = require('co');

r2pipe.open('/bin/ls', (err, r2) => {
  if (err) {
    throw err;
  }
  const r2p = r2.promisify();
  co(function * () {
    try {
      const hello = yield r2p.cmd('?E Hello');
      console.log(hello);
      const version = yield r2p.cmd('?V');
      console.log('version', version);
      const info = yield r2p.cmdj('ij');
      console.log('info', JSON.stringify(info, null, '  '));
    } catch (err) {
      console.error(err);
    }
    yield r2p.quit();
  });
});
