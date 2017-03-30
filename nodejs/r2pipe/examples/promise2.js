const r2pipe = require('..');
const co = require('co');

r2pipe.open('/bin/ls', (err, r2) => {
  if (err) {
    throw err;
  }
  r2pipe.open('/bin/cp', (err, r22) => {
    if (err) {
      throw err;
    }
    const r2p = r2.promisify();
    const r22p = r22.promisify();
    co(function * () {
      try {
        console.log(yield r2p.cmd('o'));
        console.log(yield r22p.cmd('o'));
      } catch (err) {
        console.error(err);
      }
      console.log('Should be done');
      r22.quit();
      r2.quit();
      console.log('Should be done');
    });
  });
});
