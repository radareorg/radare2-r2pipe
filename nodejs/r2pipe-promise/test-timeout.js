const r2promise = require('./');

function testTimeout (ns, cb) {
  console.log('Testing for ' + ns);
  r2promise.open('-')
  .then(waitAndRun)
  .catch(cb);

  function waitAndRun (r2) {
    r2.cmd('!sleep 1')
    .timeout(ns)
    .then(res => {
      r2.quit()
      .then(_ => { cb(null, _); })
      .catch(cb);
    })
    .catch(err => {
      r2.quit();
      cb(err);
    });
  }
}

// XXX if we run the 200ms test first the second call will fail
testTimeout(2000, err => {
  console.log('error must be null', err);
  console.log('2s will fail', err ? 'FAIL' : 'OK');
});

testTimeout(200, err => {
  console.log('error wins', err);
  console.log('200ms will fail', err ? 'OK' : 'FAIL');
});
