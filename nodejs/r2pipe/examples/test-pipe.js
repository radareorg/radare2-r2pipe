'use strict';

function assert (a, b) {
  if (a === b) {
    console.error('test passes ok');
  } else {
    console.error('assert', a, b);
    process.exit(1);
  }
}

const r2p = require('../');
r2p.pipe('target-bin', ['-nw'], (error, r2) => {
  assert(error, null);
  r2.cmd('wx 90;p8 1', (error, result) => {
    assert(error, null);
    assert(result.trim(), '90');
    r2.cmd('wx 90', (error, result) => {
      assert(error, null);
      r2.quit();
      console.log('done');
    });
  });
});
