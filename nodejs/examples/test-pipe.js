'use strict';

function assert(a, b) {
  if (a === b) {
    console.error('test passes ok');
  } else {
    console.error('assert', a, b);
    process.exit(1);
  }
}

const r2p = require('../');
r2p.pipe('target-bin', ['-nw'], (error, r2) => {
  if (error) {
    console.error('pipe error', error);
    process.exit(1);
  }
  r2.cmd('wx 90;p8 1', (error, result) => {
    assert(result.trim(), '90');
    r2.cmd('wx 90', (error, result) => {
      r2.quit();
      console.log('done');
    });
  });
});
