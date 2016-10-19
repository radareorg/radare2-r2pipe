/* pancake - 2016 - radare project */

const r2pipe = require('..');
const fs = require('fs');


const buf = new Buffer([1,2,3,4]);

r2pipe.openBuffer(buf, (err, r2) => {
  if (err) {
    throw err;
  }
  r2.cmd('p8 4; wx 11223344', (err, res) => {
    if (err) {
      throw err;
    }
    console.log(res);
    r2.getBuffer(0, 4, (err, res) => {
      if (err) {
        throw err;
      }
      console.log('BufBack', res);
      r2.quit();
    });
  });
});
