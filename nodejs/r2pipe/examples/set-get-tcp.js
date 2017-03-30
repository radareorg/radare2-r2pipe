/* pancake - 2016 - radare project */

const r2pipe = require('..');

const buf = new Buffer([1, 2, 3, 4]);

r2pipe.openBuffer(buf, (err, r2) => {
// r2pipe.open('malloc://9999', (err, r2) => {
  if (err) {
    throw err;
  }
  r2.cmd('wx 90909090', (err, res) => {
    if (err) {
      throw err;
    }
    r2.getBuffer(0, 4, (err, res) => {
      if (err) {
        throw err;
      }
      console.log('BufBack', res);
      r2.quit();
    });
  });
});
