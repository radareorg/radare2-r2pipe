/* pancake - 2016 - radare project */

const r2pipe = require('..');
const net = require('net');

const buf = new Buffer([1,2,3,4,5,6,7,8,9]);
const r2port = 9998;

/* this is a bit racy, but works as a PoC */

setTimeout(_=>{
  const client = new net.Socket();
  client.connect(r2port, '127.0.0.1', _ => {
    client.write(buf, null, _ => {
      client.destroy();
    });
  });
}, 100);

r2pipe.open('tcp://:' + r2port, (err, r2) => {
  r2.cmd('p8 10', (err, res) => {
    console.log(res);
    r2.quit();
  });
});

