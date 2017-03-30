/* pancake - 2016 - radare project */

const r2pipe = require('..');
const fs = require('fs');

const buf = fs.readFileSync('/bin/ls');

r2pipe.openBuffer(buf, (err, r2) => {
  if (err) {
    throw err;
  }
  r2.cmd('pd 20', (err, res) => {
    if (err) {
      throw err;
    }
    console.log(res);
    r2.quit();
  });
});

/*

PoC

const net = require('net');

const server = net.createServer(client => {
  client.write(buf, null, _ => {
    client.destroy();
    server.close();
  });
});

server.listen(0, _ => {
  const port = server.address().port;
  r2pipe.open('tcp://127.0.0.1:' + port, (err, r2) => {
    if (err) {
      throw err;
    }
    r2.cmd('pd 20', (err, res) => {
      console.log(res);
      r2.quit();
    });
  });
});
*/
