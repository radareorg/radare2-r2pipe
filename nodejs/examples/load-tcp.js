/* pancake - 2016 - radare project */

const r2pipe = require('..');
const net = require('net');
const fs = require('fs');

const buf = fs.readFileSync('/bin/ls');
const r2port = 9998;

const server = net.createServer(function(client) {
  client.write(buf, null, _ => {
    client.destroy();
    server.close();
  });
});

server.listen(r2port);

r2pipe.open('tcp://127.0.0.1:' + r2port, (err, r2) => {
  r2.cmd('pd 20', (err, res) => {
    console.log(res);
    r2.quit();
  });
});

