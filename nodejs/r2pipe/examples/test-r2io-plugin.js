/*

r2 r2pipe://"node test-r2io-plugin.js"

*/

var r2p = require('./../');

r2p.ioplugin(function (io, msg) {
  switch (msg.op) {
    case 'read':
      var obj = {
        result: msg.count,
        data: [1, 2, 3]
      };
      io.send(obj);
      break;
    case 'write':
      /* not implemented */
      io.writeObject();
      break;
    case 'system':
      io.send({
        result: 'Hello World'
      });
      break;
    default:
      io.send();
      break;
  }
});
