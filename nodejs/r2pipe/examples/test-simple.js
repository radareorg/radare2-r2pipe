var r2pipe = require('r2pipe');

r2pipe.open(function (err, r2) {
  if (err) throw err;
  console.log(r2.cmd('?e hello world'));
});
