var r2pipe = require ('r2pipe');

r2pipe.open(function(err, r2) {
   console.log(r2.cmd('?e hello world'));
});

