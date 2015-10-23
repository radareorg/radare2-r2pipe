var r2pipe = require ('r2pipe');
r2pipe.open(function(r2) {
   console.log(r2.cmd('?e hello world'));
});

