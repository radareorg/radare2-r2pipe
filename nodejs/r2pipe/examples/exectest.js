'use strict';

const r2pipe = require('../');

r2pipe.syscmd(['/bin/ls', '-l', '/'], (err, r) => {
  if (err) throw err;
  console.log(r);
});
