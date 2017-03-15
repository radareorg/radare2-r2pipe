'use strict';

const r2pipe = require('../');

r2pipe.syscmd(['/bin/ls', '-l', '/'], (err, r) => {
  console.log(r);
});
