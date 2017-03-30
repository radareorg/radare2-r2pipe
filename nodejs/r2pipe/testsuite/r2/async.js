'use strict';
require('colors');

require('../..').open((err, r2) => {
  if (err) throw err;
  r2.cmd('?e r2 async r2pipe.js', (err, res) => {
    if (err) throw err;
    console.log('[OK] '.green + res.trim().yellow);
    r2.quit();
  });
});
