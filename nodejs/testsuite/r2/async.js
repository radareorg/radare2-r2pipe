'use strict';
require('colors');

require('../..').open((err, r2) => {
  r2.cmd('?e r2 async r2pipe.js', (err, res) => {
    console.log('[OK] '.green + res.trim().yellow);
    r2.quit();
  });
});
