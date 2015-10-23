'use strict';
require('colors');

require("../..").open((r2) => {
  r2.cmd('?e r2 async r2pipe.js', (r) => {
    console.log('[OK] '.green + r.trim().yellow);
    r2.quit();
  });
});
