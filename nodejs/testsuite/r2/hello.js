require('colors');
var r2p = require('../..');
var r2 = r2p.open();
console.log('[OK] '.green + r2.cmd('?e r2 sync r2pipe.js').trim().yellow);
r2.quit();
