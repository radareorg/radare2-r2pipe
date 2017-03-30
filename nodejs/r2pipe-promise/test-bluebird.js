const Promise = require('bluebird');
const r2pipe = Promise.promisifyAll(require('r2pipe'));

r2pipe.openAsync('/bin/ls').then(r => {
  const r2 = Promise.promisifyAll(r);
  r2.cmdAsync('?E hello').then(msg => {
    console.log(msg);
    r2.quitAsync();
  });
})
.catch(err => {
  console.error(err.message);
});
