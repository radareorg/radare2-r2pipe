
const r2promise = require('./'); //r2pipe-promise');
r2promise.open('/bin/ls')
.then(r2 => {
  r2.cmd('?E hello world')
  .then(res => {
    console.log(res);
    r2.quit();
  })
  .catch(console.error);
})
.catch(console.error);
