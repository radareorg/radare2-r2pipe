
const r2promise = require('./'); // r2pipe-promise');
var a = r2promise.open('/bin/ls');

console.log('AAA', a);

a
.then(r2 => {
  r2.cmd('?e hello world')
  .then(res => {
    console.log(res);
    r2.quit();
  })
  .catch(console.error);
})
.catch(console.error);
