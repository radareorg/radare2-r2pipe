const r2promise = require('./');
const co = require('co');

function work (file) {
  return co(function * () {
    const r2 = yield r2promise.open(file);
    return [r2, yield r2.cmd('o')];
  });
}

co(function * () {
  try {
    const [r2, msg] = yield work('/bin/ls');
    console.log('This is', msg);
    const [r3, msh] = yield work('/bin/cp');
    console.log('This is', msh);
    yield r3.quit();
    yield r2.quit();
  } catch (e) {
    console.error('error', e);
    process.exit(1);
  }
});
