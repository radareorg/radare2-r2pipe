'use strict';

const co = require('co');
const r2pipe = require('r2pipe');

const r2launch = co.wrap(function * (fn) {
  return new Promise(function (resolve) {
    r2pipe.launch(fn, function (r2) {
      r2.__cmd = r2.cmd;
      r2.cmd = co.wrap(function * (cmd) {
        return new Promise(function (resolve) {
          r2.__cmd(cmd, resolve);
        });
      });
      resolve(r2);
    });
  });
});

const identifyTarget = co.wrap(function * (bin) {
  return new Promise(function (resolve) {
    co(function * () {
      const r2 = yield r2launch(bin);
      console.log('->', yield r2.cmd('?V'));
      resolve(r2);
    });
  });
});

co(function * () {
  let r = yield identifyTarget('/bin/ls');
  console.log(yield r.cmd('pd 3'));
  r.quit();
});
