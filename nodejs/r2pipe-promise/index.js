'use strict';

const r2pipe = require('r2pipe');

module.exports = {
  open: function openPromise (file) {
    return new Promise(function (resolve, reject) {
      r2pipe.open(file, (err, res) => {
        if (err) {
          return reject(err);
        }
        resolve(r2promise(res));
      });
    });
  }
};

function makePromise (obj, method) {
  return function cb () {
    const args = [...arguments];
    return new Promise(function (resolve, reject) {
      args.push(function (err, res) {
        if (err) {
          return reject(err);
        }
        resolve(res);
      });
      obj[method](...args);
    });
  };
}

function r2promise (r2) {
  return {
    cmd: makePromise(r2, 'cmd'),
    cmdj: makePromise(r2, 'cmdj'),
    syscmd: makePromise(r2, 'syscmd'),
    syscmdj: makePromise(r2, 'syscmdj'),
    quit: makePromise(r2, 'quit')
  };
}
