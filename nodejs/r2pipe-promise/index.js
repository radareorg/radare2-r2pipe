'use strict';

const r2pipe = require('r2pipe');

module.exports = {
  open: function openPromise (file, options) {
    return new Promise(function (resolve, reject) {
      r2pipe.open(file, options, (err, res) => {
        if (err) {
          return reject(err);
        }
        resolve(r2promise(res));
      });
    });
  }
};

class TimeoutError extends Error {
  constructor () {
    super(...arguments);
    this.name = 'TimeoutError';
  }
}

function R2Promise (obj, method, args) {
  let myReject = null;
  let timer = null;
  let finished = false;

  let stopTimer = function () {
    finished = true;
    if (timer !== null) {
      timer.close();
      clearTimeout(timer);
      timer = null;
    }
  };
  let self = new Promise((resolve, reject) => {
    myReject = reject;
    args.push((err, res) => {
      if (finished) {
        console.log('timeout was executed before the execution');
        resolve(res);
        return;
      }
      stopTimer();
      if (err) {
        return reject(err);
      }
      resolve(res);
    });
    try {
      obj[method](...args);
    } catch (e) {
      stopTimer();
      reject(e);
    }
  });

  self.name = method + args[0];

  self.timeout = (ns) => {
    timer = setTimeout(function promiseTimeout () {
      if (!finished) {
        const msg = `Timeout on r2.${method}(${args[0]})`;
        myReject(new TimeoutError(msg));
        finished = true;
      }
      timer = null;
    }, ns);
    return self;
  };
  return self;
}

function makePromise (obj, method) {
  return function cb () {
    return new R2Promise(obj, method, [...arguments]);
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
