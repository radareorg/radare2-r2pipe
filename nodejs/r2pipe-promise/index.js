'use strict';

const r2pipe = require('r2pipe');

module.exports = {
  open: function openPromise (file, options) {
    return new Promise(function (resolve, reject) {
      function cb (err, res) {
        if (err) {
          return reject(err);
        }
        resolve(r2promise(res));
      }
      const args = [file, options, cb].filter(x => x !== undefined);
      r2pipe.open(...args);
    });
  }
};

class TimeoutError extends Error {
  constructor () {
    super(...arguments);
    this.name = 'TimeoutError';
  }
}

function R2Promise (r2, method, args) {
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
  let promise = new Promise((resolve, reject) => {
    myReject = reject;
    function handler(err, res) {
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
    }
    args.push(handler);
    try {
      r2[method](...args);
    } catch (e) {
      stopTimer();
      reject(e);
    }
  });

  promise.name = method + args[0];

  promise.timeout = (ns) => {
    timer = setTimeout(function promiseTimeout () {
      if (!finished) {
        const msg = `Timeout on r2.${method}(${args[0]})`;
        myReject(new TimeoutError(msg));
        finished = true;
      }
      timer = null;
    }, ns);
    return promise;
  };
  return promise;
}

function makePromise (r2, method) {
  return function () {
    return new R2Promise(r2, method, [...arguments]);
  }
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
