'use strict';

/* XXX: Promise prototype is read only, properties should not be added */

function Promise (func, cmd, callback) {
  this._thens = [];
  this.doneHandler = null;
  this.i = 0;
  this.then(func, cmd, callback);
  this.execute();
}

Promise.prototype.execute = function () {
  const aThen = this._thens[this.i];
  aThen.func(aThen.cmd, (arg1, arg2) => {
    /* Execute original callback */
    if (typeof aThen.callback === 'function') {
      aThen.callback(arg1, arg2);
    }
    if (this._thens[++this.i]) {
      /* Execute next promise */
      this.execute();
    } else if (typeof this.doneHandler === 'function') {
      /* Execute done callback */
      this.doneHandler();
    }
  });
};

Promise.prototype.then = function (func, cmd, callback) {
  this._thens.push({func: func, cmd: cmd, callback: callback});
  return this;
};

Promise.prototype.done = function (func) {
  this.doneHandler = func;
};

module.exports.Promise = Promise;
