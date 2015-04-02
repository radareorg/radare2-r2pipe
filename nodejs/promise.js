function Promise (func, cmd, callback) {
  this._thens = [];
  this.doneHandler = null;
  this.i = 0;

  this.then(func, cmd, callback);
  this.execute();
}


Promise.prototype.execute = function () {

  var aThen = this._thens[this.i];
  var self = this;

  aThen.func(aThen.cmd, function(arg1, arg2) {

    /* Execute original callback */
    if (typeof aThen.callback === 'function')
      aThen.callback(arg1, arg2);

    /* Execute next promise */
    if (self._thens[++self.i])
      self.execute();

    /* Execute done callback */
    else if (typeof self.doneHandler === 'function')
      self.doneHandler();
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