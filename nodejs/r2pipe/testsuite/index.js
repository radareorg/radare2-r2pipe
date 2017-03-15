'use strict';

require('colors');

var stack = [];
function queue (cb) {
  stack.push(cb);
}

function next () {
  if (stack.length > 0) {
    var cb = stack.pop();
    try {
      cb();
    } catch (e) {
      console.error(e);
    }
    return true;
  }
  return false;
}

module.exports.inSerial = function () {
  next();
};

module.exports.inParalel = function () {
  while (next());
};

module.exports.addTest = function (n, a, b, opt) {
  queue(() => {
    let msg = ' node '.yellow + n;
    process.stdout.write('[  ]' + msg);
    a((c) => {
      process.stdout.write('\x1b[2K');
      if (c === b) {
        console.log('\r[OK]'.green + msg);
      } else {
        if (opt && opt.broken) {
          console.log('\r[BR]'.blue + msg);
        } else {
          console.log('\r[XX]'.red + msg);
        }
        console.log('((' + c + '))');
      }
      next();
    });
  });
  return module.exports;
};
