'use strict';

var r2pipe = require('../..');
var TestSuite = require('..');

function testAsync5 (fin) {
  let result = '';
  try {
    var count = 5;
    r2pipe.open('../b/ls', function (err, r2) {
      if (err) {
        throw err;
      }
      var intrv = setInterval(function () {
        if (count === 0) {
          r2.quit();
        } else {
          r2.cmd('?e a', (err, x) => {
            if (err) {
              throw err;
            }
            result += x;
            count--;
            if (count === 0) {
              clearInterval(intrv);
              r2.quit();
              fin(result);
            }
          });
        }
      }, 10);
    });
  } catch (e) {
    console.error('XXX', e);
  }
  return result;
}

function testAsyncFor5 (fin) {
  let result = '';
  try {
    var count = 5;
    r2pipe.open('../b/ls', function (err, r2) {
      if (err) {
        throw err;
      }
      for (let i = 0; i < 5; i++) {
        if (count === 0) {
          r2.quit();
        } else {
          r2.cmd('?e a', (err, x) => {
            if (err) throw err;
            result += x;
            count--;
            if (count === 0) {
              r2.quit();
              fin(result);
            }
          });
        }
      }
    });
  } catch (e) {
    console.error('error', e);
  }
  return result;
}

TestSuite
  .addTest('testAsync5', testAsync5, 'a\na\na\na\na\n')
  .addTest('testAsyncFor5', testAsyncFor5, 'a\na\na\na\na\n')
  .inParalel();
