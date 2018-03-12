r2pipe-promise
==============

The r2pipe-promise is a frontend for the r2pipe module that provides
a promisified API that can be used with `co`, `bluebird` or just in
plain Javascript using the `.then`, `.catch` methods.

This allows to create cleaner and better asynchronous scripts without
making the whole logic.

This is an example:

```js
const r2promise = require('r2pipe-promise');
r2promise.open('/bin/ls')
.then(r2 => {
  r2.cmd('?E hello world')
  .then(res => {
    console.log(res);
    r2.quit();
  })
  .catch(console.error);
})
.catch(console.error);

```

Another example using the `co` module:

```js
const r2promise = require('r2pipe-promise');
const co = require('co');

co(function * () {
  try {
    const r2 = yield r2promise.open('/bin/ls');
    console.log('This is', yield r2.cmd('o'));
    yield r2.quit();
  } catch (e) {
    console.error('error', e);
    process.exit(1);
  }
});
```

You can achieve the same using `bluebird` in exchange of having
more dependencies and verboser code.

```js
const Promise = require('bluebird');
const r2pipe = Promise.promisifyAll(require('r2pipe'));

r2pipe.openAsync('/bin/ls').then(r => {
  const r2 = Promise.promisifyAll(r);
  r2.cmdAsync('?E hello').then(msg => {
    console.log(msg);
    r2.quitAsync();
  });
})
.catch(err => {
  console.error(err.message);
});
~
```

Since node 7.6 there is default support for Async/Await, so now we
can use it to write more cleaner and legible code, for example:

```js
const r2promise = require('r2pipe-promise');

const radare2FTW = async () => {
  try {
    const r2 = await r2promise.open('/bin/ls');
    const msg = await r2.cmd('?E hello world');
    console.log(msg);
    return r2.quit();
  } catch (err) {
    console.error(err);
  }
}

// Call function
radare2FTW();
```
