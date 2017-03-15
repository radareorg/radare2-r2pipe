r2pipe-promise
==============

The r2pipe-promise is a frontend for the r2pipe module that provides
a promisified API that can be used with `co`, `bluebird` or just in
plain Javascript using the `.then`, `.catch` methods.

This allows to create cleaner and better asynchronous scripts without
making the whole logic.

This is an example:

```
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

```
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
