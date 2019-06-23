const r2promise = require('./');

const radare2FTW = async () => {
  try {
    const r2 = await r2promise.open('/bin/ls');
    const msg = await r2.cmd('?E hello world');
    console.log(msg);
    return r2.quit();
  } catch (err) {
    console.error(err);
  }
};

radare2FTW();
