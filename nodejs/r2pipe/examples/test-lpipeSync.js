/*  Small tests for r2pipe */
// return true;

const r2pipe = require('..');

try {
  const r2 = r2pipe.lpipeSync();
  const res = r2.cmd('pd 4');
  const resj = r2.cmdj('pdj 4');

  console.log('Normal output');
  console.log(res);

  console.log('JSON output');
  console.log(resj);
  r2.quit();
} catch (e) {
  console.error(e.toString());
  process.exit(1);
}
