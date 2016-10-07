/*
  Test open and openSync lpipe protocols
*/

var r2pipe = require ('../');

const syncMode = process.argv[2] == '-s';

/* sync example */
try {
  if (syncMode) {
    const r2p = r2pipe.openSync();
    console.log(r2p.cmdj('ij'));
    r2p.quit();
  } else {
    r2pipe.open((err, r2p) => {
      r2p.cmdj('ij', (err, res) => {
        console.log(res);
        r2p.quit();
      });
    });
  }
} catch (e) {
  console.error (e); //.toString());
}
