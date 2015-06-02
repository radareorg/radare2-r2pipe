/*
  Test open and openSync rlangpipe protocols
*/

var r2pipe = require ('./');

var sync_mode = process.argv[2] == '-s';

/* sync example */
try {
  if (sync_mode) {
    var r2p = r2pipe.openSync();
    console.log(r2p.cmdj("ij"));
    r2p.quit();
  } else {
    r2pipe.open(function(r2p) {
      r2p.cmdj('ij', function(o) {
        console.log(o);
        r2p.quit();
      });
    });
  }
} catch (e) {
  console.error ("This script must run from r2");
}
