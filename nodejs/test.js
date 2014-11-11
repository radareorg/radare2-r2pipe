/*  Small tests for r2pipe */
// return true;

var r2pipe = require ("./");


function doSomeStuff(r2) {

  r2.cmdj ("aij entry0+2", function(o) {
    console.log (o);
  });

  r2.cmd ('af @ entry0', function(o) {
    r2.cmd ("pdf @ entry0", function(o) {
      console.log (o);
      r2.quit ()
    });
  });

}


r2pipe.pipe ("/bin/ls", doSomeStuff);
r2pipe.launch ("/bin/ls", doSomeStuff);
r2pipe.connect ("http://cloud.rada.re/cmd/", doSomeStuff);
