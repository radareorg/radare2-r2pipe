'use strict';
const r2pipe = require("./");
r2pipe.syscmd(["/bin/ls", "-l", "/"], (r) => {
  console.log(r);
});
