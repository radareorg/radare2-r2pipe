import * as r2pipe from "@r2pipe";

const r2 = r2pipe.open();
console.log(r2.cmd("?e hello"));
