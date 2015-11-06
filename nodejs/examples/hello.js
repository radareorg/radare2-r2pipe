var r2pipe = require ("../");
r2pipe.syscmd("ls", {cwd:'/'},(x) => { console.log(x); });
r2pipe.options = ['-n'];
var r2 = r2pipe.open("/bin/ls");
console.log(r2.cmd("x"));
r2.quit();
