#!/usr/bin/env node
var r2pipe = require('r2pipe');
var sn = +process.argv[2];

// runs some code emulating each syscall
console.log('Running NodeJS powered syscall handler', sn);

function syscallLinuxX8632 (r2p, regs) {
  console.log('REGS', regs);
  switch (regs.eax) {
    case 1: // exit() syscall
      console.log('[SYSCALL] exit code ', regs.ebx);
      break;
    case 4: // write() syscall,
      const a0 = regs.ebx; // fd
      const a1 = regs.ecx; // data
      const a2 = regs.edx; // len
      console.log('[SYSCALL] write fd:', a0);
      console.log('[SYSCALL] write data:', a1);
      console.log('[SYSCALL] write len:', a2);
      r2p.cmd('psz ' + a2 + '@' + a1, function (out) {
        console.log(out);
        process.exit(0);
      });
      break;
    default: // etc...
      console.log('[SYSCALL] reg:', regs.eax);
  }
}

// it works using r2pipe, connecting to r2 session
r2pipe.lpipe(function (err, r2p) {
  if (err) {
    throw err;
  }
  const syscall = syscallLinuxX8632;
  switch (sn) {
    case 3: // same as INT3
      console.error('[INT3] Breakpoint trap');
      process.exit(0);
      break;
    case 128:
    case 0x80: // INT 0x80
      /* linux */
      console.error('[SYSCALL] number:', sn);
      r2p.cmdj('arj', function (err, regs) {
        if (err) throw err;
        if (syscall(r2p, regs)) {
          process.exit(0);
        }
      });
      break;
    default:
      process.exit(0);
      break;
  }
});
