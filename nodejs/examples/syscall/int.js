#!/usr/bin/env node
var r2pipe = require ("r2pipe");
var sn = +process.argv[2];

// runs some code emulating each syscall
console.log ("Running NodeJS powered syscall handler", sn);

function syscall_linux_x86_32(r2p,regs) {
	console.log ("REGS",regs);
	switch (regs.eax) {
	case 1: // exit() syscall
		console.log ("[SYSCALL] exit code ", regs.ebx);
		break;
	case 4: // write() syscall, 
		console.log ("[SYSCALL] write fd:",regs.ebx);
		console.log ("[SYSCALL] write data:",regs.ecx);
		console.log ("[SYSCALL] write len:",regs.edx);
		mustexit = false;
		var a0 = regs.ebx; // fd
		var a2 = regs.ecx; // data
		var a3 = regs.edx; // len
		r2p.cmd ("psz "+a3+"@"+a2, function (out) {
			console.log (out);
			process.exit (0);
		});
		break;
	default: // etc...
		console.log ("[SYSCALL] reg:",regs.eax);
	}
}

// it works using r2pipe, connecting to r2 session
r2pipe.rlangpipe(function (r2p) {
	var syscall = syscall_linux_x86_32;
	switch (sn) {
	case 3: // same as INT3
		console.error ("[INT3] Breakpoint trap");
		process.exit (0);
		break;
	case 128:
	case 0x80: // INT 0x80
		/* linux */
		console.error ("[SYSCALL] number:", sn);
		r2p.cmdj ("arj", function(regs) {
			if (syscall (r2p,regs))
				process.exit (0);
		});
		break;
	default:
		process.exit (0);
		break;
	}
});
