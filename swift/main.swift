import Foundation

print("Hello r2pipe.swift!");

let r2p = R2Pipe(url:"http://cloud.radare.org/cmd/");
if (r2p != nil) {
	r2p!.cmd ("pi 5 @ entry0", closure:{ (str:String)->() in
		print (str)
		exit (0);
	});
}

/* main loop required for async network requests */
NSRunLoop.currentRunLoop().run();
