import Foundation


private func log (a:String, b:String) {
	let Color = "\u{001b}[32m"
	let Reset = "\u{001b}[0m"
	print (Color+"\(a)("+Reset+"\n\(b)"+Color+")"+Reset)
}

#if HAVE_SPAWN

private func testSpawn () {
	print ("Testing r2pipe spawn method");
	if let r2p = R2Pipe(url:"/bin/ls") {
		if let str = r2p.cmdSync ("?V") {
			log("spawn-sync", b:str)
		} else {
			print ("ERROR: spawnCmdSync");
		}
		r2p.cmd("pd 5 @ entry0", closure:{
			(str:String?)->() in
			if let s = str {
				log("spawn-async", b:s)
			} else {
				log("Error", b:"Network error");
			}
		});
	} else {
		print ("ERROR: spawn not working\n");
	}
}

#else

private func testSpawn () {
	print ("ERROR: Compiled without spawn support")
}

#endif

private func testHttp() {
	print ("Testing r2pipe HTTP method");
	if let r2p = R2Pipe(url:"http://cloud.radare.org/cmd/") {
		if let str = r2p.cmdSync ("?V") {
			log("http-sync", b:str)
		} else {
			print ("ERROR: HTTP Sync Call failed");
		}
		r2p.cmd("pi 5 @ entry0", closure:{
			(str:String?)->() in
			if let s = str {
				log ("http-async", b: s);
			} else {
				log ("error", b: "network");
			}
			exit (0);
		});
	} else {
		print ("ERROR: HTTP method");
	}
}

private func testCcall() {
	print ("Testing r2pipe Ccall method");
	if let r2p = R2Pipe(url:"#!ccall") {
		if let str = r2p.cmdSync ("?V") {
			log("http-sync", b:str)
		} else {
			print ("ERROR: Ccall Sync Call failed");
		}
		r2p.cmdSync ("o /bin/ls");
		r2p.cmd("pi 5 @ entry0", closure:{
			(str:String?)->() in
			if let s = str {
				log ("http-async", b: s);
			} else {
				log ("error", b: "network");
			}
			exit (0);
		});
	} else {
		print ("ERROR: Ccall method");
	}
}

/* ---------------------------- */
/* --          main          -- */
/* ---------------------------- */

print("Hello r2pipe.swift!");

testCcall();
//if let r2p = R2Pipe(url:nil) { //"#!pipe") {
/*
if let r2p = R2Pipe(url:"#!ccall") { //"#!pipe") {
	r2p.cmd ("?V", closure:{
		(str:String?) in
		if let s = str {
			print ("R2PIPE.SWIFT: \(str)");
			exit (0);
		} else {
			debugPrint ("R2PIPE. Error");
			exit (1);
		}
	});
	NSRunLoop.currentRunLoop().run();
} else {
	print ("Invalid R2PIPE_{IN|OUT} environment")
	//testSpawn();
	//testHttp();
	testCcall();
}
*/

/* main loop required for async network requests */
NSRunLoop.currentRunLoop().run();
