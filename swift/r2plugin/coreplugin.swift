import Foundation
import Darwin

@_cdecl("test_me")
public func test_me(that thing: Int) {
	print("This is new")
}

func jsonParse(_ str:String) -> NSDictionary? {
	// f let data = data(usingEncoding:allowLossyConversion:
	if let data = str.data(using: String.Encoding.utf8, allowLossyConversion: true) {
		// if let data = str.dataUsingEncoding(String.Encoding.utf8) {
		do {
			let parsedObject = try JSONSerialization.jsonObject(with: data, options: .allowFragments);
			return parsedObject as? NSDictionary
		} catch _ {
			return nil;
		}
	}
	return nil;
}

class RCore {
	let core: UnsafeMutableRawPointer;
	init(_core: UnsafeMutableRawPointer) {
		core = _core;
	}
	func cmd(_ command: String) -> String {
		typealias coreCmdFunc = @convention(c) (_:UnsafeMutableRawPointer,_:UnsafePointer<Int8>) -> UnsafePointer<Int8>
		let r2handle = dlopen("/usr/local/lib/libr_core.dylib", RTLD_NOW)
		let r2cmdstr = dlsym(r2handle, "r_core_cmd_str")
		let r = unsafeBitCast(r2cmdstr, to: coreCmdFunc.self)
		let cstr = command.utf8CString
		var result = ""
		cstr.withUnsafeBufferPointer { pstr in
			let res = r(core, pstr.baseAddress!)
			result = String(cString:res)
			// free (res)
		}
		return result
	}

	func cmdj(_ str: String) -> NSDictionary? {
		return jsonParse(cmd(str))
	}

	func wip(str: String) -> String {
		typealias randomFunc = @convention(c) () -> CInt
		let handle = dlopen("/usr/lib/libc.dylib", RTLD_NOW)
		let sym = dlsym(handle, "random")

		// typealias coreCmdFunc = (_:UnsafeMutableRawPointer,_:UnsafeBufferPointer<Int8>, _:CInt) -> CInt
		typealias coreCmdFunc = @convention(c) (_:UnsafeMutableRawPointer,_:UnsafePointer<Int8>, _:CInt) -> CInt
		let r2handle = dlopen("/usr/local/lib/libr_core.dylib", RTLD_NOW)
		let r2sym = dlsym(r2handle, "r_core_cmd0")
		// print("\(sym)")
		let f = unsafeBitCast(sym, to: randomFunc.self)
		let result = f()

		let r = unsafeBitCast(r2sym, to: coreCmdFunc.self)
		let cstr = str.utf8CString
		cstr.withUnsafeBufferPointer { pstr in
			let rs = String(describing: r)
			print("r \(rs)")
			let r2sult = r(core, pstr.baseAddress!, 0)
			print("r2sult \(r2sult)")
		}
		print("r2sult \(result)")

		// let cstr = str.toCString()
		/*
		let sym = dlsym(UnsafeMutableRawPointer(bitPattern:0), "random")
		let functionPointer = UnsafeMutablePointer<() -> CLong>(sym)
		let result = functionPointer.memory()

		*/
		return "";
	}
}

@_cdecl("r2swift_cmd")
public func r2swift_cmd(_core: UnsafeMutableRawPointer, cmd: UnsafePointer<CChar>) -> CInt {
	let str = String(cString: cmd)
	if str.starts(with:"swift") {
		let core = RCore(_core: _core)
		// run r2 command
		let res = core.cmd("x")
		print("This is your favourite Swift command BEGIN\n \(str) \(res) END")

		if let j = core.cmdj("ij") {
			let j_bin = j.value(forKey:"bin") as? NSDictionary
			if j_bin != nil {
				let j_bin_arch = j_bin!.value(forKey:"arch")!
				print("arch=\(j_bin_arch)")
			}
		}
		//print("Json \(String(describing:j))")
		//print("jbin \(String(describing:j_bin))")
	}
	return 0
}
