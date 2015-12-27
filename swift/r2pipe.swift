import Foundation
#if USE_SWIFTY_JSON
import SwiftyJSON
#endif
#if USE_CCALL
import r_core
#endif

enum R2PipeChannel {
	case Unknown
	case Http
	case Native
	case Ccall
	case Env
}

extension String {
	func URLEncodedString() -> String? {
		let customAllowedSet = NSCharacterSet.URLQueryAllowedCharacterSet()
		let escapedString = self.stringByAddingPercentEncodingWithAllowedCharacters(customAllowedSet)
		return escapedString
	}
	func ToR2WebURL(str:String) -> String {
		var ret = self;
		if !self.hasSuffix ("/") {
			ret += "/";
		}
		return ret + str.URLEncodedString()!;
	}
}

class R2Pipe {
	var mode : R2PipeChannel = .Unknown;
	var path = "";
#if USE_CCALL
	var r2c : UnsafeMutablePointer<()> = nil;
#endif
#if USE_SPAWN
	var r2p : R2PipeNative? = nil;
#endif
	init?(url: String?) {
		if url == nil || url == "#!pipe" {
#if USE_SPAWN
#if USE_ENV_PIPE
			mode = .Env
			self.r2p = R2PipeNative(file:nil);
			if self.r2p == nil {
				return nil;
			}
#else
			return nil;
#endif
#else
			return nil;
#endif
		} else if url == "#!ccall" {
			mode = .Ccall;
#if USE_CCALL
			r2c = r_core.r_core_new();
#else
			return nil;
#endif
		} else if url!.rangeOfString("://") != nil {
			if url!.hasPrefix ("http://")
			|| url!.hasPrefix ("https://") {
				mode = .Http
				path = url!
			}
		} else {
#if USE_SPAWN
			mode = .Native
			path = url!
			self.r2p = R2PipeNative(file:url!)
#else
			return nil
#endif
		}
	}

#if USE_CCALL
	func cmdCcall(str: String, closure:(String?)->()) -> Bool {
		if let s = cmdCcallSync(str) {
			closure (s);
			return true;
		}
		return false;
	}

	func cmdCcallSync(str: String) -> String? {
		if r2c != nil {
			let s = r_core.r_core_cmd_str(r2c, str);
			if s != nil {
				let r = String.fromCString(s);
	//			r_core.free (s);
				return r;
			}
		}
		return nil;
	}
#endif

	func cmdHttp(str: String, closure:(String?)->()) -> Bool {
		let urlstr = self.path.ToR2WebURL(str);
		let url = NSURL(string: urlstr);
		let request = NSURLRequest(URL: url!)
#if USE_NSURL_SESSION
		NSURLSession.sharedSession().dataTaskWithRequest(request, completionHandler:{
			(data:NSData?, url:NSURLResponse?, error:NSError?) -> Void in
			let str = NSString(data: data!, encoding: NSUTF8StringEncoding)
			closure (str as? String);
		})
#else
		NSURLConnection.sendAsynchronousRequest(request, queue: NSOperationQueue.mainQueue()) {(response, data, error) in
			if let d = data {
				let str = NSString(data: d, encoding: NSUTF8StringEncoding)
				closure (str as String?);
			} else {
				closure (nil);
			}
		}
#endif
		return true;
	}

	func cmdHttpSync(str: String) -> String? {
#if USE_NSURL_SESSION
		/* not yet supported */
#endif
		let urlstr = self.path.ToR2WebURL(str);
		let url = NSURL(string: urlstr);
		let request = NSURLRequest(URL: url!)
		let response:AutoreleasingUnsafeMutablePointer<NSURLResponse?> = nil;
		do {
			let responseData = try NSURLConnection.sendSynchronousRequest(
					request, returningResponse: response) as NSData;
			let responseStr = NSString(data:responseData, encoding:NSUTF8StringEncoding);
			if responseStr != nil {
				return responseStr! as String;
			}
		} catch _ {
			print ("catch");
		}
		return nil;
	}

	func cmd(str:String, closure:(String?)->()) -> Bool {
		switch (mode) {
		case .Ccall:
#if USE_CCALL
			return cmdCcall(str, closure:closure);
#else
			return false;
#endif
		case .Http:
			return cmdHttp(str, closure:closure);
		case .Native, .Env:
#if USE_SPAWN
			if let r2p = self.r2p {
				return r2p.sendCommand (str, closure:closure);
			}
#endif
			return false;
		default:
			return false;
		}
	}

	func cmdSync(str:String) -> String? {
		switch (mode) {
		case .Ccall:
#if USE_CCALL
			return cmdCcallSync(str);
#else
			return nil;
#endif
		case .Http:
			return cmdHttpSync(str);
		case .Native, .Env:
#if USE_SPAWN
			if let r2p = self.r2p {
				return r2p.sendCommandSync(str);
			}
#endif
            return nil;
		default:
			return nil;
		}
	}

	/* JSON APIs */
#if USE_SWIFTY_JSON
	func cmdjSync(str:String) -> NSDictionary? {
		if let s = cmdSync (str) {
			return JSON (s)
		}
		return nil;
	}

	func cmdj(str:String, closure:(NSDictionary)->()) -> Bool {
		cmd (str, closure:{
			(s:String?)->() in
			if let js = JSON (obj) {
				closure (js)
			}
		});
		return true;
	}
#else
	func jsonParse(str:String) -> NSDictionary? {
		if let data = str.dataUsingEncoding(NSUTF8StringEncoding) {
			do {
				if let parsedObject: AnyObject? = try NSJSONSerialization.JSONObjectWithData(data,
						options: NSJSONReadingOptions.AllowFragments) {
					return parsedObject as? NSDictionary
				}
			} catch _ {
				return nil;
			}
		}
		return nil;
	}

	func cmdjSync(str:String) -> NSDictionary? {
		if let s = cmdSync (str) {
			if let obj = self.jsonParse (s) {
				return obj;
			}
		}
		return nil;
	}

	func cmdj(str:String, closure:(NSDictionary?)->()) -> Bool {
		cmd (str, closure:{
			(s:String?)->() in
			if (s != nil) {
				if let obj = self.jsonParse (s!) {
					closure (obj);
				}
			} else {
				closure(nil);
			}
		});
		return true;
	}
#endif
}
