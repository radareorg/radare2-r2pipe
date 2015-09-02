import Foundation

enum R2PipeChannel {
	case Unknown
	case Http
	case Spawn
}

extension String {
	func URLEncodedString() -> String? {
		let customAllowedSet =  NSCharacterSet.URLQueryAllowedCharacterSet()
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

	init?(url: String) {
		if (url.hasPrefix ("http://")) {
			mode = .Http;
			path = url;
		} else {
			return nil;
		}
	}

	func cmdHttp(str: String, closure:(String)->()) -> Bool {
		let urlstr = self.path.ToR2WebURL(str);
		let url = NSURL(string: urlstr);
		let request = NSURLRequest(URL: url!)
		NSURLConnection.sendAsynchronousRequest(request, queue: NSOperationQueue.mainQueue()) {(response, data, error) in
			let str = NSString(data: data!, encoding: NSUTF8StringEncoding)
			closure (str as! String);
		}
		return true;
	}

	func cmd(str:String, closure:(String)->()) -> Bool {
		switch (mode) {
		case .Http:
			return cmdHttp(str, closure:closure);
		case .Spawn:
			return false;
		default:
			return false;
		}
	}
}
