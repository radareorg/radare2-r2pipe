import Foundation
#if USE_SWIFTY_JSON
    import SwiftyJSON
#endif
#if USE_CCALL
    import r_core
#endif

public enum R2PipeChannel {
    case Unknown
    case Http
    case Native
    case Ccall
    case Env
}

extension String {
    func URLEncodedString() -> String? {
        let customAllowedSet = CharacterSet.urlQueryAllowed
        let escapedString = addingPercentEncoding(withAllowedCharacters: customAllowedSet)
        return escapedString
    }

    func ToR2WebURL(_ str: String) -> String {
        var ret = self
        if !hasSuffix("/") {
            ret += "/"
        }
        return ret + str.URLEncodedString()!
    }
}

typealias open = R2Pipe

public class R2Pipe {
    var mode: R2PipeChannel = .Unknown
    var path = ""
    #if USE_CCALL
        var r2c: UnsafeMutableRawPointer?
    #endif
    #if USE_SPAWN
        var r2p: R2PipeNative?
    #endif
    public init?(_ url: String?) {
        if url == nil || url == "#!pipe" {
            #if USE_SPAWN
                #if USE_ENV_PIPE
                    mode = .Env
                    r2p = R2PipeNative(file: nil)
                    if r2p == nil {
                        return nil
                    }
                #else
                    return nil
                #endif
            #else
                return nil
            #endif
        } else if url == "#!ccall" {
            mode = .Ccall
            #if USE_CCALL
                r2c = r_core.r_core_new()
            #else
                return nil
            #endif
        } else if url!.contains("://") {
            if url!.hasPrefix("http://")
                || url!.hasPrefix("https://")
            {
                mode = .Http
                path = url!
            } else {
                return nil
            }
        } else {
            #if USE_SPAWN
                print("RUNNING ANTIVE SPAWN")
                mode = .Native
                path = url!
                r2p = R2PipeNative(file: url!)
            #else
                print("NO SPAWN")
                return nil
            #endif
        }
    }

    #if USE_CCALL
        func cmdCcall(_ str: String, closure: (String?) -> Void) -> Bool {
            if let s = cmdCcallSync(str) {
                closure(s)
                return true
            }
            return false
        }

        func cmdCcallSync(_ str: String) -> String? {
            if r2c != nil {
                if let s = r_core.r_core_cmd_str(r2c, str) {
                    let r = String(cString: s)
                    // r_core.free (s);
                    return r
                }
            }
            return nil
        }
    #endif

    func cmdHttp(_ str: String, closure: @escaping (String?) -> Void) -> Bool {
        let urlstr = path.ToR2WebURL(str)
        let request = URLRequest(url: URL(string: urlstr)!)
        URLSession.shared.dataTask(with: request, completionHandler: {
            (data: Data?, _: URLResponse?, _: Error?) in
            let str = String(data: data!, encoding: String.Encoding.utf8)
            closure(str as String?)
        })
        return true
    }

    func cmdHttpSync(_ str: String) -> String? {
        #if USE_NSURL_SESSION
            /* not yet supported */
        #endif
        let urlstr = path.ToR2WebURL(str)
        let url = URL(string: urlstr)
        let request = URLRequest(url: url!)
        var responseStr: String!
        DispatchQueue.main.async {
            let session = URLSession.shared
            let task = session.dataTask(with: request) { data, _, _ in
                if let rstr = String(data: data!, encoding: String.Encoding.utf8) {
                    responseStr = rstr
                    return
                }
            }
            task.resume()
        }
        return responseStr
    }

    @discardableResult
    public func cmd(_ str: String, closure: @escaping (String?) -> Void) -> Bool {
        switch mode {
        case .Ccall:
            #if USE_CCALL
                return cmdCcall(str, closure: closure)
            #else
                return false
            #endif
        case .Http:
            return cmdHttp(str, closure: closure)
        case .Native, .Env:
            #if USE_SPAWN
                if let r2p {
                    return r2p.sendCommand(str, closure: closure)
                }
            #endif
            return false
        default:
            return false
        }
    }

    @discardableResult
    public func cmdSync(_ str: String) -> String? {
        switch mode {
        case .Ccall:
            #if USE_CCALL
                return cmdCcallSync(str)
            #else
                return nil
            #endif
        case .Http:
            return cmdHttpSync(str)
        case .Native, .Env:
            #if USE_SPAWN
                if let r2p {
                    return r2p.sendCommandSync(str)
                }
            #endif
            return nil
        default:
            return nil
        }
    }

    /* JSON APIs */
    #if USE_SWIFTY_JSON
        public func cmdjSync(_ str: String) -> NSDictionary? {
            if let s = cmdSync(str) {
                return JSON(s)
            }
            return nil
        }

        public func cmdj(_ str: String, _ closure: (NSDictionary) -> Void) -> Bool {
            cmd(str, closure: {
                (_: String?) in
                if let js = JSON(obj) {
                    closure(js)
                }
            })
            return true
        }
    #else
        func jsonParse(_ str: String) -> NSDictionary? {
            // f let data = data(usingEncoding:allowLossyConversion:
            if let data = str.data(using: String.Encoding.utf8, allowLossyConversion: true) {
                // if let data = str.dataUsingEncoding(String.Encoding.utf8) {
                do {
                    let parsedObject = try JSONSerialization.jsonObject(with: data, options: .allowFragments)
                    return parsedObject as? NSDictionary
                } catch _ {
                    return nil
                }
            }
            return nil
        }

        public func cmdjSync(_ str: String) -> NSDictionary? {
            if let s = cmdSync(str) {
                if let obj = jsonParse(s) {
                    return obj
                }
            }
            return nil
        }

        public func cmdj(_ str: String, _ closure: @escaping (NSDictionary?) -> Void) -> Bool {
            _ = cmd(str, closure: {
                (s: String?) in
                if s != nil {
                    if let obj = self.jsonParse(s!) {
                        closure(obj)
                    }
                } else {
                    closure(nil)
                }
            })
            return true
        }
    #endif
}
