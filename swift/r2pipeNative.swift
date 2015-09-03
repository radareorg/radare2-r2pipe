#if HAVE_SPAWN
import Foundation

private struct Stack<T> {
	var items = [T]()
	mutating func push(item:T) {
		items.append (item);
	}
	mutating func pop() -> T? {
		if items.count > 0 {
			return items.removeLast()
		}
		return nil;
	}
}

typealias Closure = (String)->Void

class R2PipeNative {
	var taskNotLaunched = true;
	var initState = true;
	private var stack = Stack<Closure>();
	private let pipe = NSPipe()
	private let pipeIn = NSPipe()
	private let task = NSTask()
	private var bufferedString = "";
	private var inHandle:NSFileHandle? = nil;

	init?(file:String?) {
		let outHandle:NSFileHandle;
		if file == nil {
#if USE_ENV_PIPE
			let dict = NSProcessInfo.processInfo().environment
				let env_IN = dict["R2PIPE_IN"] as String?
				let env_OUT = dict["R2PIPE_OUT"] as String?

				// print ("PIPES \(env_IN) \(env_OUT)");
				if env_IN == nil || env_OUT == nil {
					return nil;
				}
			let fd_IN = Int32(env_IN!);
			let fd_OUT = Int32(env_OUT!);
			if fd_IN == nil || fd_OUT == nil {
				return nil;
			}
			if fd_IN < 0 || fd_OUT < 0 {
				return nil;
			}
			initState = false;
			taskNotLaunched = false;
			outHandle = NSFileHandle(fileDescriptor:fd_IN!)
			inHandle = NSFileHandle(fileDescriptor:fd_OUT!)
#else
			return nil;
#endif
		} else {
			task.launchPath = "/usr/bin/radare2";
			task.arguments = ["-q0", file!]
			task.standardOutput = pipe
			task.standardInput = pipeIn
			outHandle = pipe.fileHandleForReading
			inHandle = pipeIn.fileHandleForWriting
		}
		outHandle.waitForDataInBackgroundAndNotify()
		NSNotificationCenter.defaultCenter()
				.addObserverForName(NSFileHandleDataAvailableNotification,
				object: outHandle, queue: nil) {
			notification -> Void in
			var data = outHandle.availableData
			if data.length > 0 {
				var count = data.length
				var pointer = UnsafePointer<UInt8>(data.bytes)
				var buffer = UnsafeBufferPointer<UInt8>(start:pointer, count:count)
				var foundTerminator = false;
				var foundTerminatorAt = -1;
				for (var i = 0; i<count; i++) {
					if (buffer[i] == 0) {
						foundTerminator = true;
						foundTerminatorAt = i;
						break;
					}
				}

				if (foundTerminator) {
					for (;;) {
						if (self.initState) {
							// skip
							self.initState = false;
						} else {
							let newData = NSData(bytes:data.bytes, length:foundTerminatorAt);
							if let str = NSString(data:newData, encoding: NSUTF8StringEncoding) {
								self.bufferedString += str as String;
								self.runCallback (self.bufferedString);
								self.bufferedString = "";
							} else {
								print ("ERROR")
							}
						}

						let newBytes = UnsafePointer<UInt8>(data.bytes) + foundTerminatorAt + 1;
						count = count - foundTerminatorAt - 1;
						data = NSData(bytes:newBytes, length:count);
						pointer = UnsafePointer<UInt8>(newBytes)
						buffer = UnsafeBufferPointer<UInt8>(start:pointer, count:count)

						if count < 1 {
							break;
						}
						foundTerminator = false;
						foundTerminatorAt = -1;
						for (var i = 0; i<count; i++) {
							if (buffer[i] == 0) {
								foundTerminator = true;
								foundTerminatorAt = i;
								break;
							}
						}
						if (!foundTerminator) {
							if let d = NSString(data:data, encoding: NSUTF8StringEncoding) {
								self.bufferedString = d as String
							}
							break;
						}
					}
				} else {
					if let str = NSString(data:data, encoding: NSUTF8StringEncoding) {
						self.bufferedString += str as String;
					}
				}

				outHandle.waitForDataInBackgroundAndNotify ();
			} else {
				// EOF happened
			}
		}

		NSNotificationCenter.defaultCenter()
				.addObserverForName(NSTaskDidTerminateNotification,
				object: outHandle, queue: nil) {
			notification -> Void in
			print ("Terminated")
			/* TODO: Terminate properly */
			self.taskNotLaunched = true;
		}
	}

	private func runCallback(str:String) {
		if let closure = stack.pop() {
			closure(str);
		}
	}

	func sendCommand(str:String, closure:Closure) -> Bool{
		let cmd = str + "\n";
		if let data = cmd.dataUsingEncoding(NSUTF8StringEncoding) {
			inHandle!.writeData (data)
			stack.push (closure);
		}
		if (self.taskNotLaunched) {
			task.launch()
			self.taskNotLaunched = false;
			self.initState = true;
		}
		return true;
	}

	func sendCommandSync(str:String) -> String? {
		let timeout = 10000000;
		var result:String? = nil;
		self.sendCommand (str, closure:{
			(str:String) in
			result = str
		})
		for (var i = 0; i<timeout; i++) {
			// wait for reply in a loop
			if let r = result {
				return r;
			}
			let next = NSDate(timeIntervalSinceNow:0.1)
			NSRunLoop.currentRunLoop().runUntilDate(next);
		}
		return nil;
	}
}

#endif
