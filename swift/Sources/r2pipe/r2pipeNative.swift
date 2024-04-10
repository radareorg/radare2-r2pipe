#if USE_SPAWN
    import Foundation

    private struct Stack<T> {
        var items = [T]()
        mutating func push(item: T) {
            items.append(item)
        }

        mutating func pop() -> T? {
            if items.count > 0 {
                return items.removeLast()
            }
            return nil
        }
    }

    typealias Closure = (String?) -> Void

    class R2PipeNative {
        var taskNotLaunched = true
        var initState = true
        private var stack = Stack<Closure>()
        private let pipe = Pipe()
        private let pipeIn = Pipe()
        private let task = Process()
        private var bufferedString = ""
        private var inHandle: FileHandle?

        init?(file: String?) {
            var outHandle: FileHandle
            outHandle = pipe.fileHandleForReading
            if file == nil {
                #if USE_ENV_PIPE
                    let dict = ProcessInfo.processInfo.environment
                    let env_IN = dict["R2PIPE_IN"] as String?
                    let env_OUT = dict["R2PIPE_OUT"] as String?

                    // print ("PIPES \(env_IN) \(env_OUT)");
                    if env_IN == nil || env_OUT == nil {
                        return nil
                    }
                    if let fd_IN = Int32(env_IN!),
                       let fd_OUT = Int32(env_OUT!)
                    {
                        if fd_IN < 0 || fd_OUT < 0 {
                            return nil
                        }
                        initState = false
                        taskNotLaunched = false
                        outHandle = FileHandle(fileDescriptor: fd_IN)
                        inHandle = FileHandle(fileDescriptor: fd_OUT)
                    }
                #else
                    return nil
                #endif
            } else {
                task.launchPath = "/usr/bin/radare2"
                task.arguments = ["-q0", file!]
                task.standardOutput = pipe
                task.standardInput = pipeIn
                outHandle = pipe.fileHandleForReading
                inHandle = pipeIn.fileHandleForWriting
            }
            outHandle.waitForDataInBackgroundAndNotify()

            NotificationCenter.default.addObserver(forName: NSNotification.Name.NSFileHandleDataAvailable,
                                                   object: outHandle, queue: nil)
            {
                _ in
                var data = outHandle.availableData
                if data.count > 0 {
                    data.withUnsafeBytes {
                        (bytes: UnsafeRawBufferPointer) in
                        var pointer = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self)
                        var buffer = UnsafeBufferPointer<UInt8>(start: pointer, count: data.count)
                        var foundTerminator = false
                        var foundTerminatorAt = -1
                        for i in 0 ..< data.count {
                            if buffer[i] == 0 {
                                foundTerminator = true
                                foundTerminatorAt = i
                                break
                            }
                        }

                        if foundTerminator {
                            while true {
                                if self.initState {
                                    // skip
                                    self.initState = false
                                } else {
                                    let newData = Data(bytes: pointer!, count: foundTerminatorAt)
                                    if let str = String(data: newData, encoding: .utf8) {
                                        self.bufferedString += str as String
                                        self.runCallback(self.bufferedString)
                                        self.bufferedString = ""
                                    } else {
                                        print("ERROR")
                                    }
                                }

                                let newBytes = bytes.baseAddress! + foundTerminatorAt + 1
                                let k = data.count - foundTerminatorAt - 1
                                data = Data(bytes: newBytes, count: k)
                                pointer = newBytes.assumingMemoryBound(to: UInt8.self)
                                buffer = UnsafeBufferPointer<UInt8>(start: pointer, count: k)

                                if k < 1 {
                                    break
                                }
                                foundTerminator = false
                                foundTerminatorAt = -1
                                for i in 0 ..< k {
                                    if buffer[i] == 0 {
                                        foundTerminator = true
                                        foundTerminatorAt = i
                                        break
                                    }
                                }
                                if !foundTerminator {
                                    if let d = String(data: data, encoding: String.Encoding.utf8) {
                                        self.bufferedString = d as String
                                    }
                                    break
                                }
                            }
                        } else {
                            if let str = String(data: data, encoding: .utf8) {
                                self.bufferedString += str as String
                            }
                        }

                        outHandle.waitForDataInBackgroundAndNotify()
                    }
                } else {
                    // EOF happened
                }
            }

            NotificationCenter.default.addObserver(forName: Process.didTerminateNotification,
                                                   object: outHandle, queue: nil)
            {
                _ in
                print("Terminated")
                /* TODO: Terminate properly */
                self.taskNotLaunched = true
            }
        }

        private func runCallback(_ str: String) {
            if let closure = stack.pop() {
                closure(str)
            }
        }

        func sendCommand(_ str: String, closure: @escaping Closure) -> Bool {
            let cmd = str + "\n"
            if let data = cmd.data(using: .utf8) {
                inHandle!.write(data)
                stack.push(item: closure)
            }
            if taskNotLaunched {
                task.launch()
                taskNotLaunched = false
                initState = true
            }
            return true
        }

        func sendCommandSync(_ str: String) -> String? {
            let timeout = 10_000_000
            var result: String?
            let res = sendCommand(str, closure: {
                (str: String?) in
                result = str
            })
            if !res {
                return nil
            }
            for _ in 0 ..< timeout {
                // wait for reply in a loop
                if let r = result {
                    return r
                }
                let next = Date(timeIntervalSinceNow: 0.1)
                RunLoop.current.run(until: next)
            }
            return nil
        }
    }

#endif
