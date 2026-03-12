#if USE_SPAWN
    import Foundation

    private struct Queue<T> {
        var items = [T]()
        mutating func enqueue(_ item: T) {
            items.append(item)
        }

        mutating func dequeue() -> T? {
            if !items.isEmpty {
                return items.removeFirst()
            }
            return nil
        }
    }

    typealias Closure = (String?) -> Void

    class R2PipeNative {
        var taskNotLaunched = true
        var initState = true
        private var queue = Queue<Closure>()
        private let pipe = Pipe()
        private let pipeIn = Pipe()
        private let task = Process()
        private var bufferedString = ""
        private var inHandle: FileHandle?
        private var observers = [NSObjectProtocol]()

        private static func resolveRadare2Command() -> (String, [String]) {
            let env = ProcessInfo.processInfo.environment
            let command = env["R2PIPE_R2"] ?? "r2"
            if command.contains("/") {
                return (command, [])
            }
            return ("/usr/bin/env", [command])
        }

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
                let (launchPath, launchArguments) = Self.resolveRadare2Command()
                task.executableURL = URL(fileURLWithPath: launchPath)
                task.arguments = launchArguments + [
                    "-q0",
                    "-e", "scr.color=0",
                    "-e", "scr.interactive=false",
                    "-e", "bin.relocs.apply=true",
                    file!,
                ]
                task.standardOutput = pipe
                task.standardInput = pipeIn
                var environment = ProcessInfo.processInfo.environment
                if environment["R2_NOPLUGINS"] == nil {
                    environment["R2_NOPLUGINS"] = "1"
                }
                task.environment = environment
                outHandle = pipe.fileHandleForReading
                inHandle = pipeIn.fileHandleForWriting
            }
            outHandle.waitForDataInBackgroundAndNotify()

            observers.append(NotificationCenter.default.addObserver(forName: NSNotification.Name.NSFileHandleDataAvailable,
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
            })

            observers.append(NotificationCenter.default.addObserver(forName: Process.didTerminateNotification,
                                                                    object: task, queue: nil)
            {
                _ in
                self.taskNotLaunched = true
            })
        }

        deinit {
            for observer in observers {
                NotificationCenter.default.removeObserver(observer)
            }
        }

        private func runCallback(_ str: String) {
            if let closure = queue.dequeue() {
                closure(str)
            }
        }

        private func launchTaskIfNeeded() -> Bool {
            if taskNotLaunched {
                do {
                    try task.run()
                    taskNotLaunched = false
                    initState = true
                } catch {
                    return false
                }
            }
            return true
        }

        func sendCommand(_ str: String, closure: @escaping Closure) -> Bool {
            guard launchTaskIfNeeded(), let inHandle else {
                return false
            }
            let cmd = str + "\n"
            guard let data = cmd.data(using: .utf8) else {
                return false
            }
            queue.enqueue(closure)
            inHandle.write(data)
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
