open System
open r2pipe

[<EntryPoint>]
let main argv = 
  let a = new R2Pipe "/bin/ls"
  let v: string = a.RunCommand "?V"
  printfn "Hello r2pipe version %s" v
  0 
