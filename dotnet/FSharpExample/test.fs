open System
open r2pipe

[<EntryPoint>]
let main argv = 
  let a = new R2Pipe("/bin/ls");
  let v = a.RunCommand("?V"); 
  printfn "Hello %s" v
  0 
