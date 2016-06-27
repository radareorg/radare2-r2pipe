include r2pipe
import asyncdispatch

proc test {.async.} = 
  let r2p = R2PipeHttp(url: "http://cloud.radare.org")
  let res = await r2p.cmd("?V")
  echo(res);

waitFor test();
