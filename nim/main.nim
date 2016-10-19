include r2pipe
import asyncdispatch

proc test {.async.} = 
  let r2p = R2PipeHttp(url: "http://cloud.radare.org")
  let res = await r2p.cmd("?V")
  echo(res);

proc testApi =
  let r2p = R2PipeApi();
  let res = r2p.cmd("pd 20")
  echo(res);
  echo(r2p.cmd("?e hello world"))

testApi()
waitFor test()
