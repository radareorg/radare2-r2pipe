include r2pipe
import asyncdispatch

proc test {.async.} = 
  # let r2p = R2PipeHttp(url: "http://cloud.radare.org")
  let r2p = R2PipeHttp(url: "http://localhost:8080")
  let res = await r2p.cmd("?V")
  echo(res);

proc testApi =
  let r2p = R2PipeApi();
  discard r2p.cmd("o /bin/ls")
  let res = r2p.cmd("pd 20")
  echo(res);
  echo(r2p.cmd("?e hello world"))
  let info = r2p.cmdj("ij");
  echo(info["core"]["file"].str);

testApi()
waitFor test()
