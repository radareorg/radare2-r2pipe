import sockets, strutils
import httpclient
import asyncdispatch

type
  R2PipeHttp = object
    url*:string

proc cmd*(r: R2PipeHttp, c: string):Future[string] {.async.} =
  var client = newAsyncHttpClient()
  var resp = await client.request(r.url & "/cmd/" & c)
  return resp.body;

