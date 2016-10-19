import sockets, strutils
import httpclient
import asyncdispatch
import sequtils
import json

type
  R2PipeHttp = ref object
    url*:string

proc cmd*(r: R2PipeHttp, c: string):Future[string] {.async.} =
  var client = newAsyncHttpClient()
  var resp = await client.request(r.url & "/cmd/" & c)
  return resp.body;

proc cmdj*(r: R2PipeHttp, c: string):Future[JsonNode] {.async.} =
  return parseJson(await cmd(r, c))

# dll api

proc r_core_new(): pointer {.importc, dynlib: "libr_core.dylib".}
proc r_core_cmd_str(c: pointer, cmd: cstring): cstring {.importc, dynlib: "libr_core.dylib".}
# proc r_core_free(c: pointer): void {.importc, dynlib: "libr_core.dyilb".}

proc toString(str: seq[char]): string =
  result = newStringOfCap(len(str))
  for ch in str:
    add(result, ch)
  return result

proc fromString(str: string): seq[char] =
  return toSeq(str.items)

type R2PipeApi = ref object
  lib: pointer

# proc construct(this: R2PipeAPI) =
#  this.lib = r_core_new();

proc cmd*(this: R2PipeApi, c: string): string =
  if this.lib == nil:
    this.lib = r_core_new()
  return $r_core_cmd_str(this.lib, c)

proc cmdj*(r: R2PipeApi , c: string):JsonNode =
  return parseJson(cmd(r, c))
