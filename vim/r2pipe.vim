


let s:host = "localhost"
let s:port = "9090"

function! r2pipe#endpoint(host, port)
  let s:host = a:host
  let s:port = a:port 
endfunction

function! r2pipe#cmd(c)
  " TODO: use r2p instead of curl when it supports http endpoints
  let res = system("curl -s http://".s:host.":".s:port."/cmd/" . a:c)
  put=res
endfunction

" :r2("pd 10") <--- shortest form
cnoreabbrev r2 call r2pipe#cmd
