"""Optional HTTP GET/POST imports; no sockets or process execution exposed."""
import struct
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class HttpRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if target.scheme not in ("http", "https"):
            raise ValueError("Only HTTP(S) redirects are supported")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        source = urlsplit(req.full_url)
        if redirected and (source.scheme, source.netloc) != (target.scheme, target.netloc):
            for name in ("Authorization", "Cookie", "Proxy-authorization"):
                redirected.remove_header(name)
        return redirected


class HttpBridge:
    def __init__(self, pipe):
        self.pipe = pipe

    def _request(self, method, url, headers, data, code, length):
        exports = self.pipe._exports
        pointer = 0
        try:
            # Check output pointers before performing any host request.
            with memoryview(exports.memory.buffer) as memory:
                for p in (code, length):
                    if p:
                        struct.pack_into("<i", memory, p & 0xffffffff, 0)
            address = self.pipe._read_string(url & 0xffffffff)
            if urlsplit(address).scheme not in ("http", "https"):
                return 0
            fields = {}
            if headers:
                for line in self.pipe._read_string(headers & 0xffffffff).splitlines():
                    if line:
                        name, value = line.split(":", 1)
                        fields[name.strip()] = value.strip()
            body = self.pipe._read_string(data & 0xffffffff).encode() if data else b""
            request = Request(address, data=body if method == "POST" else None,
                              headers=fields, method=method)
            try:
                response = build_opener(HttpRedirects()).open(request, timeout=30)
            except HTTPError as error:
                response = error  # HTTP errors still have a status and response body.
            with response:
                result = response.read(16 * 1024 * 1024 + 1)
                status = response.code
            if len(result) > 16 * 1024 * 1024:
                return 0
            pointer = exports.malloc(len(result) + 1) & 0xffffffff
            if not pointer:
                return 0
            with memoryview(exports.memory.buffer) as memory:
                memory[pointer:pointer + len(result) + 1] = result + b"\0"
                if code:
                    struct.pack_into("<i", memory, code & 0xffffffff, status)
                if length:
                    struct.pack_into("<i", memory, length & 0xffffffff, len(result))
            return pointer
        except (OSError, ValueError, RuntimeError, OverflowError, struct.error):
            if pointer:
                exports.free(pointer)
            return 0

    def http_get(self, url, headers, code, length):
        return self._request("GET", url, headers, 0, code, length)

    def http_post(self, url, headers, data, code, length):
        return self._request("POST", url, headers, data, code, length)
