"""Optional synchronous r2net host imports. Handles are private to one instance."""

import select
import socket
import ssl


class SocketBridge:
    NAMES = {"connect", "listen", "accept", "read", "write", "close", "ready", "block_time", "peer"}

    def __init__(self, owner):
        self.owner = owner
        self.sockets = {}
        self.next_handle = 1

    def bind(self, name):
        operation = getattr(self, name)
        def call(*args):
            try:
                return operation(*args)
            except (OSError, ValueError, KeyError, OverflowError):
                return -1
        return call

    def _add(self, sock):
        handle = self.next_handle
        self.next_handle += 1
        self.sockets[handle] = sock
        return handle

    def _string(self, pointer):
        return self.owner._read_string(pointer & 0xffffffff)

    def _buffer(self, pointer, length):
        pointer &= 0xffffffff
        if length < 0 or pointer + length > self.owner._exports.memory.data_size:
            raise ValueError("Socket buffer outside WASM memory")
        return pointer

    def connect(self, host, port, proto, tls, timeout):
        if proto not in (6, 17) or (tls and proto != 6) or timeout < 0:
            return -1
        host, port = self._string(host), self._string(port)
        kind = socket.SOCK_STREAM if proto == 6 else socket.SOCK_DGRAM
        for family, socktype, protocol, _, address in socket.getaddrinfo(host, port, type=kind):
            sock = socket.socket(family, socktype, protocol)
            try:
                sock.settimeout(timeout or None)
                sock.connect(address)
                if tls:
                    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                return self._add(sock)
            except (OSError, ValueError):
                sock.close()
            except BaseException:
                sock.close()
                raise
        return -1

    def listen(self, port, local, proto):
        # UDP has no accept API; connected UDP is supported by connect().
        if proto not in (0, 6):
            return -1
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1" if local else "0.0.0.0", int(self._string(port))))
            sock.listen()
            return self._add(sock)
        except BaseException:
            sock.close()
            raise

    def accept(self, handle):
        client, _ = self.sockets[handle].accept()
        return self._add(client)

    def read(self, handle, pointer, length):
        pointer = self._buffer(pointer, length)
        data = self.sockets[handle].recv(min(length, 65536))
        with memoryview(self.owner._exports.memory.buffer) as memory:
            memory[pointer:pointer + len(data)] = data
        return len(data)

    def write(self, handle, pointer, length):
        pointer = self._buffer(pointer, length)
        with memoryview(self.owner._exports.memory.buffer) as memory:
            data = bytes(memory[pointer:pointer + length])
        sock = self.sockets[handle]
        if sock.type == socket.SOCK_STREAM:
            sock.sendall(data)
            return len(data)
        return sock.send(data)

    def close(self, handle):
        self.sockets.pop(handle).close()
        return 0

    def ready(self, handle, sec, usec):
        sock = self.sockets[handle]
        if isinstance(sock, ssl.SSLSocket) and sock.pending():
            return 1
        return int(bool(select.select([sock], [], [], max(sec, 0) + max(usec, 0) / 1e6)[0]))

    def block_time(self, handle, block, sec, usec):
        timeout = max(sec, 0) + max(usec, 0) / 1e6
        self.sockets[handle].settimeout((timeout or None) if block else 0)
        return 0

    def peer(self, handle, pointer, length):
        pointer = self._buffer(pointer, length)
        host, port = self.sockets[handle].getpeername()[:2]
        data = f"{host}:{port}".encode() + b"\0"
        if len(data) > length:
            return -1
        with memoryview(self.owner._exports.memory.buffer) as memory:
            memory[pointer:pointer + len(data)] = data
        return len(data) - 1

    def close_all(self):
        for sock in self.sockets.values():
            sock.close()
        self.sockets.clear()
