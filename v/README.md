# r2pipe for V

```v
import r2pipe

fn main() {
	mut r2 := r2pipe.open('malloc://512') or { panic(err) }
	defer { r2.close() }
	print(r2.cmd('?e Hello from V') or { panic(err) })
	println(r2.cmdj('ij') or { panic(err) })
}
```

Use a recent V 0.5.2 build with `json2` and `net.http`. Run the example with
`cd v && v run test.v`. From another project, add this checkout's `v` directory
to the module search path.

```sh
v -path '/path/to/radare2-r2pipe/v|@vlib|@vmodules' run main.v
```

## Connections

| Target or option | Connection |
| --- | --- |
| A file, an IO URI such as `malloc://512`, or `-` | Start `radare2 -q0`. Radare2 interprets `-` as a scratch buffer and `--` as an empty session. |
| `http://host:port` or `https://host:port` | Connect to a radare2 HTTP server. `/cmd` and `/cmd/` suffixes are accepted. |
| `''` or `#!pipe` | Attach to the current `#!pipe` host via `R2PIPE_IN` and `R2PIPE_OUT`. |
| `ccall://` followed by a target, or `open_native(target, ...)` | Load `libr_core` dynamically and create an `RCore` in this process. An empty target creates a core without opening a file. |

`open` also takes `backend: .spawn`, `.http`, `.inherited`, or `.native` to
select the transport explicitly. Subprocesses and inherited pipes use POSIX
APIs. The native backend needs an installed shared `libr_core`. Build-time
radare2 headers and link flags are unnecessary.

### Subprocess options

```v
mut r2 := r2pipe.open('firmware.bin', spawn: r2pipe.SpawnOptions{
	executable: '/usr/local/bin/radare2'
	flags: ['-N', '-a', 'arm', '-b', '32']
	working_dir: '/path/to/inputs'
})!
defer { r2.close() }
```

The executable, flags, and target are passed as separate arguments. `flags`
defaults to `['-N']`. `SpawnOptions` also supports environment overrides,
stderr inheritance, and startup, command, and shutdown timeouts. The default
command limit is 4094 bytes after newline normalization, including any `call`
prefix or r2pipe2 envelope. This matches radare2's `-q0` line buffer. Inherited
pipes use the host pipe's atomic write limit. Use one session per inherited host
connection. The stream transports turn literal line endings into `;` so each
call sends one frame.

### HTTP options

```v
mut r2 := r2pipe.open('http://127.0.0.1:9090', http: r2pipe.HttpOptions{
	method: .post
})!
defer { r2.close() }
```

GET sends the command as one encoded path segment. POST sends plain text to
`/cmd` and works with servers that enable that endpoint. `HttpOptions` supports
custom headers, a proxy, read and write timeouts, and TLS trust and client
certificate files. Supply credentials with an `Authorization` header. HTTPS
validates certificates. Requests are sent once with redirects disabled so a
command with side effects cannot be replayed by the client.

### Native options

```v
mut r2 := r2pipe.open_native('firmware.bin', library: '/usr/local/lib/libr_core.dylib',
	before_open: ['e asm.arch=arm'], after_open: ['e asm.bits=32'])!
defer { r2.close() }
```

`NativeOptions` also controls write access, binary loading and load and base
addresses. Target paths are passed directly to the native file API. The core
is created, used and freed on one worker thread. Native calls run in the
application process and wait for libr to return.

## Commands and errors

- `cmd(command)` returns text with its original trailing newline, if present.
- `cmdj(command)` returns a dynamic `JsonValue`. Cast strings with `as string`, use
  `as_map()` and `as_array()` for containers, and convert `JsonNumber` with
  `u64()`, `i64()`, or `f64()`. Numeric text is preserved even for integers
  above JavaScript's safe integer range.
- `cmd_as[Type](command)` decodes JSON into a V type with strict type checking.
- `call(command)` sends radare2's single-quote command prefix.
- `cmd2(command, trim: true)` returns a parsed r2pipe2 `Reply`. `cmd2j` defaults
  `trim` and `json` to `true`. Set either option to `false` to override it.
  Read `reply.res`, `reply.error`, `reply.code`, `reply.value`, and `reply.logs`.
  Radare2 command failures appear in the envelope. Transport and decoding
  failures are V errors. Use a radare2 version with r2pipe2 support.

Commands are serialized per session. `close()` and `quit()` release resources
and can be called repeatedly. If a stream times out or loses framing, it closes
to preserve request and reply ordering. `max_response_bytes` defaults to 64 MiB
and can be overridden on `open`. Set it to 0 to disable the client limit.
Use `open_transport` to apply the same command API to an application-provided
transport.

## Tests

Run `make -C v test` from the repository root. `make -C v integration` also
requires a local radare2 executable, its shared library, and loopback networking.
Override `R2` or `R2_LIB` when testing a different build.
