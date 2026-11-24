module r2pipe

import net.http
import sync
import time

// Backend selects how a session connects to radare2.
pub enum Backend {
	auto
	spawn
	http
	native
	inherited
}

pub const default_max_response_bytes = 64 * 1024 * 1024

pub struct SpawnOptions {
pub:
	executable        string   = 'radare2'
	max_command_bytes int      = 4094 // Payload limit for radare2's -q0 input buffer, excluding the newline.
	flags             []string = ['-N']
	working_dir       string
	environment       map[string]string // Overrides inherited environment variables.
	inherit_stderr    bool
	startup_timeout   time.Duration = 10 * time.second
	command_timeout   time.Duration = 30 * time.second
	shutdown_timeout  time.Duration = 500 * time.millisecond
}

pub enum HttpMethod {
	get
	post
}

pub struct HttpOptions {
pub:
	method        HttpMethod
	header        http.Header
	read_timeout  time.Duration   = 30 * time.second
	write_timeout time.Duration   = 30 * time.second
	proxy         &http.HttpProxy = unsafe { nil }
	verify        string // Custom TLS CA file.
	cert          string // TLS client certificate file.
	cert_key      string // TLS client key file.
}

pub struct NativeOptions {
pub:
	library        string   // Full path or loader name. Defaults to libr_core for this OS.
	before_open    []string // Commands executed before opening the target.
	after_open     []string // Commands executed after opening the target.
	writable       bool
	load_binary    bool = true
	load_address   u64  = max_u64
	global_symbols bool // Make libr symbols available to other dynamically loaded libraries.
	base_address   u64 = max_u64
}

@[params]
pub struct Options {
pub:
	backend            Backend
	spawn              SpawnOptions
	http               HttpOptions
	native             NativeOptions
	max_response_bytes int = default_max_response_bytes // Zero disables the response size limit.
}

// Transport is an optional extension point for custom command transports.
// R2Pipe serializes calls and invokes close once.
pub interface Transport {
mut:
	exchange(command string) !string
	close()
}

@[heap]
pub struct R2Pipe {
mut:
	mutex     &sync.Mutex = sync.new_mutex()
	transport Transport
	closed    bool = true
	limit     int
}

// open selects a transport from the target. Recognized prefixes are http://,
// https:// and ccall://. An empty string or '#!pipe' selects inherited pipes.
pub fn open(target string, options Options) !&R2Pipe {
	if options.max_response_bytes < 0 {
		return error('r2pipe: max_response_bytes must be nonnegative')
	}
	if target.contains_u8(0) {
		return error('r2pipe: target contains NUL')
	}
	backend := if options.backend != .auto {
		options.backend
	} else if target.starts_with('http://') || target.starts_with('https://') {
		Backend.http
	} else if target.starts_with('ccall://') {
		Backend.native
	} else if target == '' || target == '#!pipe' {
		Backend.inherited
	} else {
		Backend.spawn
	}
	resolved := if backend == .native { target.trim_string_left('ccall://') } else { target }
	transport := connect(backend, resolved, options)!
	return open_transport(transport, options.max_response_bytes)
}

fn connect(backend Backend, target string, options Options) !Transport {
	match backend {
		.spawn { return new_spawn(target, options.spawn, options.max_response_bytes) }
		.inherited {
			return new_inherited(options.spawn.command_timeout, options.max_response_bytes)
		}
		.http { return new_http(target, options.http, options.max_response_bytes) }
		.native { return new_native(target, options.native, options.max_response_bytes) }
		.auto { return error('r2pipe: unresolved backend') }
	}
}

// open_native creates an in-process RCore using a dynamically loaded libr_core.
pub fn open_native(target string, options NativeOptions) !&R2Pipe {
	return open(target, backend: .native, native: options)
}

// open_transport wraps an application-provided transport with the command API.
pub fn open_transport(transport Transport, max_response_bytes int) !&R2Pipe {
	if max_response_bytes < 0 {
		return error('r2pipe: max_response_bytes must be nonnegative')
	}
	return &R2Pipe{
		transport: transport
		closed:    false
		limit:     max_response_bytes
	}
}

// cmd runs a command and returns the output, including any trailing newline.
pub fn (mut pipe R2Pipe) cmd(command string) !string {
	if command.contains_u8(0) {
		return error('r2pipe: command contains NUL')
	}
	pipe.mutex.lock()
	defer { pipe.mutex.unlock() }
	if pipe.closed {
		return error('r2pipe: session is closed')
	}
	output := pipe.transport.exchange(command)!
	if pipe.limit > 0 && output.len > pipe.limit {
		return error('r2pipe: response exceeds ${pipe.limit} bytes')
	}
	return output
}

// call runs a command using radare2's single-quote call prefix.
pub fn (mut pipe R2Pipe) call(command string) !string {
	return pipe.cmd("'" + command)
}

// close releases this session. Closing twice is safe.
pub fn (mut pipe R2Pipe) close() {
	pipe.mutex.lock()
	defer { pipe.mutex.unlock() }
	if !pipe.closed {
		pipe.closed = true
		pipe.transport.close()
	}
}

// quit is an alias for close.
pub fn (mut pipe R2Pipe) quit() {
	pipe.close()
}
