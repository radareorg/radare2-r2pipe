module r2pipe

import os
import strconv
import strings
import time

#flag -I @VMODROOT/r2pipe
#flag linux -D_GNU_SOURCE
#include "stream_posix.h"

fn C.v_r2p_spawn(&char, &&char, &&char, &char, bool, &i32) i32
fn C.v_r2p_dup(i32, bool) i32
fn C.v_r2p_pipe_buf(i32) i32
fn C.v_r2p_poll(i32, bool, i32) i32
fn C.v_r2p_read(i32, &u8, i32) i32
fn C.v_r2p_write(i32, &u8, i32, bool) i32
fn C.v_r2p_reap(i32, bool) bool
fn C.memchr(voidptr, i32, uint) voidptr

struct StreamTransport {
mut:
	read_fd           i32 = -1
	write_fd          i32 = -1
	child             i32
	command_timeout   time.Duration
	shutdown_timeout  time.Duration
	limit             int
	atomic_write_max  int
	max_command_bytes int
	buffer            [16384]u8
	start             int
	end               int
}

fn new_spawn(target string, options SpawnOptions, limit int) !Transport {
	if options.startup_timeout <= 0 || options.command_timeout <= 0 || options.shutdown_timeout < 0 {
		return error('r2pipe: invalid subprocess timeouts')
	}
	if options.max_command_bytes <= 0 {
		return error('r2pipe: max_command_bytes must be positive')
	}
	if options.executable.contains_u8(0) || options.working_dir.contains_u8(0) {
		return error('r2pipe: executable or working directory contains NUL')
	}
	executable := os.find_abs_path_of_executable(options.executable) or {
		return error('r2pipe: cannot find executable ${options.executable}: ${err}')
	}
	// Radare2 treats '--' as a target in its own right. Make a dash-prefixed
	// filename relative explicitly so it cannot be interpreted as a flag.
	filename := if target == '' {
		'--'
	} else if target.starts_with('-') && target !in ['-', '--'] {
		'./${target}'
	} else {
		target
	}
	mut argv := [&char(executable.str)]
	for flag in options.flags {
		if flag.contains_u8(0) {
			return error('r2pipe: subprocess flag contains NUL')
		}
		argv << &char(flag.str)
	}
	mode := '-q0'
	argv << &char(mode.str)
	argv << &char(filename.str)
	argv << &char(unsafe { nil })
	mut env := []&char{}
	mut entries := []string{}
	if options.environment.len > 0 || os.getenv('R2PIPE_IN') != '' || os.getenv('R2PIPE_OUT') != '' {
		mut child_env := os.environ()
		for key, value in options.environment {
			if key == '' || key.contains('=') || key.contains_u8(0) || value.contains_u8(0) {
				return error('r2pipe: invalid subprocess environment entry')
			}
			child_env[key] = value
		}
		child_env.delete('R2PIPE_IN')
		child_env.delete('R2PIPE_OUT')
		for key, value in child_env {
			entries << '${key}=${value}'
		}
		for entry in entries {
			env << &char(entry.str)
		}
		env << &char(unsafe { nil })
	}
	mut child := i32(0)
	fd := C.v_r2p_spawn(&char(executable.str), argv.data, if env.len > 0 {
		env.data
	} else {
		unsafe { nil }
	},
		&char(options.working_dir.str), options.inherit_stderr, &child)
	if fd < 0 {
		return stream_error('spawn', fd)
	}
	mut stream := &StreamTransport{
		read_fd:           fd
		write_fd:          fd
		child:             child
		command_timeout:   options.command_timeout
		shutdown_timeout:  options.shutdown_timeout
		limit:             limit
		max_command_bytes: options.max_command_bytes
	}
	stream.read_frame(deadline_after(options.startup_timeout)) or {
		stream.disconnect(false)
		return error('r2pipe: subprocess startup: ${err}')
	}
	return stream
}

fn new_inherited(timeout time.Duration, limit int) !Transport {
	if timeout <= 0 {
		return error('r2pipe: command timeout must be positive')
	}
	read_fd := duplicate_env_fd('R2PIPE_IN', false)!
	write_fd := duplicate_env_fd('R2PIPE_OUT', true) or {
		os.fd_close(read_fd)
		return err
	}
	return &StreamTransport{
		read_fd:          read_fd
		write_fd:         write_fd
		command_timeout:  timeout
		limit:            limit
		atomic_write_max: C.v_r2p_pipe_buf(write_fd)
	}
}

fn duplicate_env_fd(name string, writable bool) !i32 {
	value := os.getenv(name)
	if value == '' || !value.bytes().all(it >= `0` && it <= `9`) {
		return error('r2pipe: ${name} must contain an open file descriptor')
	}
	fd := strconv.parse_uint(value, 10, 31)!
	duplicate := C.v_r2p_dup(i32(fd), writable)
	if duplicate < 0 {
		return stream_error('duplicate ${name}', duplicate)
	}
	return duplicate
}

fn (mut stream StreamTransport) exchange(command string) !string {
	if stream.read_fd < 0 {
		return error('r2pipe: stream is closed')
	}
	line := if command.contains_any('\r\n') {
		command.replace_each(['\r\n', ';', '\r', ';', '\n', ';'])
	} else {
		command
	}
	if stream.max_command_bytes > 0 && line.len > stream.max_command_bytes {
		return error('r2pipe: command exceeds ${stream.max_command_bytes} bytes')
	}
	payload := if stream.child > 0 || line == '' { line + '\n' } else { line }
	// The inherited radare2 host reads each command with a single read().
	if stream.atomic_write_max > 0 && payload.len > stream.atomic_write_max {
		return error('r2pipe: inherited command exceeds ${stream.atomic_write_max} bytes')
	}
	deadline := deadline_after(stream.command_timeout)
	return stream.transact(payload, deadline) or {
		// A failure after sending bytes leaves the response boundary unknown.
		stream.disconnect(false)
		return err
	}
}

fn deadline_after(timeout time.Duration) u64 {
	return time.sys_mono_now() + u64(timeout)
}

fn stream_error(operation string, code i32) IError {
	return error_with_code('r2pipe: ${operation}: ${os.posix_get_error_msg(-code)}', -code)
}

fn wait_ready(fd i32, write_ready bool, deadline u64) ! {
	for {
		now := time.sys_mono_now()
		if now >= deadline {
			return error('r2pipe: stream timed out')
		}
		ms := (deadline - now + u64(time.millisecond) - 1) / u64(time.millisecond)
		status := C.v_r2p_poll(fd, write_ready, i32(if ms > u64(max_i32) {
			u64(max_i32)
		} else {
			ms
		}))
		if status > 0 {
			return
		}
		if status < 0 && status != -C.EINTR {
			return stream_error('poll', status)
		}
	}
}

fn (mut stream StreamTransport) transact(payload string, deadline u64) !string {
	if stream.child == 0 {
		wait_ready(stream.write_fd, true, deadline)!
	}
	mut sent := 0
	for sent < payload.len {
		if time.sys_mono_now() >= deadline {
			return error('r2pipe: stream timed out')
		}
		left := payload.len - sent
		chunk := i32(if left > 65536 { 65536 } else { left })
		count := unsafe { C.v_r2p_write(stream.write_fd, payload.str + sent, chunk, stream.child > 0) }
		if count == -C.EAGAIN {
			wait_ready(stream.write_fd, true, deadline)!
			continue
		}
		if count == -C.EINTR {
			continue
		}
		if count < 0 {
			return stream_error('write command', count)
		}
		if count == 0 || (stream.atomic_write_max > 0 && count != chunk) {
			return error('r2pipe: incomplete command write')
		}
		sent += count
	}
	return stream.read_frame(deadline)
}

fn (mut stream StreamTransport) fill(deadline u64) ! {
	if stream.child == 0 {
		wait_ready(stream.read_fd, false, deadline)!
	}
	for {
		if time.sys_mono_now() >= deadline {
			return error('r2pipe: stream timed out')
		}
		count := C.v_r2p_read(stream.read_fd, &stream.buffer[0], stream.buffer.len)
		if count == -C.EAGAIN {
			wait_ready(stream.read_fd, false, deadline)!
			continue
		}
		if count == -C.EINTR {
			continue
		}
		if count < 0 {
			return stream_error('read response', count)
		}
		if count == 0 {
			return error('r2pipe: stream closed before response terminator')
		}
		stream.start = 0
		stream.end = count
		return
	}
}

fn (mut stream StreamTransport) read_frame(deadline u64) !string {
	mut output := strings.Builder{}
	defer { unsafe { output.free() } }
	for {
		if stream.start == stream.end {
			stream.fill(deadline)!
		}
		ptr := &stream.buffer[stream.start]
		available := stream.end - stream.start
		terminator := C.memchr(ptr, 0, uint(available))
		count := if isnil(terminator) { available } else { int(uint(terminator) - uint(ptr)) }
		if stream.limit > 0 && count > stream.limit - output.len {
			return error('r2pipe: response exceeds ${stream.limit} bytes')
		}
		stream.start += count
		if !isnil(terminator) {
			stream.start++
			if output.len == 0 {
				return unsafe { tos(ptr, count).clone() }
			}
			unsafe { output.write_ptr(ptr, count) }
			return output.str()
		}
		if output.len == 0 {
			output = strings.new_builder(2 * stream.buffer.len)
		}
		unsafe { output.write_ptr(ptr, count) }
	}
}

fn (mut stream StreamTransport) disconnect(graceful bool) {
	if stream.read_fd < 0 {
		return
	}
	os.fd_close(stream.read_fd)
	if stream.write_fd != stream.read_fd {
		os.fd_close(stream.write_fd)
	}
	stream.read_fd = -1
	stream.write_fd = -1
	if stream.child > 0 {
		deadline := deadline_after(if graceful {
			stream.shutdown_timeout
		} else {
			time.Duration(0)
		})
		for !C.v_r2p_reap(stream.child, false) {
			if time.sys_mono_now() >= deadline {
				C.kill(stream.child, C.SIGKILL)
				C.v_r2p_reap(stream.child, true)
				break
			}
			time.sleep(2 * time.millisecond)
		}
		stream.child = 0
	}
}

fn (mut stream StreamTransport) close() {
	stream.disconnect(true)
}
