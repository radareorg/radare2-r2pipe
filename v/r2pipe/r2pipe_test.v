module r2pipe

import io
import net
import net.http
import net.urllib
import os
import rand
import time
import x.json2

struct TestTransport {
mut:
	commands []string
	output   string
	closes   int
}

fn (mut transport TestTransport) exchange(command string) !string {
	transport.commands << command
	return transport.output
}

fn (mut transport TestTransport) close() {
	transport.closes++
}

fn test_call_and_r2pipe2_wire_options() ! {
	mut transport := &TestTransport{ output: '{"res":"hello\\n","error":false}' }
	mut pipe := open_transport(transport, default_max_response_bytes)!
	assert pipe.call('ij')! == transport.output
	assert transport.commands.last() == "'ij"
	command := '?e 日本語 "%/#?\nsecond line'
	reply := pipe.cmd2(command)!
	assert reply.res as string == 'hello\n'
	assert !reply.error
	sent := transport.commands.last()
	assert sent.starts_with("'{")
	request := json2.decode[map[string]json2.Any](sent[1..])!
	assert request.len == 1
	assert (request['cmd'] or { return error('missing cmd') }) as string == command
	pipe.cmd2j('ij', trim: false)!
	options := json2.decode[map[string]json2.Any](transport.commands.last()[1..])!
	assert (options['trim'] or { return error('missing trim') }) as bool == false
	assert (options['json'] or { return error('missing json') }) as bool == true
	before := transport.commands.len
	pipe.cmd2('bad\x00command') or { assert err.msg().contains('NUL') }
	assert transport.commands.len == before
	pipe.quit()
	pipe.close()
	assert transport.closes == 1
	pipe.cmd('ij') or {
		assert err.msg().contains('closed')
		return
	}
	assert false, 'closed session accepted a command'
}

struct TypedValue {
	offset u64 @[required]
}

fn test_json_handles_uint64_and_rejects_malformed_replies() ! {
	mut transport := &TestTransport{ output: '{"offset":18446744073709551615}' }
	mut pipe := open_transport(transport, default_max_response_bytes)!
	defer { pipe.close() }
	assert pipe.cmd_as[TypedValue]('ij')!.offset == max_u64
	dynamic := pipe.cmdj('ij')!.as_map()
	offset := (dynamic['offset'] or { return error('missing offset') }) as JsonNumber
	assert offset.u64()! == max_u64
	transport.output = '{"res":null,"error":false,"value":18446744073709551615}'
	reply := pipe.cmd2j('ij')!
	assert reply.res is json2.Null
	assert reply.value == max_u64
	transport.output = '{"res":1}'
	pipe.cmd2('ij') or {
		assert err.msg().contains('error')
		transport.output = '{} extra'
		pipe.cmdj('ij') or { return }
		assert false, 'accepted trailing non-JSON data'
		return
	}
	assert false, 'accepted an envelope without the error field'
}

fn check_live_commands(mut pipe R2Pipe) ! {
	assert pipe.cmd('?e hello')! == 'hello\n'
	assert pipe.call('?e hello')! == 'hello\n'
	info := pipe.cmdj('ij')!
	core := info.as_map()['core'] or { return error('missing core') }
	assert (core.as_map()['file'] or { return error('missing file') }) as string == 'malloc://65536'
	assert pipe.cmd2('?e hello')!.res as string == 'hello\n'
	assert pipe.cmd2('?e hello', trim: true)!.res as string == 'hello'
	assert pipe.cmd2j('?e hello', trim: false, json: false)!.res as string == 'hello\n'
	parsed := pipe.cmd2j('pxj 2')!
	assert !parsed.error
	assert parsed.res.as_array().len == 2
	invalid := pipe.cmd2j('?e invalid JSON')!
	assert invalid.error
	assert invalid.code != 0
	assert invalid.logs.any(it.message.contains('not valid JSON'))
	assert pipe.cmd('p8 50000')!.len == 100001
	assert pipe.cmd('?e after large reply')! == 'after large reply\n'
}

fn live_executable() string {
	return os.getenv_opt('R2PIPE_TEST_R2') or { '' }
}

fn test_live_spawn_and_native() ! {
	if executable := os.getenv_opt('R2PIPE_TEST_R2') {
		mut child := open('malloc://65536', spawn: SpawnOptions{ executable: executable })!
		defer { child.close() }
		check_live_commands(mut child)!
		check_concurrent_commands(mut child)!
	}
	if library := os.getenv_opt('R2PIPE_TEST_LIBRARY') {
		mut native := open_native('malloc://65536', library: library)!
		defer { native.close() }
		check_live_commands(mut native)!
		check_concurrent_commands(mut native)!
	}
}

fn test_live_targets_are_literal() ! {
	executable := live_executable()
	library := os.getenv('R2PIPE_TEST_LIBRARY')
	if executable == '' && library == '' {
		return
	}
	directory := os.join_path(os.temp_dir(), 'v-r2pipe-target-${rand.ulid()}')
	os.mkdir(directory)!
	defer { os.rmdir_all(directory) or {} }
	name := '-raw 日本語;name.bin'
	path := os.join_path(directory, name)
	os.write_file(path, 'abcd')!
	if executable != '' {
		mut child := open(name,
			spawn: SpawnOptions{ executable: executable, working_dir: directory }
		)!
		defer { child.close() }
		assert child.cmd('p8 4')! == '61626364\n'
		if mut missing := open(os.join_path(directory, 'missing'),
			spawn: SpawnOptions{ executable: executable }
		) {
			missing.close()
			assert false, 'opened a nonexistent file via subprocess'
		} else {
			assert err.msg().contains('startup')
		}
	}
	if library != '' {
		mut native := open_native(path, library: library)!
		defer { native.close() }
		assert native.cmd('p8 4')! == '61626364\n'
	}
}

fn test_live_response_limit() ! {
	executable := live_executable()
	if executable == '' {
		return
	}
	mut child := open('malloc://65536',
		max_response_bytes: 32
		spawn:              SpawnOptions{
			executable:      executable
			command_timeout: 2 * time.second
		}
	)!
	defer { child.close() }
	child.cmd('p8 40000') or {
		assert err.msg().contains('exceeds 32 bytes')
		child.cmd('?e hello') or {
			assert err.msg().contains('closed')
			return
		}
		assert false, 'stream was reused after discarding a partial frame'
		return
	}
	assert false, 'oversized reply succeeded'
}

fn echo_live(mut pipe R2Pipe, worker int) ! {
	for i in 0 .. 20 {
		message := 'worker-${worker}-command-${i}'
		assert pipe.cmd('?e ${message}')! == '${message}\n'
	}
}

fn check_concurrent_commands(mut pipe R2Pipe) ! {
	first := spawn echo_live(mut pipe, 1)
	second := spawn echo_live(mut pipe, 2)
	first.wait()!
	second.wait()!
}

fn test_live_http_get_and_post() ! {
	if os.getenv('R2PIPE_TEST_HTTP') != '1' {
		return
	}
	executable := live_executable()
	if executable == '' {
		return error('R2PIPE_TEST_HTTP requires R2PIPE_TEST_R2')
	}
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	port := listener.addr()!.port()!
	listener.close()!
	mut child := open('malloc://65536', spawn: SpawnOptions{ executable: executable })!
	defer { child.close() }
	child.cmd('e http.bind=localhost; e http.port=${port}; =h&')!
	endpoint := 'http://127.0.0.1:${port}'
	for attempt in 0 .. 100 {
		mut connection := net.dial_tcp('127.0.0.1:${port}') or {
			if attempt == 99 {
				return error('radare2 HTTP server failed to start: ${err}')
			}
			time.sleep(20 * time.millisecond)
			continue
		}
		connection.close()!
		break
	}
	for method in [HttpMethod.get, .post] {
		mut pipe := open('${endpoint}/cmd/', http: HttpOptions{ method: method })!
		defer { pipe.close() }
		check_live_commands(mut pipe)!
		message := '日本語 /+%?#&='
		assert pipe.cmd('?e "${message}"')! == '${message}\n'
		assert pipe.cmd2('?e "${message}"')!.res as string == '${message}\n'
	}
}

fn http_fixture(mut listener net.TcpListener, response string) !http.Request {
	mut connection := listener.accept()!
	defer { connection.close() or {} }
	connection.set_read_timeout(2 * time.second)
	mut reader := io.new_buffered_reader(reader: connection)
	request := http.parse_request(mut reader)!
	connection.write_string(response)!
	return request
}

fn test_http_request_encoding_and_no_redirect() ! {
	if os.getenv('R2PIPE_TEST_HTTP') != '1' {
		return
	}
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	defer { listener.close() or {} }
	listener.set_accept_timeout(3 * time.second)
	endpoint := 'http://${listener.addr()!.str()}/prefix%2Fproxy?token=one'
	header := http.new_header(key: .authorization, value: 'Bearer example')
	mut pipe := open(endpoint, http: HttpOptions{ header: header })!
	defer { pipe.close() }
	command := '?e 日本語 /+%?#&='
	worker := spawn http_fixture(mut listener, 'HTTP/1.1 302 Found\r\nLocation: /other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
	if _ := pipe.cmd(command) {
		assert false, 'accepted an HTTP redirect'
	} else {
		assert err.code() == 302
	}
	request := worker.wait()!
	assert request.method == .get
	encoded_path := request.url.all_before('?')
	assert encoded_path.starts_with('/prefix%2Fproxy/cmd/')
	assert urllib.path_unescape(encoded_path.all_after('/cmd/'))! == command
	assert request.url.all_after('?') == 'token=one'
	assert request.header.get(.authorization) or { '' } == 'Bearer example'
}

fn test_http_rejects_truncation_and_limits_body() ! {
	if os.getenv('R2PIPE_TEST_HTTP') != '1' {
		return
	}
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	defer { listener.close() or {} }
	listener.set_accept_timeout(3 * time.second)
	mut pipe := open('http://${listener.addr()!.str()}', max_response_bytes: 8)!
	defer { pipe.close() }
	for response in [
		'HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nshort',
		'HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\n123456789',
	] {
		worker := spawn http_fixture(mut listener, response)
		if _ := pipe.cmd('ij') {
			assert false, 'accepted an incomplete or oversized HTTP response'
		}
		worker.wait()!
	}
	worker := spawn http_fixture(mut listener, 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')
	assert pipe.cmd('ij')! == '{}'
	worker.wait()!
}

fn test_spawn_framing_errors_and_timeouts() ! {
	$if !windows {
		directory := os.join_path(os.temp_dir(), 'v-r2pipe-fixture-${rand.ulid()}')
		os.mkdir(directory)!
		defer { os.rmdir_all(directory) or {} }
		fixture := os.join_path(directory, 'child')
		for scenario, script in {
			'startup':             'read -r line'
			'response terminator': 'printf "\\000"; read -r line; printf partial'
			'timed out':           'printf "\\000"; read -r line; read -r line'
		} {
			os.write_file(fixture, '#!/bin/sh\n${script}\n')!
			os.chmod(fixture, 0o700)!
			options := SpawnOptions{
				executable:      fixture
				flags:           []
				startup_timeout: 200 * time.millisecond
				command_timeout: 200 * time.millisecond
			}
			if mut pipe := open('-', spawn: options) {
				defer { pipe.close() }
				if _ := pipe.cmd('ij') {
					assert false, 'accepted a broken stream'
				} else {
					assert scenario != 'startup' && err.msg().contains(scenario)
				}
			} else {
				assert scenario == 'startup' && err.msg().contains('timed out')
			}
		}
		os.write_file(fixture, '#!/bin/sh\nprintf "\\000"\nread -r line\nprintf "%s\\000" "$R2PIPE_V_FIXTURE:$line"\n')!
		mut pipe := open('-',
			spawn: SpawnOptions{
				executable:  fixture
				environment: {
					'R2PIPE_V_FIXTURE': 'custom environment'
				}
			}
		)!
		defer { pipe.close() }
		if _ := pipe.cmd('x'.repeat(4095)) {
			assert false, 'accepted a command that radare2 could split'
		} else {
			assert err.msg().contains('4094 bytes')
		}
		assert pipe.cmd('one\r\ntwo')! == 'custom environment:one;two'
	}
}

fn test_native_open_failures_and_options() ! {
	library := os.getenv('R2PIPE_TEST_LIBRARY')
	if library == '' {
		return
	}
	if mut missing := open_native('', library: library + '.missing') {
		missing.close()
		assert false, 'loaded a missing library'
	} else {
		assert err.msg().contains('cannot load')
	}
	if mut missing := open_native(os.join_path(os.temp_dir(), rand.ulid()), library: library) {
		missing.close()
		assert false, 'opened a missing target'
	} else {
		assert err.msg().contains('could not open')
	}
	mut native := open('ccall://malloc://512',
		native: NativeOptions{
			library:     library
			writable:    true
			before_open: ['e io.va=false']
			after_open:  ['wx 1234']
			load_binary: false
		}
	)!
	defer { native.close() }
	assert native.cmd('p8 2')! == '1234\n'
}

fn test_closed_pipe_write_returns_epipe() ! {
	$if !windows {
		mut descriptors := [2]i32{}
		assert C.pipe(&descriptors[0]) == 0
		os.fd_close(descriptors[0])
		defer { os.fd_close(descriptors[1]) }
		byte := u8(`x`)
		assert C.v_r2p_write(descriptors[1], &byte, 1, false) == -C.EPIPE
	}
}
