#!/usr/bin/env ruby

require 'json'
require 'minitest/autorun'
require 'open3'
require 'tmpdir'
require 'timeout'

$LOAD_PATH.unshift(File.expand_path('..', __dir__))
require 'r2pipe'

class R2PipeTest < Minitest::Test
  TEST_FILE = '/bin/ls'

  def test_spawn_transport_executes_commands
    r2 = R2Pipe.new(TEST_FILE)
    version = r2.cmd('?V')
    info = r2.cmdj('ij')

    assert_includes(version, 'radare2')
    assert_kind_of(Hash, info)
    assert(info.key?('bin'))
  ensure
    r2&.quit
  end

  def test_named_file_options_are_supported
    r2 = R2Pipe.new(file: TEST_FILE)

    assert_equal('hello', r2.cmd('?e hello').strip)
  ensure
    r2&.quit
  end

  def test_cmdj_raises_for_invalid_json
    r2 = R2Pipe.new(TEST_FILE)

    assert_raises(R2Pipe::TransportError) do
      r2.cmdj('?e not-json')
    end
  ensure
    r2&.quit
  end

  def test_pipe_transport_works_inside_r2
    fixture = File.expand_path('fixtures/in_process.rb', __dir__)
    stdout, stderr, status = Open3.capture3(r2_bin, '-q0', '-c', "#!pipe ruby #{fixture}", TEST_FILE)

    assert(status.success?, "r2 pipe run failed: #{stderr}")
    assert_includes(stdout, 'ruby-pipe-ok')
  end

  def test_http_transport_against_r2_webserver
    port = free_port
    process, error_log = start_http_r2(port)
    wait_for_http(port, process, error_log)

    r2 = R2Pipe.new("http://127.0.0.1:#{port}")
    version = r2.cmd('?V')
    info = r2.cmdj('ij')

    assert_includes(version, 'radare2')
    assert_kind_of(Hash, info)
    assert(info.key?('core'))
  ensure
    r2&.quit
    stop_process(process)
  end

  def test_tcp_transport_against_mock_server
    server, thread, port = start_tcp_server('ruby-tcp-ok')
    r2 = R2Pipe.new("tcp://127.0.0.1:#{port}")

    assert_equal('ruby-tcp-ok', r2.cmd('?V'))
  ensure
    r2&.quit
    server&.close
    thread&.join
  end

  private

  def r2_bin
    ENV['R2PIPE_R2'] || 'r2'
  end

  def free_port
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    server.close
    port
  rescue Errno::EPERM => e
    skip("sandbox blocked loopback bind/connect: #{e.message}")
  end

  def start_http_r2(port)
    error_log = File.join(Dir.tmpdir, "r2pipe-rb-http-#{port}.log")
    process = Process.spawn(
      r2_bin,
      '-q0',
      '-e', 'http.bind=127.0.0.1',
      '-e', "http.port=#{port}",
      '-c', '=H',
      TEST_FILE,
      out: File::NULL,
      err: error_log
    )
    [process, error_log]
  end

  def wait_for_http(port, process, error_log)
    Timeout.timeout(15) do
      loop do
        if Process.waitpid(process, Process::WNOHANG)
          stderr = File.exist?(error_log) ? File.read(error_log) : ''
          skip("r2 HTTP server exited before listening: #{stderr}")
        end

        begin
          socket = TCPSocket.new('127.0.0.1', port)
          socket.close
          return
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
          sleep 0.1
        rescue Errno::EPERM => e
          skip("sandbox blocked loopback bind/connect: #{e.message}")
        end
      end
    end
  rescue Timeout::Error
    stderr = File.exist?(error_log) ? File.read(error_log) : ''
    flunk("timed out waiting for r2 HTTP server on #{port}: #{stderr}")
  end

  def stop_process(process)
    return if process.nil?

    Process.kill('TERM', process)
    Process.wait(process)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end

  def start_tcp_server(response)
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    thread = Thread.new do
      client = server.accept
      client.read
      client.write(response)
      client.close
    end
    [server, thread, port]
  rescue Errno::EPERM => e
    skip("sandbox blocked loopback bind/connect: #{e.message}")
  end
end
