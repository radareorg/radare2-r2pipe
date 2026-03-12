#!/usr/bin/env ruby

# author pancake@nopcode.org

require 'json'
require 'net/http'
require 'open3'
require 'socket'
require 'uri'

# R2Pipe is an easy way to communicate with an r2 core through ruby.
class R2Pipe
  class Error < StandardError; end
  class TransportError < Error; end
  class ClosedError < Error; end

  DEFAULT_R2_BINARIES = %w[radare2 r2].freeze

  def self.open(*args, **options)
    new(*args, **options)
  end

  attr_reader :target, :type

  def initialize(target = nil, **options)
    config = normalize_arguments(target, options)
    @type = config[:type]
    @target = config[:target]
    @transport = build_transport(config)
    @closed = false
  end

  def cmd(command)
    raise ClosedError, 'r2pipe session is closed' if closed?

    @transport.cmd(command.to_s)
  end

  def cmdj(command)
    json(cmd(command))
  end

  def json(str)
    return nil if str.nil? || str.empty?

    JSON.parse(str)
  rescue JSON::ParserError => e
    raise TransportError, "cannot parse JSON response: #{e.message}"
  end

  def quit
    return if @closed

    @transport.quit
  ensure
    @closed = true
  end

  alias close quit

  def closed?
    @closed
  end

  private

  def normalize_arguments(target, options)
    opts = symbolize_keys(options.dup)
    opts[:file] = opts[:filename] if opts.key?(:filename) && !opts.key?(:file)
    opts[:filename] = opts[:file] if opts.key?(:file) && !opts.key?(:filename)
    opts[:http] = opts[:url] if opts.key?(:url) && !opts.key?(:http)
    opts[:url] = opts[:http] if opts.key?(:http) && !opts.key?(:url)
    opts[:analyze] = opts[:analyse] if opts.key?(:analyse) && !opts.key?(:analyze)
    opts[:writable] = opts[:writeable] if opts.key?(:writeable) && !opts.key?(:writable)

    target = opts[:file] if target.nil? && opts.key?(:file)
    target = opts[:http] if target.nil? && opts.key?(:http)
    target = opts[:tcp] if target.nil? && opts.key?(:tcp)

    inferred_type =
      if target.nil? || target == '' || target == '#!pipe'
        :pipe
      elsif url?(target, 'http://', 'https://')
        :http
      elsif url?(target, 'tcp://')
        :tcp
      else
        :spawn
      end

    {
      type: inferred_type,
      target: target,
      debug: truthy?(opts[:debug]),
      writable: truthy?(opts[:writable]),
      analyze: truthy?(opts[:analyze]),
      flags: Array(opts[:flags]).compact.map(&:to_s),
      r2bin: opts[:r2bin] || ENV['R2PIPE_R2']
    }
  end

  def build_transport(config)
    case config[:type]
    when :pipe
      PipeTransport.new
    when :spawn
      SpawnTransport.new(config)
    when :http
      HttpTransport.new(config[:target])
    when :tcp
      TcpTransport.new(config[:target])
    else
      raise TransportError, "unsupported transport #{config[:type].inspect}"
    end
  end

  def symbolize_keys(hash)
    hash.each_with_object({}) do |(key, value), out|
      out[key.respond_to?(:to_sym) ? key.to_sym : key] = value
    end
  end

  def truthy?(value)
    value == true || value.to_s == '1'
  end

  def url?(value, *prefixes)
    return false unless value.is_a?(String)

    prefixes.any? { |prefix| value.start_with?(prefix) }
  end

  class BaseTransport
    private

    def encode_command(command)
      URI::DEFAULT_PARSER.escape(command.to_s, /[^A-Za-z0-9\-\._~]/)
    end
  end

  class BufferedTransport < BaseTransport
    def initialize(read_io, write_io)
      @read_io = read_io
      @write_io = write_io
      @pending = ''.b
    end

    def cmd(command)
      write_command(command)
      read_response
    end

    def quit
      @read_io.close unless @read_io.closed?
      @write_io.close unless @write_io.closed?
    end

    private

    def write_command(command)
      @write_io.write("#{command}\n")
      @write_io.flush
    rescue IOError, SystemCallError => e
      raise TransportError, "failed to write command: #{e.message}"
    end

    def read_response
      output = ''.b

      loop do
        null_index = @pending.index("\x00")
        if null_index
          output << @pending.byteslice(0, null_index)
          @pending = @pending.byteslice(null_index + 1..-1).to_s.b
          return output.force_encoding(Encoding::UTF_8)
        end

        output << @pending
        @pending = ''.b

        chunk = @read_io.readpartial(4096)
        @pending << chunk
      end
    rescue EOFError
      raise TransportError, 'unexpected end of stream while reading response'
    rescue IOError, SystemCallError => e
      raise TransportError, "failed to read response: #{e.message}"
    end
  end

  class PipeTransport < BufferedTransport
    def initialize
      super(dup_fd('R2PIPE_IN', 'rb'), dup_fd('R2PIPE_OUT', 'wb'))
    end

    private

    def dup_fd(env_name, mode)
      raw_fd = Integer(ENV.fetch(env_name))
      original = IO.for_fd(raw_fd, mode, autoclose: false)
      copy = original.dup
      copy.binmode
      copy.sync = true
      copy
    rescue KeyError, ArgumentError
      raise TransportError, 'cannot find valid R2PIPE_IN and R2PIPE_OUT environment variables'
    end
  end

  class SpawnTransport < BufferedTransport
    def initialize(config)
      @config = config
      @wait_thr = nil
      super(*spawn_r2)
      read_response
      cmd('aaa') if config[:analyze]
    end

    def quit
      return if @wait_thr.nil?

      begin
        write_command('q!')
      rescue TransportError
        nil
      end

      super
      @wait_thr.value
      @wait_thr = nil
    end

    private

    def spawn_r2
      stdin, stdout, wait_thr = Open3.popen2(*command_argv, err: File::NULL)
      stdin.binmode
      stdout.binmode
      stdin.sync = true
      @wait_thr = wait_thr
      [stdout, stdin]
    rescue Errno::ENOENT
      raise TransportError, 'cannot find radare2 in PATH'
    end

    def command_argv
      [
        radare2_binary,
        *@config[:flags],
        ('-d' if @config[:debug]),
        ('-w' if @config[:writable]),
        '-q0',
        @config[:target]
      ].compact
    end

    def radare2_binary
      return @config[:r2bin] unless @config[:r2bin].nil? || @config[:r2bin].empty?

      DEFAULT_R2_BINARIES.find { |candidate| system('which', candidate, out: File::NULL, err: File::NULL) } ||
        DEFAULT_R2_BINARIES.first
    end
  end

  class HttpTransport < BaseTransport
    def initialize(target)
      @uri = normalize_uri(target)
    end

    def cmd(command)
      uri = @uri.dup
      uri.path = "#{uri.path}#{encode_command(command)}"

      response = Net::HTTP.start(
        uri.host,
        uri.port,
        use_ssl: uri.scheme == 'https'
      ) do |http|
        http.request(Net::HTTP::Get.new(uri))
      end

      unless response.is_a?(Net::HTTPSuccess)
        raise TransportError, "HTTP request failed with status #{response.code}"
      end

      response.body.to_s
    rescue SocketError, IOError, SystemCallError, Timeout::Error => e
      raise TransportError, "HTTP request failed: #{e.message}"
    end

    def quit
      nil
    end

    private

    def normalize_uri(target)
      uri = URI.parse(target)
      raise TransportError, "unsupported URI scheme #{uri.scheme.inspect}" unless %w[http https].include?(uri.scheme)

      normalized_path =
        if uri.path.nil? || uri.path.empty? || uri.path == '/'
          '/cmd/'
        elsif uri.path.end_with?('/cmd/')
          uri.path
        elsif uri.path.end_with?('/cmd')
          "#{uri.path}/"
        elsif uri.path.end_with?('/')
          "#{uri.path}cmd/"
        else
          "#{uri.path}/cmd/"
        end

      uri.path = normalized_path
      uri.query = nil
      uri.fragment = nil
      uri
    rescue URI::InvalidURIError => e
      raise TransportError, "invalid HTTP URI #{target.inspect}: #{e.message}"
    end
  end

  class TcpTransport < BaseTransport
    def initialize(target)
      @host, @port = parse_target(target)
    end

    def cmd(command)
      socket = TCPSocket.new(@host, @port)
      socket.write("#{command}\n")
      socket.close_write
      socket.read.to_s
    rescue SocketError, IOError, SystemCallError => e
      raise TransportError, "TCP request failed: #{e.message}"
    ensure
      socket.close if socket && !socket.closed?
    end

    def quit
      nil
    end

    private

    def parse_target(target)
      uri = URI.parse(target)
      raise TransportError, "unsupported URI scheme #{uri.scheme.inspect}" unless uri.scheme == 'tcp'
      raise TransportError, 'TCP URI must include a host and port' if uri.host.nil? || uri.port.nil?

      [uri.host, uri.port]
    rescue URI::InvalidURIError => e
      raise TransportError, "invalid TCP URI #{target.inspect}: #{e.message}"
    end
  end
end
