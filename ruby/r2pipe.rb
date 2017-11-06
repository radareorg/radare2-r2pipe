#!/usr/bin/env ruby

# author pancake@nopcode.org

require 'pty'
require 'json'
require 'shellwords'

# R2Pipe is an easy way to communicate with an r2 core through ruby
class R2Pipe
  def initialize(file = nil)
    @file = file
    if file == nil
      fdIn = ENV['R2PIPE_IN'].to_i
      fdOut = ENV['R2PIPE_OUT'].to_i
      print "in: ", fdIn, "\nout: ", fdOut, "\n"
      @read = IO.new(fdIn, 'r')
      @write = IO.new(fdOut, 'w')
      @pid = -1
    else
      exec = "r2 -q0 #{Shellwords.shellescape file} 2>/dev/null"
      PTY.spawn(exec) do |read, write, pid|
        @read = read
        @write = write
        @pid = pid
        @read.gets("\0")
      end
    end
  end

  def cmd(str)
    @write.print "#{str}\n"
    @write.flush
    @read.gets("\0")[0..-2]
  end

  def cmdj(str)
    json(cmd(str))
  end

  def quit
    cmd('q!')
    @read.close
    @write.close
    if @pid != -1
      ::Process.wait @pid
    end
  end

  def json(str)
    if str != nil
      JSON.parse str.sub("\n", '').sub("\r", '')
    end
  end
end

puts 'r2pipe ruby api demo'
puts '===================='
# r2p = R2Pipe.new '/bin/ls'
r2p = R2Pipe.new
puts r2p.cmd 'pi 5'
puts r2p.cmd 'pij 1'
puts r2p.cmdj 'pij 1'
puts r2p.cmd 'px 64'
r2p.quit
