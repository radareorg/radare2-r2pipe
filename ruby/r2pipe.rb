#!/usr/bin/env ruby

# author pancake@nopcode.org

require 'open3'
require 'json'
require 'shellwords'

# R2Pipe is an easy way to communicate with an r2 core through ruby
class R2Pipe
  def initialize(file = nil)
    @file = file
    if file == nil
      fdIn = ENV['R2PIPE_IN'].to_i
      fdOut = ENV['R2PIPE_OUT'].to_i
      if fdIn < 1 or fdOut < 1
        raise 'Cannot find R2PIPE_IN and R2PIPE_OUT environment variables'
      end
      @read = IO.new(fdIn, 'r')
      @write = IO.new(fdOut, 'w')
      @pid = -1
    else
      exec = "radare2 -q0 #{Shellwords.shellescape file} 2>/dev/null"
      write, read, wait_thr = Open3.popen2(exec)
      @read = read
      @write = write
      @pid = wait_thr.pid
      @read.gets("\0")
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
