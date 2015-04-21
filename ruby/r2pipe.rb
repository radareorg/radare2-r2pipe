#!/usr/bin/ruby
# author pancake@nopcode.org

require 'pty'
require 'json'
require 'shellwords'

# R2Pipe is an easy way to communicate with an r2 core through ruby
class R2Pipe
  def initialize(file)
    @file = file
    exec = "r2 -q0 #{Shellwords.shellescape file} 2>/dev/null"
    PTY.spawn(exec) do |read, write, pid|
      @read = read
      @write = write
      @pid = pid
      @read.gets("\0")
    end
  end

  def cmd(str)
    @write.print "#{str}\n"
    @read.gets("\0")[0..-2]
  end

  def quit
    cmd('q!')
    ::Process.wait @pid
  end

  def json(str)
    JSON.parse str.sub("\n", '').sub("\r", '')
  end
end

puts 'r2pipe ruby api demo'
puts '===================='
r2p = R2Pipe.new '/bin/ls'
puts r2p.cmd 'pi 5'
puts r2p.cmd 'pij 1'
puts r2p.json(r2p.cmd 'pij 1')
puts r2p.cmd 'px 64'
r2p.quit
