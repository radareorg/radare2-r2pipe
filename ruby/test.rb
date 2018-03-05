#!/usr/bin/env ruby

# author pancake@nopcode.org

require './r2pipe'

puts 'r2pipe ruby api demo'
puts '===================='

begin
  r2p = R2Pipe.new
rescue Exception => e  
  r2p = R2Pipe.new '/bin/ls'
end
  puts r2p.cmd 'pi 5'
  puts r2p.cmd 'pij 1'
  puts r2p.cmdj 'pij 1'
  puts r2p.cmd 'px 64'
  r2p.quit
