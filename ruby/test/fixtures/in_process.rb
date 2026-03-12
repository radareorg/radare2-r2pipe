#!/usr/bin/env ruby

$LOAD_PATH.unshift(File.expand_path('../..', __dir__))
require 'r2pipe'

r2 = R2Pipe.new('#!pipe')
STDOUT.write(r2.cmd('?e ruby-pipe-ok'))
STDOUT.write("\n")
r2.quit
