
source [file join [file dirname [info script]] r2pipe.tcl]
puts start
flush stdout
set r2 [r2pipe::open]
puts opened
flush stdout
puts [string trim [$r2 cmd {?e hi}]]
flush stdout
puts closing
flush stdout
$r2 close
puts done
flush stdout
