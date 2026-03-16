#!/usr/bin/env tclsh

source [file join [file dirname [info script]] r2pipe.tcl]

proc assert_eq {got want} {
    if {$got ne $want} {
        error "expected '$want' but got '$got'"
    }
}

proc test_spawn {} {
    set r2 [r2pipe::open /bin/ls]
    assert_eq [string trim [$r2 cmd "?e tcl-spawn-ok"]] tcl-spawn-ok
    set info [$r2 cmdj ij]
    if {[catch {dict size $info}]} {
        error "ij output did not parse as a dict"
    }
    $r2 close
}

proc test_pipe {} {
    set r2 [r2pipe::open]
    assert_eq [string trim [$r2 cmd "?e tcl-pipe-ok"]] tcl-pipe-ok
    $r2 close
}

if {[info exists ::env(R2PIPE_IN)] && [info exists ::env(R2PIPE_OUT)]} {
    set mode pipe
} elseif {[info exists argc] && $argc > 0} {
    set mode [lindex $argv 0]
} else {
    set mode spawn
}

if {$mode eq "pipe"} {
    test_pipe
} else {
    test_spawn
}
puts [string cat "mode: " $mode "  OK"]
