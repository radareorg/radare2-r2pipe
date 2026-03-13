namespace eval ::r2pipe {
    namespace export open
    variable version 0.1.0

    proc configure {chan} {
        fconfigure $chan -translation binary -encoding iso8859-1 -buffering none -blocking 1 -eofchar {}
        return $chan
    }

    proc read0 {chan} {
        set out ""
        while 1 {
            set ch [read $chan 1]
            if {$ch eq ""} {
                error "unexpected end of stream while reading response"
            }
            if {$ch eq "\x00"} {
                return $out
            }
            append out $ch
        }
    }

    proc open {{target ""} {r2bin ""}} {
        return [R2Pipe new $target $r2bin]
    }

    oo::class create R2Pipe {
        variable mode pids readchan writechan

        constructor {{target ""} {r2bin ""}} {
            if {$target eq "" || $target eq "#!pipe"} {
                set mode pipe
                set bridge {eval "cat <&$R2PIPE_IN" & eval "exec cat >&$R2PIPE_OUT"}
                set chan [::r2pipe::configure [::open "|/bin/sh -c [list $bridge]" r+]]
                set readchan $chan
                set writechan $chan
                set pids [pid $chan]
                return
            }
            set mode spawn
            if {$r2bin eq ""} {
                set r2bin [expr {[info exists ::env(R2PIPE_R2)] ? $::env(R2PIPE_R2) : "r2"}]
            }
            set chan [::r2pipe::configure [::open |[list $r2bin -q0 -- $target] r+]]
            set readchan $chan
            set writechan $chan
            set pids [pid $chan]
            ::r2pipe::read0 $readchan
        }

        method cmd {command} {
            puts -nonewline $writechan "[string trimright $command \n]\n"
            flush $writechan
            return [::r2pipe::read0 $readchan]
        }

        method cmdj {command} {
            package require json
            return [::json::json2dict [my cmd $command]]
        }

        method close {} {
            if {![info exists readchan]} {
                return
            }
            if {$mode eq "spawn"} {
                catch {
                    puts -nonewline $writechan "q!\n"
                    flush $writechan
                }
            } else {
                catch {exec kill {*}$pids}
            }
            catch {::close $readchan}
            unset -nocomplain mode pids readchan writechan
        }

        destructor {
            my close
        }
    }

    namespace ensemble create
}

package provide r2pipe $::r2pipe::version
