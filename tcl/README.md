# r2pipe for TCL

Minimal `r2pipe` binding for TCL with two transports:

- in-process `#!pipe` via `R2PIPE_IN` / `R2PIPE_OUT`
- local spawn via `r2 -q0`

## Requirements

- Tcl 8.6+ or Tcl 9
- `radare2` in `PATH` for spawn/tests
- `tcllib` if you want `cmdj`

## Usage

```tcl
source r2pipe.tcl

set r2 [r2pipe::open /bin/ls]
puts [$r2 cmd "?V"]
puts [dict keys [$r2 cmdj ij]]
$r2 close
```

Use from inside radare2:

```sh
r2 -q0 -c '#!pipe tclsh script.tcl' /bin/ls
```

```tcl
source r2pipe.tcl

set r2 [r2pipe::open]
puts [$r2 cmd "?e hello-from-tcl"]
$r2 close
```

## API

- `r2pipe::open ?target? ?r2bin?`
- `$r2 cmd <command>`
- `$r2 cmdj <command>`
- `$r2 close`

An empty target, or `#!pipe`, uses the in-process transport. Any other target is
opened by spawning `r2 -q0 -- <target>`.

## Tests

```sh
make -C tcl test
```
