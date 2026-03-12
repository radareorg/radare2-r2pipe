# r2pipe for Ruby

Interact with radare2 from Ruby using one of the supported transports:

- Spawn a local `r2 -q0` process
- Reuse `R2PIPE_IN` / `R2PIPE_OUT` from `#!pipe`
- Connect to an HTTP r2 web server
- Connect to a TCP r2 server

## Requirements

- Ruby with the standard library
- `radare2` in `PATH` for local spawn and `#!pipe` use

## Usage

### Spawn a local radare2 process

```ruby
require_relative 'r2pipe'

r2 = R2Pipe.new('/bin/ls')
puts r2.cmd('?V')
puts r2.cmd('pi 5')
p r2.cmdj('ij')
r2.quit
```

### Use named options

```ruby
require_relative 'r2pipe'

r2 = R2Pipe.new(
  file: '/bin/ls',
  analyze: true,
  writable: false
)

puts r2.cmd('afl')
r2.close
```

The constructor also accepts `analyse` and `writeable` for compatibility with other bindings.

### Use from inside radare2 with `#!pipe`

```ruby
require_relative 'r2pipe'

r2 = R2Pipe.new('#!pipe')
puts r2.cmd('?e hello-from-r2')
r2.quit
```

Example:

```sh
r2 -q0 -c '#!pipe ruby myscript.rb' /bin/ls
```

### Connect over HTTP

Start radare2 with the web server enabled:

```sh
r2 -q0 -e http.bind=127.0.0.1 -e http.port=9090 -c '=H' /bin/ls
```

Then connect from Ruby:

```ruby
require_relative 'r2pipe'

r2 = R2Pipe.new('http://127.0.0.1:9090')
puts r2.cmd('pi 5')
p r2.cmdj('ij')
r2.quit
```

### Connect over TCP

```ruby
require_relative 'r2pipe'

r2 = R2Pipe.new('tcp://127.0.0.1:9080')
puts r2.cmd('?V')
r2.quit
```

## API

### `R2Pipe.new(target = nil, **options)`

Creates a new session.

- `nil`, `''`, or `#!pipe`: use `R2PIPE_IN` / `R2PIPE_OUT`
- `'/path/to/file'`: spawn `radare2 -q0 /path/to/file`
- `'http://host:port'`: use the HTTP transport
- `'tcp://host:port'`: use the TCP transport

Options:

- `file` / `filename`
- `http` / `url`
- `tcp`
- `analyze` / `analyse`
- `writable` / `writeable`
- `debug`
- `flags`
- `r2bin`

### `cmd(command)`

Runs an r2 command and returns the string response.

### `cmdj(command)`

Runs an r2 command and parses the response as JSON.

### `json(string)`

Parses a JSON string using the same error handling as `cmdj`.

### `quit` / `close`

Closes the current session.

## Tests

Run the Ruby suite with:

```sh
make -C ruby test
```
