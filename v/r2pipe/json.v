module r2pipe

import strconv
import x.json2

// JsonNumber preserves the original spelling of a JSON number, including full-width addresses.
pub type JsonNumber = string

pub fn (mut number JsonNumber) from_json_number(raw string) ! {
	number = JsonNumber(raw)
}

pub fn (number JsonNumber) u64() !u64 {
	return strconv.parse_uint(string(number), 10, 64)
}

pub fn (number JsonNumber) i64() !i64 {
	return strconv.atoi64(string(number))
}

pub fn (number JsonNumber) f64() !f64 {
	return strconv.atof64(string(number), allow_extra_chars: false)
}

// JsonValue represents a JSON value without converting numbers to floating point.
pub type JsonValue = []JsonValue | JsonNumber | bool | json2.Null | map[string]JsonValue | string

pub fn (value JsonValue) as_map() map[string]JsonValue {
	return if value is map[string]JsonValue { value } else { map[string]JsonValue{} }
}

pub fn (value JsonValue) as_array() []JsonValue {
	return if value is []JsonValue { value } else { []JsonValue{} }
}

// cmdj decodes the JSON response as a dynamic V value.
pub fn (mut pipe R2Pipe) cmdj(command string) !JsonValue {
	return pipe.cmd_as[JsonValue](command)
}

// cmd_as decodes the JSON response into T with strict type checking.
pub fn (mut pipe R2Pipe) cmd_as[T](command string) !T {
	output := pipe.cmd(command)!
	return json2.decode[T](output, strict: true)
}

// CallOptions controls the optional fields on an r2pipe2 request.
@[params]
pub struct CallOptions {
pub:
	trim ?bool
	json ?bool
}

struct Request2 {
	cmd  string
	trim ?bool
	json ?bool
}

pub struct LogEntry {
pub:
	type    string
	origin  string
	message string
}

// Reply is the r2pipe2 envelope. Radare2 command failures are reported in error,
// code and logs. Missing result fields have the same representation as JSON null.
pub struct Reply {
pub:
	res   JsonValue = json2.null
	error bool @[required]
	value u64
	code  int
	logs  []LogEntry
}

// cmd2 submits an r2pipe2 request and decodes the reply envelope.
pub fn (mut pipe R2Pipe) cmd2(command string, options CallOptions) !Reply {
	if command.contains_u8(0) {
		return error('r2pipe: command contains NUL')
	}
	request := json2.encode(Request2{
		cmd:  command
		trim: options.trim
		json: options.json
	})
	output := pipe.call(request)!
	return json2.decode[Reply](output, strict: true)
}

// cmd2j defaults both trim and json to true. Set either option to false to override it.
pub fn (mut pipe R2Pipe) cmd2j(command string, options CallOptions) !Reply {
	return pipe.cmd2(command, trim: options.trim or { true }, json: options.json or { true })
}
