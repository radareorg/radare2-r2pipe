using GLib;
using Json;

public errordomain R2PipeError {
	INVALID_TARGET,
	ENVIRONMENT,
	SPAWN,
	IO,
	HTTP,
	JSON,
	CLOSED
}

private abstract class R2Transport : GLib.Object {
	public abstract string cmd (string command) throws R2PipeError;
	public virtual void close () throws R2PipeError {
	}

	protected static string normalize_command (string command) {
		return command.strip ().replace ("\n", ";");
	}
}

private abstract class BufferedTransport : R2Transport {
	protected InputStream input;
	protected OutputStream output;

	protected BufferedTransport (InputStream input, OutputStream output) {
		this.input = input;
		this.output = output;
	}

	public override string cmd (string command) throws R2PipeError {
		write_command (command);
		return read_response ();
	}

	protected void write_command (string command) throws R2PipeError {
		var payload = "%s\n".printf (normalize_command (command));
		uint8[] bytes = payload.data;
		size_t written = 0;
		try {
			output.write_all (bytes[0:payload.length], out written);
			output.flush ();
		} catch (Error e) {
			throw new R2PipeError.IO ("failed to write command: %s".printf (e.message));
		}
	}

	protected string read_response () throws R2PipeError {
		uint8[] buffer = new uint8[4096];
		var builder = new StringBuilder ();

		while (true) {
			ssize_t count;
			try {
				count = input.read (buffer, null);
			} catch (Error e) {
				throw new R2PipeError.IO ("failed to read response: %s".printf (e.message));
			}

			if (count <= 0) {
				throw new R2PipeError.IO ("unexpected end of stream while reading response");
			}

			for (ssize_t i = 0; i < count; i++) {
				if (buffer[i] == 0) {
					return builder.str;
				}
				builder.append_c ((char) buffer[i]);
			}
		}
	}

	protected void close_streams () {
		try {
			output.close ();
		} catch (Error e) {
		}
		try {
			input.close ();
		} catch (Error e) {
		}
	}
}

private class PipeTransport : BufferedTransport {
	public PipeTransport () throws R2PipeError {
		base (
			new UnixInputStream (parse_fd ("R2PIPE_IN"), false),
			new UnixOutputStream (parse_fd ("R2PIPE_OUT"), false)
		);
	}

	private static int parse_fd (string env_name) throws R2PipeError {
		var raw_value = Environment.get_variable (env_name);
		if (raw_value == null || raw_value == "") {
			throw new R2PipeError.ENVIRONMENT ("missing %s".printf (env_name));
		}
		int fd = 0;
		if (!int.try_parse (raw_value, out fd)) {
			throw new R2PipeError.ENVIRONMENT ("invalid %s value: %s".printf (env_name, raw_value));
		}
		return fd;
	}

	public override void close () throws R2PipeError {
		try {
			output.flush ();
		} catch (Error e) {
		}
	}
}

private class SpawnTransport : BufferedTransport {
	public Pid child_pid = 0;
	private bool closed = false;

	public SpawnTransport (string target) throws R2PipeError {
		int stdin_fd = -1;
		int stdout_fd = -1;
		int stderr_fd = -1;
		string[] argv = {
			R2Pipe.find_r2_binary (),
			"-q0",
			target,
			null
		};

		try {
			Process.spawn_async_with_pipes (
				"/",
				argv,
				Environ.get (),
				SpawnFlags.SEARCH_PATH | SpawnFlags.DO_NOT_REAP_CHILD,
				null,
				out child_pid,
				out stdin_fd,
				out stdout_fd,
				out stderr_fd
			);
		} catch (SpawnError e) {
			throw new R2PipeError.SPAWN ("failed to spawn radare2: %s".printf (e.message));
		}

		base (
			new UnixInputStream (stdout_fd, true),
			new UnixOutputStream (stdin_fd, true)
		);

		try {
			read_response ();
		} catch (R2PipeError e) {
			close_streams ();
			reap_child ();
			throw e;
		}
	}

	public override void close () throws R2PipeError {
		if (closed) {
			return;
		}
		closed = true;
		try {
			write_command ("q!");
		} catch (R2PipeError e) {
		}
		close_streams ();
		reap_child ();
	}

	private void reap_child () {
		if (child_pid == 0) {
			return;
		}
		int status = 0;
		Posix.waitpid ((int) child_pid, out status, 0);
		Process.close_pid (child_pid);
		child_pid = 0;
	}
}

private class HttpTransport : R2Transport {
	private string host;
	private uint16 port;
	private string path;

	public HttpTransport (string target) throws R2PipeError {
		Uri uri;
		try {
			uri = Uri.parse (target, UriFlags.NONE);
		} catch (Error e) {
			throw new R2PipeError.INVALID_TARGET ("invalid HTTP URI %s: %s".printf (target, e.message));
		}

		var scheme = uri.get_scheme ();
		if (scheme != "http") {
			throw new R2PipeError.INVALID_TARGET ("unsupported URI scheme %s".printf (scheme ?? "(null)"));
		}

		var parsed_host = uri.get_host ();
		if (parsed_host == null || parsed_host == "") {
			throw new R2PipeError.INVALID_TARGET ("HTTP target requires a host");
		}

		host = parsed_host;
		var parsed_port = uri.get_port ();
		port = (uint16) ((parsed_port > 0) ? parsed_port : 80);
		path = normalize_path (uri.get_path ());
	}

	public override string cmd (string command) throws R2PipeError {
		var client = new SocketClient ();
		SocketConnection connection;
		try {
			connection = client.connect_to_host ("%s:%u".printf (host, port), port, null);
		} catch (Error e) {
			throw new R2PipeError.HTTP ("failed to connect to %s:%u: %s".printf (host, port, e.message));
		}

		try {
			var escaped = Uri.escape_string (normalize_command (command), null, true);
			var request = "GET %s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n".printf (
				path,
				escaped,
				host
			);
			uint8[] request_bytes = request.data;
			size_t written = 0;

			connection.output_stream.write_all (request_bytes[0:request.length], out written);
			connection.output_stream.flush ();

			var input = new DataInputStream (connection.input_stream);
			size_t line_length = 0;
			var status_line = input.read_line_utf8 (out line_length, null);
			if (status_line == null || status_line == "") {
				throw new R2PipeError.HTTP ("empty HTTP response");
			}

			var status_parts = status_line.split (" ");
			if (status_parts.length < 2) {
				throw new R2PipeError.HTTP ("invalid HTTP status line: %s".printf (status_line));
			}

			int status_code = 0;
			if (!int.try_parse (status_parts[1], out status_code)) {
				throw new R2PipeError.HTTP ("invalid HTTP status code: %s".printf (status_parts[1]));
			}

			string? line = null;
			do {
				line = input.read_line_utf8 (out line_length, null);
			} while (line != null && line != "");

			if (status_code < 200 || status_code >= 300) {
				throw new R2PipeError.HTTP ("HTTP request failed with status %d".printf (status_code));
			}

			return read_text_stream (input);
		} catch (R2PipeError e) {
			throw e;
		} catch (Error e) {
			throw new R2PipeError.HTTP ("failed to execute HTTP request: %s".printf (e.message));
		} finally {
			try {
				connection.close (null);
			} catch (Error e) {
			}
		}
	}

	private static string normalize_path (string? raw_path) {
		if (raw_path == null || raw_path == "" || raw_path == "/") {
			return "/cmd/";
		}
		if (raw_path.has_suffix ("/cmd/")) {
			return raw_path;
		}
		if (raw_path.has_suffix ("/cmd")) {
			return "%s/".printf (raw_path);
		}
		if (raw_path.has_suffix ("/")) {
			return "%scmd/".printf (raw_path);
		}
		return "%s/cmd/".printf (raw_path);
	}

	private static string read_text_stream (InputStream input) throws Error {
		uint8[] buffer = new uint8[4096];
		var builder = new StringBuilder ();
		while (true) {
			var count = input.read (buffer, null);
			if (count <= 0) {
				break;
			}
			for (ssize_t i = 0; i < count; i++) {
				builder.append_c ((char) buffer[i]);
			}
		}
		return builder.str;
	}
}

public class R2Pipe : GLib.Object {
	public delegate void Callback (string output);

	public Pid child_pid = 0;
	private R2Transport transport;
	private bool closed = false;
	private Mutex transport_lock;

	public R2Pipe (string? target = null) throws R2PipeError {
		this.transport = build_transport (target);
		if (this.transport is SpawnTransport) {
			this.child_pid = ((SpawnTransport) this.transport).child_pid;
		}
	}

	public R2Pipe.sync (string? target = null) throws R2PipeError {
		this (target);
	}

	public string? cmd (string command, Callback? cb = null) throws R2PipeError {
		if (cb == null) {
			return cmdSync (command);
		}

		new Thread<int> ("r2pipe-cmd", () => {
			string response;
			try {
				response = cmdSync (command);
			} catch (R2PipeError e) {
				response = "";
			}
			Idle.add (() => {
				cb (response);
				return false;
			});
			return 0;
		});
		return null;
	}

	public string cmdSync (string command) throws R2PipeError {
		transport_lock.lock ();
		try {
			ensure_open ();
			return transport.cmd (command);
		} finally {
			transport_lock.unlock ();
		}
	}

	public Json.Node cmdj (string command) throws R2PipeError {
		var parser = new Json.Parser ();
		var response = cmdSync (command);
		if (response == "") {
			response = "{}";
		}
		try {
			parser.load_from_data (response, response.length);
		} catch (Error e) {
			throw new R2PipeError.JSON ("cannot parse JSON response: %s".printf (e.message));
		}
		return parser.get_root ().copy ();
	}

	public void close () throws R2PipeError {
		transport_lock.lock ();
		try {
			if (closed) {
				return;
			}
			transport.close ();
			closed = true;
		} finally {
			transport_lock.unlock ();
		}
	}

	private static R2Transport build_transport (string? target) throws R2PipeError {
		if (target == null || target == "" || target == "#!pipe") {
			return new PipeTransport ();
		}
		if (target.has_prefix ("http://")) {
			return new HttpTransport (target);
		}
		return new SpawnTransport (target);
	}

	private void ensure_open () throws R2PipeError {
		if (closed) {
			throw new R2PipeError.CLOSED ("r2pipe session is closed");
		}
	}

	internal static string find_r2_binary () {
		var from_env = Environment.get_variable ("R2PIPE_R2");
		if (from_env != null && from_env != "") {
			return from_env;
		}
		var radare2_path = Environment.find_program_in_path ("radare2");
		if (radare2_path != null) {
			return radare2_path;
		}
		var r2_path = Environment.find_program_in_path ("r2");
		if (r2_path != null) {
			return r2_path;
		}
		return "radare2";
	}
}
