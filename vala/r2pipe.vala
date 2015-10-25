public class R2Pipe {

	public Pid child_pid;
	public delegate void Callback (string s);
	IOChannel input;
	IOChannel output;
	IOChannel error;

	bool bootstrap = true;
	bool in_async = true;
	string reply = "";

	private bool process_line (IOChannel channel, IOCondition condition, string stream_name) {
		if (condition == IOCondition.HUP) {
			//stderr.printf ("%s: The fd has been closed.\n", stream_name);
			return false;
		}
		try {
			string line;
			size_t len;
			size_t terpos;
			channel.read_line (out line, out len, out terpos);
			//stdout.printf ("%s: %s", stream_name, line);
			reply += line;
			if (line.length != len) {
				if (bootstrap) {
					reply = "";
					bootstrap = false;
				} else {
					if (nextcb!= null) {
						nextcb (reply);
		//				nextcb = null;
					} else {
						stdout.printf ("Command lost %s\n", reply);
					}
					reply = "";
				}
			}
		} catch (IOChannelError e) {
			stderr.printf ("%s: IOChannelError: %s\n", stream_name, e.message);
			return false;
		} catch (ConvertError e) {
			stderr.printf ("%s: ConvertError: %s\n", stream_name, e.message);
			return false;
		}
		return true;
	}

	private char[] str2arr(string str) {
		char[] char_array = new char[str.length];

		for (int i = 0; i < str.length; i++){
			char_array[i] = (char)str.get_char(str.index_of_nth_char(i));
		}

		return char_array;
	}

	// XXX: use a list or so
	weak Callback? nextcb = null;

	public string? cmd(string cmd, Callback? cb = null) {
		size_t w;
		if (cb == null) {
			return cmdSync(cmd);
		}
		nextcb = cb;
		try {
			input.write_chars (str2arr (cmd + "\n"), out w);
			if (w != cmd.length + 1) {
				stderr.printf ("Error writing to stdin %d\n", (int)w);
			}
			input.flush ();
		} catch (IOChannelError e) {
			stderr.printf ("IOChannelError: %s\n", e.message);
		} catch (ConvertError e) {
			stderr.printf ("ConvertError: %s\n", e.message);
		}
		return null;
	}

	public string? cmdSync(string cmd) {
		size_t w;
		try {
			input.write_chars(str2arr (cmd + "\n"), out w);
			if (w != cmd.length+1) {
				stderr.printf ("Error writing to stdin %d\n", (int)w);
			}
			input.flush ();
			string data = "";
			while(true) {
				char buf[1];
				size_t ret;
				var r = output.read_chars(buf, out ret);
				if (r == IOStatus.ERROR || r== IOStatus.EOF) {
					break;
				}
				if (buf[0] == 0)
					break;
				data += "%c".printf(buf[0]);
			}
			return data;
		} catch (IOChannelError e) {
			stderr.printf ("IOChannelError: %s\n", e.message);
		} catch (ConvertError e) {
			stderr.printf ("ConvertError: %s\n", e.message);
		}
		return null;
	}

	public R2Pipe(string file) {
		R2Pipe.async(file);
	}

	public R2Pipe.async(string file) {
		try {
			string[] spawn_args = {"radare2", "-q0", file};
			string[] spawn_env = Environ.get ();

			int standard_input;
			int standard_output;
			int standard_error;

			Process.spawn_async_with_pipes ("/",
					spawn_args,
					spawn_env,
					SpawnFlags.SEARCH_PATH | SpawnFlags.DO_NOT_REAP_CHILD,
					null,
					out child_pid,
					out standard_input,
					out standard_output,
					out standard_error);
			// stdin:
			input = new IOChannel.unix_new (standard_input);
			// stdout:
			output = new IOChannel.unix_new (standard_output);
			output.add_watch (IOCondition.IN | IOCondition.HUP, (channel, condition) => {
					return process_line (channel, condition, "stdout");
					});
			// stderr:
			error = new IOChannel.unix_new (standard_error);
			error.add_watch (IOCondition.IN | IOCondition.HUP, (channel, condition) => {
					return process_line (channel, condition, "stderr");
					});
		} catch (SpawnError e) {
			stdout.printf ("Error: %s\n", e.message);
		}
	}

	public R2Pipe.sync(string file) {
		in_async = false;
		try {
			string[] spawn_args = {"radare2", "-q0", file};
			string[] spawn_env = Environ.get ();

			int standard_input;
			int standard_output;
			int standard_error;

			Process.spawn_async_with_pipes ("/",
					spawn_args,
					spawn_env,
					SpawnFlags.SEARCH_PATH | SpawnFlags.DO_NOT_REAP_CHILD,
					null,
					out child_pid,
					out standard_input,
					out standard_output,
					out standard_error);
			// stdin:
			input = new IOChannel.unix_new (standard_input);
			// stdout:
			output = new IOChannel.unix_new (standard_output);
			output.add_watch (IOCondition.IN | IOCondition.HUP, (channel, condition) => {
				return process_line (channel, condition, "stdout");
			});
			// stderr:
			error = new IOChannel.unix_new (standard_error);
			error.add_watch (IOCondition.IN | IOCondition.HUP, (channel, condition) => {
				return process_line (channel, condition, "stderr");
			});
			char buf[1];
			size_t ret;
			output.read_chars(buf, out ret);
		} catch (ConvertError e) {
			stdout.printf ("ConvertError: %s\n", e.message);
		} catch (IOChannelError e) {
			stdout.printf ("IOChannelError: %s\n", e.message);
		} catch (SpawnError e) {
			stdout.printf ("SpawnError: %s\n", e.message);
		}
	}
}
