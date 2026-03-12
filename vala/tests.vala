using GLib;
using Json;

private const string TEST_FILE = "/bin/ls";
private string? pipe_probe_executable;

private class HttpFixture : GLib.Object {
	public Pid pid = 0;
	public int stderr_fd = -1;
}

private void fail_test (string message) {
	stderr.printf ("%s\n", message);
	assert_not_reached ();
}

private string find_r2_binary () {
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

private string read_fd_text (int fd) {
	if (fd < 0) {
		return "";
	}
	var input = new UnixInputStream (fd, true);
	uint8[] buffer = new uint8[4096];
	var builder = new StringBuilder ();

	while (true) {
		try {
			var count = input.read (buffer, null);
			if (count <= 0) {
				break;
			}
			for (ssize_t i = 0; i < count; i++) {
				builder.append_c ((char) buffer[i]);
			}
		} catch (Error e) {
			break;
		}
	}
	return builder.str;
}

private uint16 free_port () {
	try {
		var listener = new SocketListener ();
		uint16 port = listener.add_any_inet_port (null);
		listener.close ();
		return port;
	} catch (Error e) {
		fail_test ("failed to reserve an HTTP test port: %s".printf (e.message));
		return 0;
	}
}

private HttpFixture start_http_r2 (uint16 port) {
	var fixture = new HttpFixture ();
	string[] argv = {
		find_r2_binary (),
		"-q0",
		"-e", "http.bind=127.0.0.1",
		"-e", "http.port=%u".printf (port),
		"-c", "=H",
		TEST_FILE,
		null
	};
	int stdin_fd = -1;
	int stdout_fd = -1;
	int stderr_fd = -1;

	try {
		Process.spawn_async_with_pipes (
			"/",
			argv,
			Environ.get (),
			SpawnFlags.SEARCH_PATH | SpawnFlags.DO_NOT_REAP_CHILD,
			null,
			out fixture.pid,
			out stdin_fd,
			out stdout_fd,
			out stderr_fd
		);
	} catch (Error e) {
		fail_test ("failed to start r2 HTTP server: %s".printf (e.message));
	}

	if (stdin_fd >= 0) {
		Posix.close (stdin_fd);
	}
	if (stdout_fd >= 0) {
		Posix.close (stdout_fd);
	}
	fixture.stderr_fd = stderr_fd;
	return fixture;
}

private void wait_for_http (uint16 port) {
	for (int attempt = 0; attempt < 150; attempt++) {
		try {
			var client = new SocketClient ();
			var connection = client.connect_to_host ("127.0.0.1:%u".printf (port), port, null);
			connection.close (null);
			return;
		} catch (Error e) {
			Thread.usleep (100000);
		}
	}
	fail_test ("timed out waiting for r2 HTTP server on port %u".printf (port));
}

private void stop_http_r2 (HttpFixture fixture) {
	if (fixture.pid == 0) {
		return;
	}
	Posix.kill ((int) fixture.pid, Posix.Signal.TERM);
	int status = 0;
	Posix.waitpid ((int) fixture.pid, out status, 0);
	Process.close_pid (fixture.pid);
	fixture.pid = 0;
	if (fixture.stderr_fd >= 0) {
		Posix.close (fixture.stderr_fd);
		fixture.stderr_fd = -1;
	}
}

private void assert_json_has_member (Json.Node node, string member) {
	assert (node.get_node_type () == Json.NodeType.OBJECT);
	var obj = node.get_object ();
	assert (obj != null);
	assert (obj.has_member (member));
}

private void test_spawn_transport () {
	R2Pipe r2;
	try {
		r2 = new R2Pipe.sync (TEST_FILE);
	} catch (Error e) {
		fail_test ("spawn transport failed to initialize: %s".printf (e.message));
		return;
	}

	try {
		var version = r2.cmdSync ("?V");
		assert (version.contains ("radare2"));
		assert_json_has_member (r2.cmdj ("ij"), "bin");
		assert (r2.cmdSync ("?e vala-spawn-ok").strip () == "vala-spawn-ok");
	} catch (Error e) {
		fail_test ("spawn transport test failed: %s".printf (e.message));
	} finally {
		try {
			r2.close ();
		} catch (Error e) {
		}
	}
}

private void test_json_failure () {
	try {
		var r2 = new R2Pipe.sync (TEST_FILE);
		try {
			r2.cmdj ("?e not-json");
			fail_test ("cmdj should fail on invalid JSON");
		} catch (R2PipeError.JSON e) {
		} finally {
			try {
				r2.close ();
			} catch (Error e) {
			}
		}
	} catch (Error e) {
		fail_test ("JSON failure test could not initialize r2pipe: %s".printf (e.message));
	}
}

private void test_http_transport () {
	var port = free_port ();
	var fixture = start_http_r2 (port);
	try {
		wait_for_http (port);
		var r2 = new R2Pipe.sync ("http://127.0.0.1:%u".printf (port));
		try {
			var version = r2.cmdSync ("?V");
			assert (version.contains ("radare2"));
			assert_json_has_member (r2.cmdj ("ij"), "core");
		} finally {
			try {
				r2.close ();
			} catch (Error e) {
			}
		}
	} catch (Error e) {
		var stderr_text = read_fd_text (fixture.stderr_fd);
		fixture.stderr_fd = -1;
		fail_test ("HTTP transport test failed: %s\n%s".printf (e.message, stderr_text));
	} finally {
		stop_http_r2 (fixture);
	}
}

private void test_pipe_transport (string executable_path) {
	string[] argv = {
		find_r2_binary (),
		"-q0",
		"-c", "#!pipe %s --pipe-probe".printf (executable_path),
		TEST_FILE,
		null
	};
	string standard_output;
	string standard_error;
	int status = 0;

	try {
		Process.spawn_sync (
			"/",
			argv,
			Environ.get (),
			SpawnFlags.SEARCH_PATH,
			null,
			out standard_output,
			out standard_error,
			out status
		);
	} catch (Error e) {
		fail_test ("failed to run env-pipe probe: %s".printf (e.message));
		return;
	}

	if (status != 0) {
		fail_test ("env-pipe probe failed with status %d\n%s".printf (status, standard_error));
	}
	if (!standard_output.contains ("vala-pipe-ok")) {
		fail_test ("env-pipe probe did not emit success marker\nstdout:%s\nstderr:%s".printf (
			standard_output,
			standard_error
		));
	}
}

private void test_env_pipe_transport () {
	assert (pipe_probe_executable != null);
	test_pipe_transport (pipe_probe_executable);
}

private int run_pipe_probe () {
	try {
		var r2 = new R2Pipe.sync ();
		assert (r2.cmdSync ("?e vala-pipe-ok").strip () == "vala-pipe-ok");
		assert_json_has_member (r2.cmdj ("ij"), "core");
		stdout.printf ("vala-pipe-ok\n");
		return 0;
	} catch (Error e) {
		stderr.printf ("%s\n", e.message);
		return 1;
	}
}

private string resolve_executable_path (string arg0) {
	if (GLib.Path.is_absolute (arg0)) {
		return arg0;
	}
	return GLib.Path.build_filename (Environment.get_current_dir (), arg0);
}

int main (string[] args) {
	if (args.length > 1 && args[1] == "--pipe-probe") {
		return run_pipe_probe ();
	}

	Test.init (ref args);
	pipe_probe_executable = resolve_executable_path (args[0]);

	Test.add_func ("/vala/spawn", test_spawn_transport);
	Test.add_func ("/vala/json_failure", test_json_failure);
	Test.add_func ("/vala/http", test_http_transport);
	Test.add_func ("/vala/env_pipe", test_env_pipe_transport);

	return Test.run ();
}
