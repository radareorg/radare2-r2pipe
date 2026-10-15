import asyncio
import json
import os
import subprocess
import sys
import threading
import unittest
from unittest.mock import Mock, patch

from r2pipe.native import RCore, r2lib
from r2pipe.open_async import open as async_open


def run_async(coroutine):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coroutine)
    finally:
        loop.close()


class TestAsyncNative(unittest.TestCase):
    def setUp(self):
        self.cores = []
        self.entered = threading.Event()
        self.release = threading.Event()
        cores, entered, release = self.cores, self.entered, self.release

        class NativeCore:
            def __init__(self):
                self.worker = threading.current_thread()
                self.commands = []
                self.frees = 0
                cores.append(self)

            def cmd_str(self, cmd):
                if threading.current_thread() is not self.worker:
                    raise AssertionError("Native core moved between threads")
                self.commands.append(cmd)
                if cmd.startswith("o "):
                    return ""
                if cmd == "blocked":
                    entered.set()
                    if not release.wait(5):
                        raise TimeoutError("Native command was not released")
                if cmd == "fail":
                    raise ValueError("Native command failed")
                if cmd == "bytes":
                    return b"native bytes\n"
                if cmd == "ij":
                    return '{"core":{"file":"malloc://32"}}'
                if cmd.startswith("'"):
                    request = json.loads(cmd[1:])
                    value = self.cmd_str(request["cmd"])
                    if request.get("json"):
                        value = json.loads(value)
                    return json.dumps({"res": value, "error": False})
                return cmd + "\n"

            def free(self):
                if threading.current_thread() is not self.worker:
                    raise AssertionError("Native core freed on a different thread")
                self.frees += 1

        self.native = patch("r2pipe.open_base.RCore", NativeCore)
        self.available = patch("r2pipe.open_base.has_native", True)
        self.native.start()
        self.available.start()
        self.addCleanup(self.native.stop)
        self.addCleanup(self.available.stop)
        self.addCleanup(self.release.set)

    async def wait_until_entered(self):
        async def wait():
            while not self.entered.is_set():
                await asyncio.sleep(0)
        await asyncio.wait_for(wait(), 2)

    def test_blocking_commands_wrappers_callbacks_and_cleanup(self):
        caller = threading.current_thread()
        with async_open("ccall://malloc://32") as r2:
            self.assertEqual(r2.cmd("text"), "text\n")
            self.assertEqual(r2.cmd("bytes"), "native bytes\n")
            self.assertEqual(r2.cmdj("ij")["core"]["file"], "malloc://32")
            self.assertEqual(r2.cmdJ("ij").core.file, "malloc://32")
            self.assertEqual(r2.cmd2j("ij").res.core.file, "malloc://32")
            callbacks = []
            self.assertEqual(r2.cmd2("text", callback=callbacks.append).res, "text\n")
            self.assertEqual(json.loads(callbacks[0])["res"], "text\n")
            r2.use_cache = True
            self.assertEqual(r2.cmd("cached"), "cached\n")
            self.assertEqual(r2.cmd("cached"), "cached\n")
        self.assertEqual(len(self.cores), 1)
        core = self.cores[0]
        self.assertIsNot(core.worker, caller)
        self.assertEqual(core.commands.count("o malloc://32"), 1)
        self.assertEqual(core.commands.count("cached"), 1)
        self.assertEqual(core.frees, 1)
        self.assertFalse(core.worker.is_alive())
        self.assertFalse(hasattr(r2, "native"))
        r2.close()
        self.assertEqual(core.frees, 1)

    def test_await_concurrent_commands_and_recovery_after_error(self):
        async def main():
            async with async_open("ccall://malloc://32") as r2:
                results = await asyncio.gather(*[
                    r2.cmd("command-%d" % index) for index in range(30)
                ])
                self.assertEqual(results, ["command-%d\n" % index for index in range(30)])
                self.assertEqual((await r2.cmd2j("ij")).res.core.file, "malloc://32")
                with self.assertRaisesRegex(ValueError, "Native command failed"):
                    await r2.cmd("fail")
                self.assertEqual(await r2.cmd("after"), "after\n")
            self.assertFalse(r2._loop.is_closed())
        run_async(main())
        self.assertEqual(len(self.cores), 1)
        self.assertEqual(self.cores[0].frees, 1)

    def test_cancel_active_command_and_close_wait_for_native_worker(self):
        async def main():
            r2 = async_open("ccall://malloc://32")
            active = r2._loop.create_task(r2.cmd("blocked"))
            try:
                await self.wait_until_entered()
                # Reaching this point proves the C-call adapter leaves the loop free.
                active.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await active
                queued = r2._loop.create_task(r2.cmd("must not run"))
                await asyncio.sleep(0)
                closing = r2._loop.create_task(r2.close())
                await asyncio.sleep(0)
                self.assertFalse(closing.done())
                self.assertEqual(self.cores[0].frees, 0)
                self.release.set()
                with self.assertRaisesRegex(RuntimeError, "closed"):
                    await queued
                await closing
                await r2.quit()
            finally:
                self.release.set()
                await r2.close()
            self.assertNotIn("must not run", self.cores[0].commands)
            self.assertEqual(self.cores[0].frees, 1)
            self.assertFalse(self.cores[0].worker.is_alive())
        run_async(main())

    def test_unavailable_library_releases_worker(self):
        with patch("r2pipe.open_base.has_native", False):
            with async_open("ccall://malloc://32") as r2:
                with self.assertRaises(ImportError):
                    r2.cmd("text")
        self.assertEqual(self.cores, [])

    def test_close_unused_connection_does_not_create_worker(self):
        with patch("r2pipe.open_async.ThreadPoolExecutor") as executor:
            with async_open("ccall://malloc://32"):
                pass
            executor.assert_not_called()


class TestNativeCoreCleanup(unittest.TestCase):
    def test_free_uses_core_pointer_once_and_closed_commands_raise(self):
        core = RCore.__new__(RCore)
        core._o = 1234
        wrapped, raw = Mock(), Mock()
        core._r_core_free = (wrapped, raw)
        core.free()
        core.free()
        core.__del__()
        raw.assert_called_once_with(1234)
        wrapped.assert_not_called()
        self.assertIsNone(core._o)
        with self.assertRaisesRegex(RuntimeError, "closed"):
            core.cmd_str("text")

    def test_missing_library_raises_cleanly(self):
        with patch("r2pipe.native.r2lib", return_value=None):
            with self.assertRaises(ImportError):
                RCore()


class TestAsyncNativeIntegration(unittest.TestCase):
    @unittest.skipUnless(r2lib() is not None, "r_core library not available")
    def test_real_native_library_in_subprocess(self):
        script = '''
import asyncio
from r2pipe.open_async import open

with open("ccall://malloc://32") as r2:
    assert r2.cmd("?e blocking-native") == "blocking-native\\n"
    assert r2.cmd2j("ij").res.core.file == "malloc://32"

async def main():
    async with open("ccall://malloc://32") as first, open("ccall://malloc://64") as second:
        first_info, second_info = await asyncio.gather(first.cmd2j("ij"), second.cmd2j("ij"))
        assert first_info.res.core.file == "malloc://32"
        assert second_info.res.core.file == "malloc://64"
        replies = await asyncio.gather(*[first.cmd2("?e native-%d" % i) for i in range(30)])
        assert [reply.res for reply in replies] == ["native-%d\\n" % i for i in range(30)]

loop = asyncio.new_event_loop()
try:
    loop.run_until_complete(main())
finally:
    loop.close()
print("native integration passed")
'''
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"native integration passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
