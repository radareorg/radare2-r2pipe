import asyncio
import json
import unittest
from unittest.mock import Mock

import r2pipe
from r2pipe.open_async import open as async_open
from r2pipe.open_base import OpenBase


def run_async(coroutine):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coroutine)
    finally:
        loop.close()


class Callback(list):
    def __call__(self, response):
        self.append(response)


class TestR2Pipe2Options(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.response = '{"res":"hello\\n","error":false}'
        self.r2 = OpenBase.__new__(OpenBase)
        self.r2.asyn = False

        def transport(command):
            self.sent.append(command)
            return self.response
        self.r2._cmd = transport

    def test_sync_options_are_sent_and_callbacks_receive_raw_response(self):
        callback = Callback()
        reply = self.r2.cmd2("?e hello", trim=True, json=False, callback=callback)
        self.assertEqual(reply.res, "hello\n")
        self.assertEqual(json.loads(self.sent[-1][1:]), {
            "cmd": "?e hello", "trim": True, "json": False,
        })
        self.assertEqual(callback, [self.response])

    def test_cmd2j_defaults_and_false_overrides_do_not_leak_to_cmd2(self):
        self.r2.cmd2j("ij")
        self.assertEqual(json.loads(self.sent[-1][1:]), {
            "cmd": "ij", "trim": True, "json": True,
        })
        callback = Mock()
        self.r2.cmd2j("ij", trim=False, json=False, callback=callback)
        self.assertEqual(json.loads(self.sent[-1][1:]), {
            "cmd": "ij", "trim": False, "json": False,
        })
        callback.assert_called_once_with(self.response)
        self.r2.cmd2("ij")
        self.assertEqual(json.loads(self.sent[-1][1:]), {"cmd": "ij"})

    def test_call_and_plain_commands_support_sync_callbacks(self):
        for method in (self.r2.call, self.r2.cmd, self.r2.cmdj, self.r2.cmdJ):
            with self.subTest(method=method.__name__):
                callback = Mock()
                method("ij", callback=callback)
                callback.assert_called_once_with(self.response)

    def test_invalid_options_fail_before_sync_transport(self):
        cases = [
            {"trmi": True}, {"timeout": 1}, {"trim": "yes"},
            {"trim": None}, {"json": 1}, {"json": None}, {"callback": False},
        ]
        for method in (self.r2.cmd2, self.r2.cmd2j):
            for kwargs in cases:
                with self.subTest(method=method.__name__, kwargs=kwargs):
                    with self.assertRaises(TypeError):
                        method("ij", **kwargs)
        with self.assertRaises(TypeError):
            self.r2.call("ij", timeout=1)
        with self.assertRaises(TypeError):
            self.r2.call("ij", callback=0)
        self.assertEqual(self.sent, [])

    def test_async_options_callbacks_and_false_overrides(self):
        async def main():
            async with async_open("-", ["-N", "-2"]) as r2:
                async def transport(command, future, callback):
                    self.sent.append(command)
                    await asyncio.sleep(0)
                    future.set_result((future._cmd_id, self.response, callback))
                    return self.response
                r2._cmd_coro = transport
                callbacks = Callback()
                replies = await asyncio.gather(
                    r2.cmd2("?e first", trim=True, json=False, callback=callbacks),
                    r2.cmd2j("?e second", trim=False, json=False, callback=callbacks),
                )
                self.assertEqual([reply.res for reply in replies], ["hello\n", "hello\n"])
                self.assertEqual([json.loads(command[1:]) for command in self.sent], [
                    {"cmd": "?e first", "trim": True, "json": False},
                    {"cmd": "?e second", "trim": False, "json": False},
                ])
                self.assertEqual(callbacks, [self.response, self.response])
                await r2.cmd2j("ij")
                self.assertEqual(json.loads(self.sent[-1][1:]), {
                    "cmd": "ij", "trim": True, "json": True,
                })
                await r2.cmd2("ij")
                self.assertEqual(json.loads(self.sent[-1][1:]), {"cmd": "ij"})
                callback = Mock()
                await r2.call("ij", callback=callback)
                callback.assert_called_once_with(self.response)
                self.assertFalse(hasattr(r2, "process"))
        run_async(main())

    def test_invalid_async_options_fail_before_scheduling(self):
        async def main():
            async with async_open("-", ["-N", "-2"]) as r2:
                for method in (r2.cmd2, r2.cmd2j):
                    for kwargs in ({"trmi": True}, {"trim": "yes"}, {"json": 1}, {"callback": False}):
                        with self.subTest(method=method.__name__, kwargs=kwargs):
                            with self.assertRaises(TypeError):
                                method("ij", **kwargs)
                with self.assertRaises(TypeError):
                    r2.call("ij", timeout=1)
                with self.assertRaises(TypeError):
                    r2.call("ij", callback=False)
                self.assertFalse(hasattr(r2, "process"))
                self.assertEqual(r2._command_tasks, set())
        run_async(main())


class TestR2Pipe2OptionsIntegration(unittest.TestCase):
    def check_options(self, r2):
        self.assertEqual(r2.cmd2("?e hello", trim=True).res, "hello")
        self.assertEqual(r2.cmd2("?e hello", trim=False).res, "hello\n")
        self.assertEqual(r2.cmd2("ij", json=True).res.core.file, "malloc://512")
        self.assertEqual(r2.cmd2j("?e hello", json=False).res, "hello")
        self.assertEqual(r2.cmd2j("?e hello", json=False, trim=False).res, "hello\n")
        callbacks = []
        reply = r2.cmd2("?e callback", trim=True, callback=callbacks.append)
        self.assertEqual(reply.res, "callback")
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(json.loads(callbacks[0])["res"], reply.res)

    def test_real_sync_and_blocking_async_options(self):
        for factory in (r2pipe.open, async_open):
            with self.subTest(client=factory.__module__):
                with factory("-", ["-N", "-2"]) as r2:
                    self.check_options(r2)

    def test_real_awaited_options(self):
        async def main():
            async with async_open("-", ["-N", "-2"]) as r2:
                replies = await asyncio.gather(
                    r2.cmd2("?e hello", trim=True),
                    r2.cmd2("ij", json=True),
                    r2.cmd2j("?e hello", json=False, trim=False),
                )
                self.assertEqual(replies[0].res, "hello")
                self.assertEqual(replies[1].res.core.file, "malloc://512")
                self.assertEqual(replies[2].res, "hello\n")
        run_async(main())


if __name__ == "__main__":
    unittest.main()
