import asyncio
import gc
import json
import os
import unittest
import warnings
from unittest.mock import patch

from r2pipe.open_async import open as async_open
from r2pipe.open_base import OpenBase


def run_async(coroutine):
    if hasattr(asyncio, "run"):
        return asyncio.run(coroutine)
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coroutine)
    finally:
        loop.close()


class MemoryWriter:
    def __init__(self):
        self.closing = False

    def write(self, data):
        pass

    async def drain(self):
        pass

    def close(self):
        self.closing = True

    def is_closing(self):
        return self.closing

    async def wait_closed(self):
        pass


class TestAsyncRunningLoop(unittest.TestCase):
    flags = ["-N", "-2"]

    def block_response(self, r2):
        """Pause after a command is sent, before its response is consumed."""
        entered = asyncio.Event()
        release = asyncio.Event()
        read = r2.process.stdout.read

        async def blocked_read(size):
            entered.set()
            await asyncio.wait_for(release.wait(), 5)
            return await read(size)

        r2.process.stdout.read = blocked_read
        return entered, release

    def test_await_command_wrappers_and_raw_callbacks(self):
        async def main():
            async with async_open("-", self.flags) as r2:
                self.assertEqual(await r2.cmd("?e text"), "text\n")
                self.assertEqual((await r2.cmdj("ij"))["core"]["file"], "malloc://512")
                self.assertEqual((await r2.cmdJ("ij")).core.file, "malloc://512")
                callbacks = []
                reply = await r2.cmd2("?e r2pipe2", callback=callbacks.append)
                self.assertFalse(reply.error)
                self.assertEqual(reply.res, "r2pipe2\n")
                self.assertEqual(json.loads(callbacks[0])["res"], reply.res)
                reply = await r2.cmd2j("ij")
                self.assertEqual(reply.res.core.file, "malloc://512")
                result = await r2.call(json.dumps({"cmd": "?e call"}))
                self.assertEqual(json.loads(result)["res"], "call\n")
                self.assertEqual(await r2.cmdj(""), {})
                self.assertIsNone(await r2.cmdj("?e invalid json"))
                self.assertIsNone(await r2.cmdJ("?e invalid json"))
        run_async(main())

    def test_client_created_before_running_loop_adopts_it(self):
        r2 = async_open("-", self.flags)
        original_loop = r2._loop

        async def main():
            async with r2:
                self.assertEqual(await r2.cmd("?e adopted"), "adopted\n")
                self.assertIs(r2._loop, asyncio.get_event_loop())
                self.assertTrue(original_loop.is_closed())
            self.assertFalse(asyncio.get_event_loop().is_closed())
        run_async(main())

    def test_concurrent_first_use_spawns_once_and_orders_callbacks(self):
        async def main():
            callbacks = []
            spawn = asyncio.create_subprocess_exec
            spawn_count = []

            async def counted_spawn(*args, **kwargs):
                spawn_count.append(1)
                # Give competing commands a chance to initialize a process too.
                await asyncio.sleep(0)
                return await spawn(*args, **kwargs)

            async with async_open("-", self.flags) as r2:
                with patch("r2pipe.open_async.asyncio.create_subprocess_exec", counted_spawn):
                    expected = ["command-%d\n" % index for index in range(30)]
                    results = await asyncio.gather(*[
                        r2.cmd("?e command-%d" % index, callback=callbacks.append)
                        for index in range(30)
                    ])
                self.assertEqual(spawn_count, [1])
                self.assertEqual(results, expected)
                self.assertEqual(callbacks, expected)
        run_async(main())

    def test_commands_leave_caller_event_loop_responsive(self):
        async def main():
            async with async_open("-", self.flags) as r2:
                await r2.cmd("?e warmup")
                entered, release = self.block_response(r2)
                task = r2._loop.create_task(r2.cmd("?e response"))
                await asyncio.wait_for(entered.wait(), 2)
                self.assertFalse(task.done())
                # The test coroutine is still running while transport I/O is paused.
                await asyncio.sleep(0)
                release.set()
                self.assertEqual(await task, "response\n")
        run_async(main())

    def test_wait_accepts_command_coroutines_and_keeps_input_order(self):
        async def main():
            async with async_open("-", self.flags) as r2:
                futures = await r2.wait([r2.cmd("?e first"), r2.cmd("?e second")])
                self.assertEqual([future.result() for future in futures], ["first\n", "second\n"])
                future, = await r2.wait(r2.cmd("?e single"))
                self.assertEqual(future.result(), "single\n")
                self.assertEqual(await r2.wait([]), [])
        run_async(main())

    def test_canceled_wait_followed_by_close_retrieves_wrapper_errors(self):
        async def main():
            r2 = async_open("-", self.flags)
            entered = asyncio.Event()
            release = asyncio.Event()
            errors = []
            loop = r2._loop
            handler = loop.get_exception_handler()
            loop.set_exception_handler(lambda loop, context: errors.append(context))

            async def blocked_command(cmd, future, callback):
                entered.set()
                await asyncio.wait_for(release.wait(), 5)
                future.set_result((future._cmd_id, cmd, callback))
                return cmd

            r2._cmd_coro = blocked_command
            try:
                waiter = loop.create_task(r2.wait([r2.cmd("first"), r2.cmd("second")]))
                await asyncio.wait_for(entered.wait(), 2)
                waiter.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await waiter
                closing = loop.create_task(r2.close())
                await asyncio.sleep(0)
                release.set()
                await closing
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                gc.collect()
                self.assertEqual(errors, [])
            finally:
                release.set()
                await r2.close()
                loop.set_exception_handler(handler)
        run_async(main())

    def test_cancel_started_command_preserves_next_response(self):
        async def main():
            async with async_open("-", self.flags) as r2:
                await r2.cmd("wx 90 @0")
                entered, release = self.block_response(r2)
                task = r2._loop.create_task(r2.cmd("wx cc @0; ?e canceled"))
                await asyncio.wait_for(entered.wait(), 2)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                following = r2._loop.create_task(r2.cmd("?e following"))
                await asyncio.sleep(0)
                self.assertFalse(following.done())
                release.set()
                self.assertEqual(await following, "following\n")
                self.assertEqual(await r2.cmd("p8 1 @0"), "cc\n")
        run_async(main())

    def test_cancel_queued_command_does_not_execute(self):
        async def main():
            async with async_open("-", self.flags) as r2:
                await r2.cmd("wx 90 @0")
                callbacks = []
                async with r2._cmd_lock:
                    queued = r2._loop.create_task(
                        r2.cmd("wx cc @0", callback=callbacks.append)
                    )
                    await asyncio.sleep(0)
                    await asyncio.sleep(0)
                    queued.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await queued
                self.assertEqual(await r2.cmd("p8 1 @0"), "90\n")
                self.assertEqual(callbacks, [])
        run_async(main())

    @unittest.skipUnless(hasattr(asyncio, "eager_task_factory"), "requires eager asyncio tasks")
    def test_cancel_started_eager_task_preserves_next_response(self):
        async def main():
            async with async_open("-", self.flags) as r2:
                await r2.cmd("?e warmup")
                entered, release = self.block_response(r2)
                loop = r2._loop
                factory = loop.get_task_factory()
                loop.set_task_factory(asyncio.eager_task_factory)
                try:
                    task = loop.create_task(r2.cmd("?e canceled"))
                    await asyncio.wait_for(entered.wait(), 2)
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    release.set()
                    reply = await r2.cmd2("?e following")
                    self.assertEqual(reply.res, "following\n")
                finally:
                    release.set()
                    loop.set_task_factory(factory)
        run_async(main())

    def test_concurrent_close_drains_active_and_rejects_queued_commands(self):
        async def main():
            r2 = async_open("-", self.flags)
            await r2.cmd("wx 90 @0")
            process = r2.process
            entered, release = self.block_response(r2)
            active = r2._loop.create_task(r2.cmd("?e active"))
            await asyncio.wait_for(entered.wait(), 2)
            queued = r2._loop.create_task(r2.cmd("wx cc @0"))
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            closers = [r2._loop.create_task(close()) for close in (r2.close, r2.quit, r2.aclose)]
            await asyncio.sleep(0)
            self.assertTrue(all(not task.done() for task in closers))
            release.set()
            self.assertEqual(await active, "active\n")
            with self.assertRaisesRegex(RuntimeError, "closed"):
                await queued
            await asyncio.gather(*closers)
            self.assertIsNotNone(process.returncode)
            self.assertFalse(hasattr(r2, "process"))
            self.assertEqual(r2._command_tasks, set())
            self.assertFalse(r2._loop.is_closed())
            await r2.close()
            await r2.quit()
            with self.assertRaisesRegex(RuntimeError, "closed"):
                r2.cmd("?e closed")
        run_async(main())

    def test_cancel_close_still_finishes_cleanup(self):
        async def main():
            r2 = async_open("-", self.flags)
            await r2.cmd("?e warmup")
            process = r2.process
            entered, release = self.block_response(r2)
            active = r2._loop.create_task(r2.cmd("?e active"))
            await asyncio.wait_for(entered.wait(), 2)
            closing = r2._loop.create_task(r2.close())
            await asyncio.sleep(0)
            closing.cancel()
            await asyncio.sleep(0)
            self.assertFalse(closing.done())
            closing.cancel()
            await asyncio.sleep(0)
            self.assertFalse(closing.done())
            release.set()
            self.assertEqual(await active, "active\n")
            with self.assertRaises(asyncio.CancelledError):
                await closing
            self.assertIsNotNone(process.returncode)
            self.assertFalse(hasattr(r2, "process"))
            await r2.close()
        run_async(main())

    def test_close_before_command_starts_never_spawns(self):
        async def main():
            r2 = async_open("-", self.flags)
            command = r2.cmd("?e too late")
            await asyncio.gather(r2.close(), r2.quit())
            with self.assertRaisesRegex(RuntimeError, "closed"):
                await command
            self.assertFalse(hasattr(r2, "process"))
        run_async(main())

    def test_used_client_rejects_different_loop_without_coroutine_warnings(self):
        r2 = async_open("-", self.flags)
        r2.cmd("?e private loop")

        async def main():
            with self.assertRaisesRegex(RuntimeError, "different event loop"):
                r2.cmd("?e wrong loop")
            with self.assertRaisesRegex(RuntimeError, "different event loop"):
                r2.close()

        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                run_async(main())
                gc.collect()
            self.assertFalse(any("was never awaited" in str(item.message) for item in caught))
        finally:
            r2.close()

    def test_closed_blocking_client_can_be_closed_again_inside_loop(self):
        r2 = async_open("-", self.flags)
        r2.cmd("?e blocking")
        r2.close()

        async def main():
            await r2.close()
            await r2.quit()
        run_async(main())

    def test_command_coroutine_awaited_on_foreign_loop_never_starts(self):
        owner = asyncio.new_event_loop()
        foreign = asyncio.new_event_loop()

        async def prepare():
            r2 = async_open("-", self.flags)
            return r2, r2.cmd("?e transferred")

        r2, command = owner.run_until_complete(prepare())
        try:
            with self.assertRaisesRegex(RuntimeError, "different event loop"):
                foreign.run_until_complete(command)
            self.assertEqual(r2._command_tasks, set())
            self.assertFalse(hasattr(r2, "process"))
        finally:
            owner.run_until_complete(r2.aclose())
            owner.close()
            foreign.close()

    def test_sync_context_in_event_loop_rejected_before_starting_process(self):
        async def main():
            r2 = async_open("-", self.flags)
            with self.assertRaisesRegex(RuntimeError, "async with"):
                with r2:
                    self.fail("synchronous context manager body must not run")
            self.assertFalse(hasattr(r2, "process"))
            await r2.close()
        run_async(main())

    def test_explicit_embedded_pipe_keeps_blocking_command_wrappers(self):
        with patch.dict(os.environ, {"R2PIPE_IN": "123", "R2PIPE_OUT": "124"}):
            with patch.object(OpenBase, "_cmd_pipe", return_value='{"value":1}') as pipe:
                with async_open("#!pipe") as r2:
                    self.assertFalse(r2.asyn)
                    self.assertEqual(r2.cmdj("ij"), {"value": 1})
                    self.assertEqual(r2.cmdJ("ij").value, 1)
                    self.assertEqual(r2.cmd2("ij").value, 1)
                    self.assertEqual(r2.cmd2j("ij").value, 1)
                    self.assertEqual(pipe.call_count, 4)
                    self.assertFalse(hasattr(r2, "process"))

    def test_http_pools_only_live_persistent_connections(self):
        def response(version, text, extra=""):
            return ("HTTP/%s 200 OK\r\n%sContent-Length: %d\r\n\r\n%s" % (
                version, extra, len(text), text
            )).encode()

        async def main():
            responses = iter([
                response("1.0", "first\n"),
                response("1.1", "second\n", "Connection: close\r\n"),
                response("1.1", "third\n"),
                response("1.1", "fifth\n"),
            ])
            connections = []

            async def connect(host, port):
                reader = asyncio.StreamReader()
                reader.feed_data(next(responses))
                writer = MemoryWriter()
                connections.append((reader, writer))
                return reader, writer

            with patch("r2pipe.open_async.asyncio.open_connection", connect):
                async with async_open("http://127.0.0.1:9090") as r2:
                    self.assertEqual(await r2.cmd("first"), "first\n")
                    self.assertTrue(connections[0][1].is_closing())
                    self.assertEqual(await r2.cmd("second"), "second\n")
                    self.assertTrue(connections[1][1].is_closing())
                    self.assertEqual(await r2.cmd("third"), "third\n")
                    self.assertFalse(connections[2][1].is_closing())
                    connections[2][0].feed_data(response("1.1", "fourth\n"))
                    self.assertEqual(await r2.cmd("fourth"), "fourth\n")
                    self.assertEqual(len(connections), 3)
                    connections[2][0].feed_eof()
                    self.assertEqual(await r2.cmd("fifth"), "fifth\n")
                    self.assertTrue(connections[2][1].is_closing())
                    self.assertEqual(len(connections), 4)
            self.assertTrue(all(writer.is_closing() for _, writer in connections))
        run_async(main())

    def test_http_waits_for_fragmented_headers_and_entire_body(self):
        async def main():
            headers_started = asyncio.Event()
            body_reads = asyncio.Queue()

            class Reader(asyncio.StreamReader):
                async def readuntil(self, separator):
                    headers_started.set()
                    return await super(Reader, self).readuntil(separator)

                async def read(self, size):
                    body_reads.put_nowait(size)
                    return await super(Reader, self).read(size)

            reader = Reader()
            writer = MemoryWriter()
            connections = []

            async def connect(host, port):
                connections.append(1)
                return reader, writer

            reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Len")
            with patch("r2pipe.open_async.asyncio.open_connection", connect):
                async with async_open("http://127.0.0.1:9090") as r2:
                    command = r2._loop.create_task(r2.cmd("first"))
                    try:
                        await asyncio.wait_for(headers_started.wait(), 2)
                        reader.feed_data(b"gth: 6\r\n\r")
                        await asyncio.sleep(0)
                        self.assertFalse(command.done())
                        self.assertTrue(body_reads.empty())
                        reader.feed_data(b"\nfi")
                        self.assertEqual(await asyncio.wait_for(body_reads.get(), 2), 6)
                        self.assertEqual(await asyncio.wait_for(body_reads.get(), 2), 4)
                        self.assertFalse(command.done())
                        reader.feed_data(b"rs")
                        self.assertEqual(await asyncio.wait_for(body_reads.get(), 2), 2)
                        self.assertFalse(command.done())
                        reader.feed_data(b"t\n")
                        self.assertEqual(await asyncio.wait_for(command, 2), "first\n")
                        reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nsecond\n")
                        self.assertEqual(await r2.cmd("second"), "second\n")
                        self.assertEqual(connections, [1])
                    finally:
                        reader.feed_eof()
                        await asyncio.gather(command, return_exceptions=True)
            self.assertTrue(writer.is_closing())
        run_async(main())

    def test_http_truncated_body_closes_connection_and_never_returns_partial_result(self):
        async def main():
            connections = []

            async def connect(host, port):
                reader = asyncio.StreamReader()
                writer = MemoryWriter()
                if not connections:
                    reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
                    reader.feed_eof()
                else:
                    reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nnext\n")
                connections.append((reader, writer))
                return reader, writer

            with patch("r2pipe.open_async.asyncio.open_connection", connect):
                async with async_open("http://127.0.0.1:9090") as r2:
                    errors = []
                    self.assertIsNone(await r2.cmd("truncated", callback=errors.append))
                    self.assertEqual(errors, ["Incomplete HTTP response body"])
                    self.assertTrue(connections[0][1].is_closing())
                    self.assertEqual(r2._connection_pool["127.0.0.1:9090"], [])
                    self.assertEqual(await r2.cmd("next"), "next\n")
                    self.assertEqual(len(connections), 2)
            self.assertTrue(all(writer.is_closing() for _, writer in connections))
        run_async(main())


if __name__ == "__main__":
    unittest.main()
