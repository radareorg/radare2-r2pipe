import gc
import unittest
import warnings

from r2pipe.open_async import open as async_open


class TestAsyncQuit(unittest.TestCase):
    def test_quit_uses_async_shutdown_after_r2pipe2(self):
        r2 = async_open("-", ["-N", "-e", "scr.color=0"])
        loop = r2._loop
        process = None
        try:
            reply = r2.cmd2j("ij")
            process = r2.process
            self.assertFalse(reply.error)
            self.assertEqual(reply.res.core.file, "malloc://512")

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", RuntimeWarning)
                r2.quit()
                gc.collect()

            self.assertIsNotNone(process.returncode)
            self.assertTrue(loop.is_closed())
            self.assertFalse(hasattr(r2, "process"))
            self.assertFalse(any("was never awaited" in str(item.message) for item in caught))
            r2.quit()
            r2.close()
            with self.assertRaises(RuntimeError):
                r2.cmd2("?e closed")
        finally:
            if not loop.is_closed():
                if process is not None:
                    r2.process = process
                r2.close()


if __name__ == "__main__":
    unittest.main()
