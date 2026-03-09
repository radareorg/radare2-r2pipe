import unittest
import os

import r2pipe


class TestR2PipeIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.curdir = os.path.dirname(os.path.realpath(__file__))

    def setUp(self):
        self.r2_ls = r2pipe.open(os.path.join(self.curdir, "ls") , ["-2"])
        self.r2 = r2pipe.open("-")

    def tearDown(self):
        self.r2_ls.quit()
        self.r2.quit()

    def test_open_successfully(self):
        r2 = r2pipe.open('/bin/ls')
        self.assertIsInstance(r2, r2pipe.open_sync.open)
        r2.quit()

    def test_open_unsuccessfully_file(self):
        with self.assertRaises(Exception):
            r2 = r2pipe.open("/bin/unexistent")

    def test_open_unsuccessfully_url(self):
        with self.assertRaises(Exception):
            r2 = r2pipe.open("404://notfound")

    def test_open_successfully_with_params(self):
        r2 = r2pipe.open(os.path.join(self.curdir, "ls") , ["-nn"])
        res = r2.cmd('pxW 4~:0[1]').strip()
        self.assertEqual(res, "0xfeedfacf")
        r2.quit()

    def test_r2cmd_successfully(self):
        self.r2_ls.cmd("aa")
        res = self.r2_ls.cmd("pi 1").strip()
        self.assertEqual(res, "push rbp")

    def test_r2cmd_json_successfully(self):
        self.r2_ls.cmd("aa")
        res = self.r2_ls.cmdj("pij 1")
        self.assertIsInstance(res[0], dict)
        self.assertEqual(res[0]['opcode'], "push rbp")

    def test_r2ccal_successfully(self):
        r2 = r2pipe.open("ccall:///%s" % os.path.join(self.curdir, "ls"))
        res = r2.cmd("pi 1 @e:scr.color=0").strip()
        self.assertEqual(res, "push rbp")
        r2.quit()

    def test_r2cmd_hello_newline(self):
        cmd = "?e hello\n"
        expected = "hello\n"
        res = self.r2.cmd(cmd)
        self.assertEqual(res, expected)

    def test_r2cmd_hello_world_newline(self):
        cmd = "?e hello\n?e world"
        expected = "hello\nworld\n"
        res = self.r2.cmd(cmd)
        self.assertEqual(res, expected)

    def test_r2cmd_hello_world_semicolon(self):
        cmd = "?e hello;?e world"
        expected = "hello\nworld\n"
        res = self.r2.cmd(cmd)
        self.assertEqual(res, expected)

    def test_r2cmd_hello_world_multiple_newlines(self):
        cmd = "?e hello\n\n;\n\n?e world"
        expected = "hello\nworld\n"
        res = self.r2.cmd(cmd)
        self.assertEqual(res, expected)

    def test_r2cmd_hello_world_multiple_semicolon(self):
        cmd = "?e hello;;;;;?e world"
        expected = "hello\nworld\n"
        res = self.r2.cmd(cmd)
        self.assertEqual(res, expected)

    def test_r2cmd_no_nullbyte_bug(self):
        r2 = r2pipe.open('/bin/ls')
        result = r2.cmd('prx @r:SP')
        self.assertNotEqual(result, '')
        r2.quit()

    def test_context_manager(self):
        """Test sync open works as context manager"""
        with r2pipe.open(os.path.join(self.curdir, "ls"), ["-2"]) as r2:
            res = r2.cmd("i")
            self.assertIsNotNone(res)
            self.assertTrue(len(res) > 0)

    def test_cmdJ_object_access(self):
        """Test cmdJ returns object with attribute access"""
        info = self.r2_ls.cmdJ("ij")
        self.assertIsNotNone(info)
        self.assertTrue(hasattr(info, "bin"))

    def test_cmdj_empty_result(self):
        """Test cmdj with command returning empty result"""
        result = self.r2_ls.cmdj("px 10")
        # px doesn't return JSON, cmdj should handle gracefully
        self.assertIsNone(result)

    def test_version(self):
        """Test version() returns expected string"""
        ver = r2pipe.version()
        self.assertEqual(ver, r2pipe.VERSION)
        self.assertIsInstance(ver, str)

    def test_in_r2(self):
        """Test in_r2() returns False outside r2 environment"""
        self.assertFalse(r2pipe.in_r2())

    def test_sequential_commands(self):
        """Test running many commands sequentially on same instance"""
        for i in range(10):
            res = self.r2.cmd(f"?e cmd{i}")
            self.assertEqual(res, f"cmd{i}\n")
