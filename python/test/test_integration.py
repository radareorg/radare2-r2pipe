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

    def test_r2cmd_hello_world(self):
        cmd = "?e hello;?e world"
        expected = "hello\nworld\n"
        res = self.r2.cmd(cmd)
        self.assertEqual(res, expected)

    def test_r2cmd_hello_world(self):
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
        import r2pipe
        r = r2pipe.open('/bin/ls')

        result = r.cmd('prx @r:SP')
        self.assertNotEqual(result, '')
