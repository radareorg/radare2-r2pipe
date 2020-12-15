import unittest
import os
import r2pipe


class TestR2PipeIntegration(unittest.TestCase):

    def setUp(self):
        curdir = os.path.dirname(os.path.realpath(__file__))
        self.r2 = r2pipe.open(os.path.join(curdir, "ls") , ["-2"])

    def tearDown(self):
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

    def test_r2cmd_successfully(self):
        self.r2.cmd("aa")
        res = self.r2.cmd("pi 1").strip()
        self.assertEqual(res, "push rbp")

    def test_r2cmd_json_successfully(self):
        self.r2.cmd("aa")
        res = self.r2.cmdj("pij 1")
        self.assertIsInstance(res[0], dict)
        self.assertEqual(res[0]['opcode'], "push rbp")

    def test_r2ccal_successfully(self):
        r2 = r2pipe.open("ccall:///bin/ls")
        res = r2.cmd("pi 1 @e:scr.color=0").strip()
        self.assertEqual(res, "push rbp")
        r2.quit()

    def test_dbg_successfully(self):
        r2 = r2pipe.open("/bin/ls", ["-nd"])
        for a in range(1, 10):
            regs = r2.cmdj("drj")
            print("0x%x  0x%x" % (regs["rip"], regs["rsp"]))
            r2.cmd("ds")
