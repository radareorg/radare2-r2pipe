import sys
import r2pipe

err = 0


def test(msg, a, b):
    global err
    sys.stdout.write("%s  " % (msg))
    a = a.strip()
    b = b.strip()
    if a == b:
        print("ok")
    else:
        err = err + 1
        print("FAIL")


def verify(title, cmd, expected):
    r2 = r2pipe.open("-")
    msg = r2.cmd(cmd)
    test(title, msg, expected)
    r2.quit()


verify("Test #1", "?e hello", "hello")
verify("Test #2", "?e hello\n", "hello")
verify("Test #3", "?e hello\n?e world", "hello\nworld")
verify("Test #4", "?e hello;?e world", "hello\nworld")
verify("Test #5", "?e hello\n", "hello")
verify("Test #6", "?e hello\n\n;\n\n?e world", "hello\nworld")  # known to fail
verify("Test #7", "?e hello\n", "hello")
verify("Test #8", "?e hello;;;;;?e world", "hello\nworld")

sys.exit(err)
