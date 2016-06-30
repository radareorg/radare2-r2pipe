r2pipe for Python
=================

Interact with radare2 using the #!pipe command or in standalone scripts
that communicate with local or remote r2 via pipe, tcp or http.

Usage example::

    $ python
    > import r2pipe
    > r2 = r2pipe.open("/bin/ls")
    > print(r2.cmd("pd 10"))
    > r2.quit()
