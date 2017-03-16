r2pipe for Python
=================

Interact with radare2 using the #!pipe command or in standalone scripts
that communicate with local or remote r2 via pipe, tcp or http.

### Installation

```
$ pip install r2pipe
```

or

```
$ pip3 install r2pipe
```

### Usage example:

```python
import r2pipe

r2 = r2pipe.open("/bin/ls")
r2.cmd('aa')
print(r2.cmd("afl"))
print(r2.cmdj("aflj"))  # evaluates JSONs and returns an object
r2.quit()
```
