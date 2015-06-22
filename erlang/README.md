r2pipe for erlang
=================
Works with r2 over the ports interface or by calling escript direclty from r2. 

Build:

```
$ rebar get-deps
$ rebar co
```

Example pipe usage:

```
$ rebar sh
erl> H = r2pipe:init(pipe, "/bin/ls").
erl> io:format("~s", [r2pipe:cmd(H, "i")]).
erl> r2pipe:cmdj(H, "ij").
```

See testr2pipe.erl as local pipe call example escript. Call it from r2 by using:
```
r2> #!pipe escript testr2pipe.erl
```

Or

```
$ chmod +x testr2pipe.erl
```

And then from r2:

```
r2> #!pipe testr2pipe.erl
```