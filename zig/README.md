# r2pipe for zig

## Compilation

You can do `make` or `zig build-exe main.zig` to get the program to run

```
make
```

## Usage

Now you are ready to use this executable as via `#!pipe` inside radare2:

```
$ r2 /bin/ls
> #!pipe ./main
Hello, World
 ╭──╮    ╭─────────────╮
 │ _│    │             │
 │ O O  <  Hello World │
 │  │╭   │             │
 ││ ││   ╰─────────────╯
 │└─┘│
 ╰───╯
```
