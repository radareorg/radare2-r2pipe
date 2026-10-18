# r2pipe API for radare2

![r2pipe logo](http://lolcathost.org/b/r2pipe.png)

This is a reimplementation in TypeScript of the original `r2pipe` and `r2pipe-promise` modules for NodeJS.

## Usage

If you are using r2skel (`r2pm -ci r2skel`) you can get a hello world to use this module with the following line:

```
r2pm -r r2skel r2-script-r2pipe-ts hello-ts
make -C hello-ts
```

## Basics

The basic fundamentals of r2pipe is that you the API provides the most basic communication channel with r2, this is a single function called `cmd` that takes the command to be executed and returns the output of the command as a string.

Many commands in r2 return JSON. `cmdj<T>()` parses that output, with an optional result type. Its default result type is `unknown`; specifying `T` describes the expected result without validating it.

```typescript
import { open } from "r2pipe-ts";

const r2 = open("/bin/ls");
const flags = await r2.cmdj<Array<{ name: string; addr: number | bigint }>>("fj");
await r2.quit();
```

Integer JSON literals outside JavaScript's safe integer range are returned as `bigint`, preserving 64-bit addresses exactly. Safe integers, fractions, and numbers written with an exponent remain JavaScript numbers. JSON strings, booleans, arrays, and `null` keep their usual meanings. Use `String(value)` to display a bigint; native `JSON.stringify` requires a replacer for bigint values.

To retain native `JSON.parse` behavior, or use another parser, pass `jsonParser` when opening any backend:

```typescript
const r2 = open("http://localhost:9090", { jsonParser: JSON.parse });
```

The package also exports `R2PipeCmdInterface`, `R2PipeOptions`, `R2PipeWasmOptions`, and `JsonParser` types and the default `parseJson` function.

In order to provide compatibility with all kind of backends, the whole api has been made asynchronous, this allows the developer to change the backend by only changing one line.

The spawn backend consumes radare2's stderr so diagnostics cannot block command processing.

## Supported r2pipe methods

* http (command text is URL-encoded; radare2 versions that emit LF-only HTTP response headers require Node's `--insecure-http-parser` flag)
* spawn (launch a new radare2 process and communicate with it sending async commands to collect the response)
* local (the local pipe is used when launching scripts from `r2 -i too.ts` or `> . too.ts`
* wasm (opt-in WASI API backend, running an isolated radare2 instance without a native process)

## Optional WASM backend

Set `wasm.path` to a local `radare2.wasm` from a **wasi-api** archive on the [radare2 releases page](https://github.com/radareorg/radare2/releases). These are reactor builds exporting the C API; the CLI and browser archives are different builds. The [r2wasm project](https://github.com/radareorg/r2wasm) provides browser components.

```typescript
import { open } from "r2pipe-ts";

const r2 = open("malloc://64", { wasm: { path: "./radare2.wasm" } });
try {
  await r2.cmd("wx 9090c3");
  console.log(await r2.cmd("p8 3"));
} finally {
  await r2.quit();
}
```

`open()` keeps its synchronous interface. The first command reads and instantiates the selected module, initializes WASI, and creates a core with `r_core_new()`. Commands call `r_core_cmd_str()` to capture their output; command buffers and returned strings are freed after each call. Commands are serialized, and `quit()` waits for accepted commands before freeing the core. An empty target creates a core without opening a file. `cmdj()` and `jsonParser` work as with the other backends.

The feature is disabled unless `wasm` is supplied. Loading the package and using other backends requires neither WebAssembly nor WASI. The WASM backend loads `node:wasi` only on its first command and requires a runtime providing WebAssembly and Node's WASI preview1 API. It downloads nothing automatically and adds no runtime dependencies.

No host directories or environment variables are exposed by default. For host files, explicitly map a directory and use the guest path as the target:

```typescript
const r2 = open("/data/program", {
  wasm: { path: "./radare2.wasm", preopens: { "/data": "/absolute/host/directory" } },
});
console.log(await r2.cmdj("ij"));
await r2.quit();
```

Preopened directories permit file access, including writes through radare2 commands. Node's WASI implementation is [not a security boundary for untrusted modules](https://nodejs.org/api/wasi.html#webassembly-system-interface-wasi).

### Downloading API builds

The separate helper requires Node.js 20+ and `unzip`. It lists all published releases, marking those without API builds, and downloads only the API archive's `radare2.wasm`:

```sh
cd typescript
node wasm-download.cjs --list
node wasm-download.cjs                       # newest stable release with an API build
node wasm-download.cjs 6.2.0                 # explicit release
node wasm-download.cjs 6.2.0 ./r2-6.2.0.wasm  # explicit output path
```

`npm run wasm -- ...` also invokes the helper. Downloads replace the output file only after successful extraction and WASM header validation. Releases without API assets are skipped for `latest`; explicitly selecting one reports an error.

The 6.2.0 API build has been verified with this backend. The 6.2.2 API build traps inside `r_core_new()` during initialization in Node.js 24; select 6.2.0 if you encounter that upstream build issue.

## r2Frida-Compile

radare2 also supports the esm modules generated by frida-compile. But it is worth to mention that r2frida comes with a C reimplementation of frida-compile (python). Which ships a typescript compiler and is able to pack multiple ts/js files into a single file.

## Runtime

This module is suposed to run with NodeJS, under some circunstancies, it may also with with r2js, bun or deno.

Development tools require Node.js 20.19+, 22.13+, or 24+. Use `npm ci` to install dependencies, `npm test` to build and test, and `npm run lint` to lint the TypeScript sources.

WASM tests include a small offline API fixture. To also exercise a released radare2 module, run `R2PIPE_WASM=/absolute/path/radare2.wasm npm test`.

## Author

--pancake <@nopcode.org>

## IO address values

IO requests encode unsigned 64-bit addresses as hexadecimal strings. Use
`parseAddress` for those strings or legacy numbers/bigints; it returns an exact
`bigint` and rejects invalid syntax, out-of-range values and already-rounded
JavaScript numbers. `parseJson` continues to preserve JSON strings as strings.

```typescript
import { parseAddress, parseJson } from "r2pipe-ts";
const offset = parseAddress("0xffffffffffffffff"); // 18446744073709551615n
const legacy = parseAddress(parseJson("9007199254740993") as bigint);
```
