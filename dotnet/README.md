# r2pipe for .NET

Modern C# implementation of the r2pipe protocol for `dotnet`.

## Features

- `spawn`: launch `radare2 -q0` and talk to it over stdio
- `http`: connect to `http://host:port` or `http://host:port/cmd/`
- `#!pipe`: attach to the local pipe exported by radare2
- `inprocess`: call `libr_core` directly from C#
- JSON helpers built on `System.Text.Json`

## Requirements

- .NET SDK 10.0 or newer
- `radare2` in `PATH` for spawn tests and normal usage
- `radare2-dev` or an equivalent `libr_core` install for the in-process channel

## Usage

```csharp
using System.Text.Json.Nodes;
using R2Pipe;

await using var r2 = await R2Pipe.R2Pipe.OpenAsync("malloc://128");

await r2.CmdAsync("wx 41424344");
JsonNode? info = await r2.CmdJsonAsync("ij");

Console.WriteLine(info?["core"]?["file"]);
```

Explicit channels are available when you do not want auto-detection:

```csharp
using var native = R2Pipe.R2Pipe.OpenInProcess("malloc://64");
await using var spawned = await R2Pipe.R2Pipe.OpenSpawnAsync("/bin/ls");
await using var http = R2Pipe.R2Pipe.OpenHttp("http://127.0.0.1:9090");
```

## Build and test

```sh
make -C dotnet test
```

Equivalent raw commands:

```sh
dotnet restore dotnet/tests/R2Pipe.Tests/R2Pipe.Tests.csproj
dotnet build dotnet/tests/R2Pipe.Tests/R2Pipe.Tests.csproj --no-restore -p:UseSharedCompilation=false /nr:false
dotnet test dotnet/tests/R2Pipe.Tests/R2Pipe.Tests.csproj --no-build --no-restore -p:UseSharedCompilation=false /nr:false
```
