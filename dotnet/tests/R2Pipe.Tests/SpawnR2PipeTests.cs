using System.Text.Json.Nodes;

namespace R2Pipe.Tests;

public sealed class SpawnR2PipeTests
{
    private static readonly R2PipeOpenOptions MockSpawnOptions = new()
    {
        Radare2Path = "python3",
        UseDefaultRadareArguments = false,
        SpawnArguments =
        [
            "-u",
            "-c",
            """
import sys
sys.stdout.write("\0")
sys.stdout.flush()
for line in sys.stdin:
    command = line.rstrip("\n")
    if command == "q!":
        break
    if command == "?e hello":
        sys.stdout.write("hello\n\0")
    elif command == "ij":
        sys.stdout.write("{\"core\":{\"file\":\"mock://file\"}}\n\0")
    else:
        sys.stdout.write(f"unsupported:{command}\0")
    sys.stdout.flush()
"""
        ]
    };

    [Fact]
    public async Task SpawnChannelRunsCommands()
    {
        var pipe = await R2Pipe.OpenSpawnAsync("mock://file", MockSpawnOptions).WaitAsync(TimeSpan.FromSeconds(5));

        try
        {
            var result = await pipe.CmdAsync("?e hello").WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal("hello", result.Trim());
        }
        finally
        {
            await pipe.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public async Task SpawnChannelParsesJson()
    {
        var pipe = await R2Pipe.OpenAsync("mock://file", MockSpawnOptions).WaitAsync(TimeSpan.FromSeconds(5));

        try
        {
            var info = await pipe.CmdJsonAsync<JsonObject>("ij").WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal("mock://file", info?["core"]?["file"]?.GetValue<string>());
        }
        finally
        {
            await pipe.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        }
    }
}
