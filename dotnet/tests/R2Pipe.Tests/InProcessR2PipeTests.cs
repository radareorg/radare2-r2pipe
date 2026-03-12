using System.Text.Json.Nodes;

namespace R2Pipe.Tests;

public sealed class InProcessR2PipeTests
{
    [Fact]
    public async Task InProcessChannelRunsCommands()
    {
        Assert.True(InProcessR2Pipe.IsAvailable, "libr_core is required for the in-process backend.");

        using var pipe = R2Pipe.OpenInProcess("malloc://4");
        var info = await pipe.CmdJsonAsync<JsonObject>("ij");

        Assert.Equal("malloc://4", info?["core"]?["file"]?.GetValue<string>());
    }
}
