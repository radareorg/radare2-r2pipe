using System.Text.Json.Nodes;

namespace R2Pipe.Tests;

public sealed class HttpR2PipeTests
{
    [Fact]
    public async Task HttpChannelNormalizesCmdBasePath()
    {
        await using var server = await TestHttpServer.StartAsync(path =>
        {
            return path == "/cmd/%3FVj"
                ? "{\"version\":\"6.1.1\"}"
                : throw new InvalidOperationException($"Unexpected path: {path}");
        });

        await using var pipe = R2Pipe.OpenHttp($"{server.BaseUri}cmd/");
        var version = await pipe.CmdJsonAsync<JsonObject>("?Vj");

        Assert.Equal("/cmd/%3FVj", server.LastRequestPath);
        Assert.Equal("6.1.1", version?["version"]?.GetValue<string>());
    }

    [Fact]
    public async Task FactoryUsesHttpChannelForHttpTargets()
    {
        await using var server = await TestHttpServer.StartAsync(_ => "{\"status\":\"ok\"}");

        await using IR2Pipe pipe = await R2Pipe.OpenAsync(server.BaseUri.ToString());
        var payload = await pipe.CmdJsonAsync<JsonObject>("?Vj");

        Assert.Equal("ok", payload?["status"]?.GetValue<string>());
    }
}
