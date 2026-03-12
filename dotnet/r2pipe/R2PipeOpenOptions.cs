using System.Text.Json;

namespace R2Pipe;

public sealed record R2PipeOpenOptions
{
    public string Radare2Path { get; init; } = "radare2";

    public bool UseDefaultRadareArguments { get; init; } = true;

    public string? WorkingDirectory { get; init; }

    public IReadOnlyList<string> SpawnArguments { get; init; } = [];

    public JsonSerializerOptions JsonSerializerOptions { get; init; } = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };

    public HttpClient? HttpClient { get; init; }

    public string? NativeLibraryPath { get; init; }
}
