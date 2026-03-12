using System.Text.Json.Nodes;

namespace R2Pipe;

public interface IR2Pipe : IDisposable, IAsyncDisposable
{
    string Cmd(string command);

    Task<string> CmdAsync(string command, CancellationToken cancellationToken = default);

    JsonNode? CmdJson(string command);

    Task<JsonNode?> CmdJsonAsync(string command, CancellationToken cancellationToken = default);

    T? CmdJson<T>(string command);

    Task<T?> CmdJsonAsync<T>(string command, CancellationToken cancellationToken = default);

    Task QuitAsync(CancellationToken cancellationToken = default);
}
