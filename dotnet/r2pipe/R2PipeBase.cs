using System.Text.Json;
using System.Text.Json.Nodes;

namespace R2Pipe;

public abstract class R2PipeBase : IR2Pipe
{
    private readonly SemaphoreSlim _commandGate = new(1, 1);
    private int _disposed;

    protected R2PipeBase(JsonSerializerOptions? jsonSerializerOptions = null)
    {
        JsonSerializerOptions = jsonSerializerOptions is null
            ? CreateDefaultJsonSerializerOptions()
            : new JsonSerializerOptions(jsonSerializerOptions);
    }

    protected JsonSerializerOptions JsonSerializerOptions { get; }

    protected bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    public string Cmd(string command) => CmdAsync(command).GetAwaiter().GetResult();

    public async Task<string> CmdAsync(string command, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ArgumentNullException.ThrowIfNull(command);

        await _commandGate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            return await CmdCoreAsync(NormalizeCommand(command), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _commandGate.Release();
        }
    }

    public JsonNode? CmdJson(string command) => CmdJsonAsync(command).GetAwaiter().GetResult();

    public async Task<JsonNode?> CmdJsonAsync(string command, CancellationToken cancellationToken = default)
    {
        var payload = await CmdAsync(command, cancellationToken).ConfigureAwait(false);

        try
        {
            return JsonNode.Parse(payload);
        }
        catch (JsonException exception)
        {
            throw new JsonException($"Failed to parse JSON output for command '{command}'.", exception);
        }
    }

    public T? CmdJson<T>(string command) => CmdJsonAsync<T>(command).GetAwaiter().GetResult();

    public async Task<T?> CmdJsonAsync<T>(string command, CancellationToken cancellationToken = default)
    {
        var payload = await CmdAsync(command, cancellationToken).ConfigureAwait(false);

        try
        {
            return JsonSerializer.Deserialize<T>(payload, JsonSerializerOptions);
        }
        catch (JsonException exception)
        {
            throw new JsonException($"Failed to parse JSON output for command '{command}'.", exception);
        }
    }

    public abstract Task QuitAsync(CancellationToken cancellationToken = default);

    protected abstract Task<string> CmdCoreAsync(string command, CancellationToken cancellationToken);

    protected abstract ValueTask DisposeCoreAsync();

    public void Dispose()
    {
        DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await DisposeCoreAsync().ConfigureAwait(false);
        _commandGate.Dispose();
        GC.SuppressFinalize(this);
    }

    private static JsonSerializerOptions CreateDefaultJsonSerializerOptions() => new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };

    private static string NormalizeCommand(string command) => command.ReplaceLineEndings(";");
}
