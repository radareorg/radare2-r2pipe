using System.Net.Http;
namespace R2Pipe;

public sealed class HttpR2Pipe : R2PipeBase
{
    private readonly Uri _commandBaseUri;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsClient;

    public HttpR2Pipe(string target, R2PipeOpenOptions? options = null)
        : this(new Uri(target, UriKind.Absolute), options)
    {
    }

    public HttpR2Pipe(Uri target, R2PipeOpenOptions? options = null)
        : base((options ?? new R2PipeOpenOptions()).JsonSerializerOptions)
    {
        ArgumentNullException.ThrowIfNull(target);

        if (target.Scheme != Uri.UriSchemeHttp && target.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Only HTTP and HTTPS URIs are supported.", nameof(target));
        }

        var resolvedOptions = options ?? new R2PipeOpenOptions();

        _httpClient = resolvedOptions.HttpClient ?? new HttpClient();
        _ownsClient = resolvedOptions.HttpClient is null;
        _commandBaseUri = NormalizeCommandBaseUri(target);
    }

    public override Task QuitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    protected override async Task<string> CmdCoreAsync(string command, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_commandBaseUri, Uri.EscapeDataString(command)));
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override ValueTask DisposeCoreAsync()
    {
        if (_ownsClient)
        {
            _httpClient.Dispose();
        }

        return ValueTask.CompletedTask;
    }

    private static Uri NormalizeCommandBaseUri(Uri uri)
    {
        var builder = new UriBuilder(uri);
        var path = builder.Path.TrimEnd('/');

        if (path.EndsWith("/cmd", StringComparison.OrdinalIgnoreCase))
        {
            path = path[..^4];
        }

        builder.Path = string.IsNullOrEmpty(path) ? "/cmd/" : $"{path}/cmd/";
        return builder.Uri;
    }
}
