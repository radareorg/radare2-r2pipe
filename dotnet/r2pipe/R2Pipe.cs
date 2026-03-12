namespace R2Pipe;

public static class R2Pipe
{
    public static IR2Pipe Open(string? target = null, R2PipeOpenOptions? options = null)
    {
        return OpenAsync(target, options).GetAwaiter().GetResult();
    }

    public static async Task<IR2Pipe> OpenAsync(
        string? target = null,
        R2PipeOpenOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            if (!LocalR2Pipe.IsAvailable)
            {
                throw new InvalidOperationException(
                    "No target was provided and the local r2pipe environment is not available.");
            }

            return OpenLocal(options);
        }

        if (Uri.TryCreate(target, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            return OpenHttp(uri, options);
        }

        return await OpenSpawnAsync(target, options, cancellationToken).ConfigureAwait(false);
    }

    public static Task<SpawnR2Pipe> OpenSpawnAsync(
        string? target = null,
        R2PipeOpenOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        return SpawnR2Pipe.OpenAsync(target ?? "-", options, cancellationToken);
    }

    public static HttpR2Pipe OpenHttp(string target, R2PipeOpenOptions? options = null)
    {
        return new HttpR2Pipe(target, options);
    }

    public static HttpR2Pipe OpenHttp(Uri target, R2PipeOpenOptions? options = null)
    {
        return new HttpR2Pipe(target, options);
    }

    public static LocalR2Pipe OpenLocal(R2PipeOpenOptions? options = null)
    {
        return new LocalR2Pipe(options);
    }

    public static InProcessR2Pipe OpenInProcess(string? target = null, R2PipeOpenOptions? options = null)
    {
        return new InProcessR2Pipe(target, options);
    }
}
