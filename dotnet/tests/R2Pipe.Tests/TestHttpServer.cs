using System.Net;
using System.Net.Sockets;
using System.Text;

namespace R2Pipe.Tests;

internal sealed class TestHttpServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly Func<string, string> _responseFactory;
    private readonly CancellationTokenSource _cancellationTokenSource = new();
    private readonly Task _acceptLoopTask;

    private TestHttpServer(TcpListener listener, Func<string, string> responseFactory)
    {
        _listener = listener;
        _responseFactory = responseFactory;
        var port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        BaseUri = new Uri($"http://127.0.0.1:{port}/", UriKind.Absolute);
        _acceptLoopTask = AcceptLoopAsync(_cancellationTokenSource.Token);
    }

    public Uri BaseUri { get; }

    public string? LastRequestPath { get; private set; }

    public static Task<TestHttpServer> StartAsync(Func<string, string> responseFactory)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return Task.FromResult(new TestHttpServer(listener, responseFactory));
    }

    public async ValueTask DisposeAsync()
    {
        _cancellationTokenSource.Cancel();
        _listener.Stop();

        try
        {
            await _acceptLoopTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }

        _cancellationTokenSource.Dispose();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            _ = Task.Run(() => HandleClientAsync(client, cancellationToken), cancellationToken);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using var _ = client;
        await using var stream = client.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);

        var requestLine = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(requestLine))
        {
            return;
        }

        var requestParts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        LastRequestPath = requestParts.Length > 1 ? requestParts[1] : "/";

        while (!string.IsNullOrEmpty(await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false)))
        {
        }

        var body = _responseFactory(LastRequestPath);
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        var headers =
            $"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {bodyBytes.Length}\r\nConnection: close\r\n\r\n";

        await stream.WriteAsync(Encoding.ASCII.GetBytes(headers), cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bodyBytes, cancellationToken).ConfigureAwait(false);
    }
}
