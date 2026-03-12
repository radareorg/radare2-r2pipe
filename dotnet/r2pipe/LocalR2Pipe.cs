using System.IO.Pipes;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using R2Pipe.Internal;

namespace R2Pipe;

public sealed class LocalR2Pipe : R2PipeBase
{
    private readonly NullDelimitedStreamTransport _transport;

    public LocalR2Pipe(R2PipeOpenOptions? options = null)
        : this(CreateTransportFromEnvironment(), options?.JsonSerializerOptions)
    {
    }

    internal LocalR2Pipe(NullDelimitedStreamTransport transport, JsonSerializerOptions? jsonSerializerOptions = null)
        : base(jsonSerializerOptions)
    {
        _transport = transport;
    }

    public static bool IsAvailable =>
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("R2PIPE_IN")) &&
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("R2PIPE_OUT")) ||
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("R2PIPE_PATH")) ||
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("r2pipe_path"));

    public override Task QuitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    protected override Task<string> CmdCoreAsync(string command, CancellationToken cancellationToken)
    {
        return _transport.ExecuteAsync(command, cancellationToken);
    }

    protected override ValueTask DisposeCoreAsync()
    {
        return _transport.DisposeAsync();
    }

    private static NullDelimitedStreamTransport CreateTransportFromEnvironment()
    {
        if (OperatingSystem.IsWindows())
        {
            var rawPath = Environment.GetEnvironmentVariable("R2PIPE_PATH")
                ?? Environment.GetEnvironmentVariable("r2pipe_path");

            if (string.IsNullOrWhiteSpace(rawPath))
            {
                throw new InvalidOperationException("R2PIPE_PATH is not defined.");
            }

            var pipeName = rawPath.Split('\\', StringSplitOptions.RemoveEmptyEntries)[^1];
            var stream = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            stream.Connect();
            return new NullDelimitedStreamTransport(stream, stream);
        }

        var input = Environment.GetEnvironmentVariable("R2PIPE_IN");
        var output = Environment.GetEnvironmentVariable("R2PIPE_OUT");

        if (!int.TryParse(input, out var inputFd) || !int.TryParse(output, out var outputFd))
        {
            throw new InvalidOperationException("R2PIPE_IN and R2PIPE_OUT must be defined.");
        }

        var readHandle = new SafeFileHandle((IntPtr)inputFd, ownsHandle: false);
        var writeHandle = new SafeFileHandle((IntPtr)outputFd, ownsHandle: false);
        var readStream = new FileStream(readHandle, FileAccess.Read, bufferSize: 4096, isAsync: true);
        var writeStream = new FileStream(writeHandle, FileAccess.Write, bufferSize: 4096, isAsync: true);
        return new NullDelimitedStreamTransport(readStream, writeStream);
    }
}
