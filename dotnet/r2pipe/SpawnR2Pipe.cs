using System.Diagnostics;
using System.Text;

namespace R2Pipe;

public sealed class SpawnR2Pipe : R2PipeBase
{
    private readonly Process _process;
    private readonly StreamReader _reader;
    private readonly StreamWriter _writer;
    private readonly StringBuilder _stderr = new();

    private SpawnR2Pipe(Process process, R2PipeOpenOptions options)
        : base(options.JsonSerializerOptions)
    {
        _process = process;
        _reader = process.StandardOutput;
        _writer = process.StandardInput;
        _writer.NewLine = "\n";
        _writer.AutoFlush = true;
        _process.ErrorDataReceived += OnErrorDataReceived;
        _process.BeginErrorReadLine();
    }

    public static async Task<SpawnR2Pipe> OpenAsync(
        string target,
        R2PipeOpenOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);

        var resolvedOptions = options ?? new R2PipeOpenOptions();
        var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        var startInfo = new ProcessStartInfo
        {
            FileName = resolvedOptions.Radare2Path,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardInputEncoding = utf8,
            StandardOutputEncoding = utf8
        };

        if (!string.IsNullOrWhiteSpace(resolvedOptions.WorkingDirectory))
        {
            startInfo.WorkingDirectory = resolvedOptions.WorkingDirectory;
        }

        if (resolvedOptions.UseDefaultRadareArguments)
        {
            startInfo.ArgumentList.Add("-q0");
            startInfo.ArgumentList.Add("-e");
            startInfo.ArgumentList.Add("scr.color=false");
            startInfo.ArgumentList.Add("-e");
            startInfo.ArgumentList.Add("scr.interactive=false");
        }

        foreach (var argument in resolvedOptions.SpawnArguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        startInfo.ArgumentList.Add(target);

        var process = new Process
        {
            StartInfo = startInfo,
            EnableRaisingEvents = true
        };

        if (!process.Start())
        {
            throw new InvalidOperationException("Failed to start radare2.");
        }

        var pipe = new SpawnR2Pipe(process, resolvedOptions);

        try
        {
            await pipe.InitializeAsync(cancellationToken).ConfigureAwait(false);
            return pipe;
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public override async Task QuitAsync(CancellationToken cancellationToken = default)
    {
        if (_process.HasExited)
        {
            return;
        }

        await _writer.WriteLineAsync("q!".AsMemory(), cancellationToken).ConfigureAwait(false);
        await _writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        await _process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task<string> CmdCoreAsync(string command, CancellationToken cancellationToken)
    {
        ThrowIfExited();
        await _writer.WriteLineAsync(command.AsMemory(), cancellationToken).ConfigureAwait(false);
        await _writer.FlushAsync(cancellationToken).ConfigureAwait(false);

        var response = await ReadResponseAsync(cancellationToken).ConfigureAwait(false);

        if (response.Length > 0)
        {
            return response;
        }

        using var probeCancellationSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        probeCancellationSource.CancelAfter(TimeSpan.FromSeconds(1));

        try
        {
            return await ReadResponseAsync(probeCancellationSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return string.Empty;
        }
    }

    protected override async ValueTask DisposeCoreAsync()
    {
        if (!_process.HasExited)
        {
            using var cancellationSource = new CancellationTokenSource(TimeSpan.FromSeconds(2));

            try
            {
                await QuitAsync(cancellationSource.Token).ConfigureAwait(false);
            }
            catch
            {
                if (!_process.HasExited)
                {
                    _process.Kill(entireProcessTree: true);
                    await _process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                }
            }
        }

        _reader.Dispose();
        _writer.Dispose();
        _process.Dispose();
    }

    private async Task InitializeAsync(CancellationToken cancellationToken)
    {
        try
        {
            _ = await ReadResponseAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (EndOfStreamException exception)
        {
            throw new InvalidOperationException(
                $"radare2 terminated before the pipe was ready. {BuildProcessError()}",
                exception);
        }
    }

    private void ThrowIfExited()
    {
        if (_process.HasExited)
        {
            throw new InvalidOperationException($"radare2 is no longer running. {BuildProcessError()}");
        }
    }

    private string BuildProcessError()
    {
        var stderr = _stderr.ToString().Trim();
        return string.IsNullOrEmpty(stderr) ? "No stderr output was captured." : $"stderr: {stderr}";
    }

    private void OnErrorDataReceived(object sender, DataReceivedEventArgs eventArgs)
    {
        if (string.IsNullOrWhiteSpace(eventArgs.Data))
        {
            return;
        }

        lock (_stderr)
        {
            _stderr.AppendLine(eventArgs.Data);
        }
    }

    private async Task<string> ReadResponseAsync(CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();
        var buffer = new char[256];

        while (true)
        {
            var read = await _reader.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);

            if (read == 0)
            {
                throw new EndOfStreamException("The radare2 stdout pipe closed unexpectedly.");
            }

            for (var index = 0; index < read; index++)
            {
                if (buffer[index] == '\0')
                {
                    return builder.ToString();
                }

                builder.Append(buffer[index]);
            }
        }
    }
}
