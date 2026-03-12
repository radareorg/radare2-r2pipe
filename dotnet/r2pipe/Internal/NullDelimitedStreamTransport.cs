using System.Buffers;
using System.Text;

namespace R2Pipe.Internal;

internal sealed class NullDelimitedStreamTransport : IAsyncDisposable, IDisposable
{
    private readonly Stream _input;
    private readonly Stream _output;
    private readonly bool _ownsInput;
    private readonly bool _ownsOutput;
    private readonly Encoding _encoding;
    private byte[] _leftover = [];

    public NullDelimitedStreamTransport(
        Stream input,
        Stream output,
        bool ownsInput = true,
        bool ownsOutput = true,
        Encoding? encoding = null)
    {
        _input = input;
        _output = output;
        _ownsInput = ownsInput;
        _ownsOutput = ownsOutput;
        _encoding = encoding ?? new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
    }

    public async Task<string> ExecuteAsync(string command, CancellationToken cancellationToken)
    {
        await WriteCommandAsync(command, cancellationToken).ConfigureAwait(false);

        var frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);

        while (frame.Length == 0 && _leftover.Length > 0)
        {
            frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
        }

        if (frame.Length == 0)
        {
            using var probeCancellationSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            probeCancellationSource.CancelAfter(TimeSpan.FromSeconds(1));

            try
            {
                frame = await ReadFrameAsync(probeCancellationSource.Token).ConfigureAwait(false);

                while (frame.Length == 0 && _leftover.Length > 0)
                {
                    frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return string.Empty;
            }
        }

        return frame;
    }

    public async Task WriteCommandAsync(string command, CancellationToken cancellationToken)
    {
        var payload = _encoding.GetBytes($"{command}\n");
        await _output.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await _output.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<string> ReadFrameAsync(CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();

        if (TryDrainLeftover(buffer, out var frame))
        {
            return frame;
        }

        var rented = ArrayPool<byte>.Shared.Rent(4096);

        try
        {
            while (true)
            {
                var read = await _input.ReadAsync(rented.AsMemory(0, rented.Length), cancellationToken).ConfigureAwait(false);

                if (read == 0)
                {
                    throw new EndOfStreamException("The r2pipe stream closed before the response finished.");
                }

                if (TryAppendSegment(buffer, rented.AsSpan(0, read), out frame))
                {
                    return frame;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    public void Dispose()
    {
        DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    public async ValueTask DisposeAsync()
    {
        if (_ownsInput)
        {
            await _input.DisposeAsync().ConfigureAwait(false);
        }

        if (_ownsOutput && !ReferenceEquals(_input, _output))
        {
            await _output.DisposeAsync().ConfigureAwait(false);
        }
    }

    private bool TryDrainLeftover(MemoryStream buffer, out string frame)
    {
        frame = string.Empty;

        if (_leftover.Length == 0)
        {
            return false;
        }

        var completed = TryAppendSegment(buffer, _leftover, out frame);

        if (!completed)
        {
            _leftover = [];
        }

        return completed;
    }

    private bool TryAppendSegment(MemoryStream buffer, ReadOnlySpan<byte> segment, out string frame)
    {
        var terminatorIndex = segment.IndexOf((byte)0);

        if (terminatorIndex < 0)
        {
            buffer.Write(segment);
            frame = string.Empty;
            return false;
        }

        if (terminatorIndex > 0)
        {
            buffer.Write(segment[..terminatorIndex]);
        }

        var remainder = segment[(terminatorIndex + 1)..];
        _leftover = remainder.TrimStart((byte)0).ToArray();
        frame = _encoding.GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length));
        return true;
    }
}
