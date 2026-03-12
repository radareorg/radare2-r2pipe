using R2Pipe.Internal;

namespace R2Pipe;

public sealed class InProcessR2Pipe : R2PipeBase
{
    private readonly RadareNative _native;
    private readonly IntPtr _core;

    public InProcessR2Pipe(string? target = null, R2PipeOpenOptions? options = null)
        : base((options ?? new R2PipeOpenOptions()).JsonSerializerOptions)
    {
        var resolvedOptions = options ?? new R2PipeOpenOptions();
        _native = RadareNative.Load(resolvedOptions.NativeLibraryPath);
        _core = _native.NewCore();

        if (_core == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to create an r_core instance.");
        }

        if (!string.IsNullOrWhiteSpace(target))
        {
            _ = _native.CmdStr(_core, $"o {QuoteTarget(target)}");
        }
    }

    public static bool IsAvailable => RadareNative.IsAvailable;

    public override Task QuitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    protected override Task<string> CmdCoreAsync(string command, CancellationToken cancellationToken)
    {
        return Task.FromResult(_native.CmdStr(_core, command));
    }

    protected override ValueTask DisposeCoreAsync()
    {
        if (_core != IntPtr.Zero)
        {
            _native.FreeCore(_core);
        }

        _native.Dispose();
        return ValueTask.CompletedTask;
    }

    private static string QuoteTarget(string target)
    {
        var escaped = target.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
        return $"\"{escaped}\"";
    }
}
