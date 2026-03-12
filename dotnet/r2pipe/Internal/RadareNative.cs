using System.Runtime.InteropServices;

namespace R2Pipe.Internal;

internal sealed class RadareNative : IDisposable
{
    private static readonly string[] CoreLibraryCandidates = GetLibraryCandidates(
        windowsNames: ["libr_core.dll", "r_core.dll"],
        unixNames: ["libr_core.dylib", "libr_core.so", "libr_core"]);

    private static readonly string[] UtilLibraryCandidates = GetLibraryCandidates(
        windowsNames: ["libr_util.dll", "r_util.dll"],
        unixNames: ["libr_util.dylib", "libr_util.so", "libr_util"]);

    private readonly nint _coreHandle;
    private readonly nint _utilHandle;
    private readonly RCoreNewDelegate _rCoreNew;
    private readonly RCoreFreeDelegate _rCoreFree;
    private readonly RCoreCmdStrDelegate _rCoreCmdStr;
    private readonly RMemFreeDelegate _rMemFree;

    private RadareNative(nint coreHandle, nint utilHandle)
    {
        _coreHandle = coreHandle;
        _utilHandle = utilHandle;
        _rCoreNew = GetDelegate<RCoreNewDelegate>(_coreHandle, "r_core_new");
        _rCoreFree = GetDelegate<RCoreFreeDelegate>(_coreHandle, "r_core_free");
        _rCoreCmdStr = GetDelegate<RCoreCmdStrDelegate>(_coreHandle, "r_core_cmd_str");
        _rMemFree = GetDelegate<RMemFreeDelegate>(_utilHandle, "r_mem_free");
    }

    public static bool IsAvailable
    {
        get
        {
            try
            {
                using var native = Load();
                return native._coreHandle != nint.Zero;
            }
            catch
            {
                return false;
            }
        }
    }

    public static RadareNative Load(string? preferredCoreLibraryPath = null)
    {
        if (!TryLoadLibrary(preferredCoreLibraryPath, CoreLibraryCandidates, out var coreHandle, out var corePath))
        {
            throw new DllNotFoundException("Unable to locate libr_core.");
        }

        var utilPreferredPath = BuildSiblingLibraryPath(corePath, OperatingSystem.IsWindows()
            ? "libr_util.dll"
            : OperatingSystem.IsMacOS()
                ? "libr_util.dylib"
                : "libr_util.so");

        if (!TryLoadLibrary(utilPreferredPath, UtilLibraryCandidates, out var utilHandle, out _))
        {
            NativeLibrary.Free(coreHandle);
            throw new DllNotFoundException("Unable to locate libr_util.");
        }

        return new RadareNative(coreHandle, utilHandle);
    }

    public IntPtr NewCore() => _rCoreNew();

    public void FreeCore(IntPtr core) => _rCoreFree(core);

    public string CmdStr(IntPtr core, string command)
    {
        var pointer = _rCoreCmdStr(core, command);

        try
        {
            return Marshal.PtrToStringUTF8(pointer) ?? string.Empty;
        }
        finally
        {
            if (pointer != IntPtr.Zero)
            {
                _rMemFree(pointer);
            }
        }
    }

    public void Dispose()
    {
        if (_utilHandle != nint.Zero)
        {
            NativeLibrary.Free(_utilHandle);
        }

        if (_coreHandle != nint.Zero)
        {
            NativeLibrary.Free(_coreHandle);
        }
    }

    private static string? BuildSiblingLibraryPath(string? corePath, string libraryName)
    {
        if (string.IsNullOrWhiteSpace(corePath) || !Path.IsPathRooted(corePath))
        {
            return null;
        }

        var directory = Path.GetDirectoryName(corePath);
        return directory is null ? null : Path.Combine(directory, libraryName);
    }

    private static bool TryLoadLibrary(
        string? preferredPath,
        IReadOnlyList<string> fallbackCandidates,
        out nint handle,
        out string? loadedPath)
    {
        if (!string.IsNullOrWhiteSpace(preferredPath) && NativeLibrary.TryLoad(preferredPath, out handle))
        {
            loadedPath = preferredPath;
            return true;
        }

        foreach (var candidate in fallbackCandidates)
        {
            if (NativeLibrary.TryLoad(candidate, out handle))
            {
                loadedPath = candidate;
                return true;
            }
        }

        handle = nint.Zero;
        loadedPath = null;
        return false;
    }

    private static string[] GetLibraryCandidates(string[] windowsNames, string[] unixNames)
    {
        if (OperatingSystem.IsWindows())
        {
            return windowsNames;
        }

        var names = new List<string>(unixNames);
        string[] directories =
        [
            "/usr/local/lib",
            "/usr/lib",
            "/lib",
            "/opt/homebrew/lib"
        ];

        foreach (var directory in directories)
        {
            foreach (var name in unixNames)
            {
                var candidate = Path.Combine(directory, name);

                if (File.Exists(candidate))
                {
                    names.Add(candidate);
                }
            }
        }

        return [.. names.Distinct(StringComparer.Ordinal)];
    }

    private static T GetDelegate<T>(nint libraryHandle, string exportName)
        where T : Delegate
    {
        var export = NativeLibrary.GetExport(libraryHandle, exportName);
        return Marshal.GetDelegateForFunctionPointer<T>(export);
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr RCoreNewDelegate();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void RCoreFreeDelegate(IntPtr core);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr RCoreCmdStrDelegate(
        IntPtr core,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string command);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void RMemFreeDelegate(IntPtr pointer);
}
