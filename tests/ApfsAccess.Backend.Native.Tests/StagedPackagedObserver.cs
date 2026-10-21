using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ApfsAccess.Backend.Native.Tests;

// Stages the stable observer binary under the test host base directory so
// provenance treats it as packaged (trusted). Each tag gets its own
// subdirectory so parallel tests never share (or overwrite) a running
// image. Always re-copies so staged bytes never go stale across rebuilds.
internal static class StagedPackagedObserver
{
    private static readonly object Sync = new();

    // Locates the stable observer binary built from this repo (same walk as
    // the integration tests; fails instead of skipping when absent).
    public static string StableObserverPath()
    {
        if (Environment.GetEnvironmentVariable("APFS_VERIFY_TEST_OBSERVER") is { Length: > 0 } explicitInput)
        {
            if (!Path.IsPathFullyQualified(explicitInput) || !File.Exists(explicitInput))
                throw new InvalidOperationException("The explicit observer input is unavailable.");
            return explicitInput;
        }
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var level = 0; level < 14 && directory is not null; level++)
        {
            var candidate = Path.Combine(
                directory.FullName, "build", "ApfsAccess.ApfsRwEngine", "Release", "ApfsObserver.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            "Integration requires build/ApfsAccess.ApfsRwEngine/Release/ApfsObserver.exe; refusing to skip.");
    }

    // Stages the stable repo-built observer under a per-tag packaged path.
    public static string StageStable(string tag) => Stage(StableObserverPath(), tag);

    public static string Stage(string realObserverPath, string tag)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(realObserverPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(tag);
        if (!File.Exists(realObserverPath))
        {
            throw new InvalidOperationException(
                $"Cannot stage packaged observer: not found: {realObserverPath}");
        }

        lock (Sync)
        {
            var dir = Path.Combine(AppContext.BaseDirectory, "staged-packaged-observer", tag);
            Directory.CreateDirectory(dir);
            var staged = Path.Combine(dir, "ApfsObserver.exe");
            if (OperatingSystem.IsWindows() && Environment.GetEnvironmentVariable("APFS_VERIFY_TEST_OBSERVER") is { Length: > 0 })
            {
                if (File.Exists(staged))
                {
                    using var source = File.OpenRead(realObserverPath);
                    using var existing = File.OpenRead(staged);
                    if (!SHA256.HashData(source).AsSpan().SequenceEqual(SHA256.HashData(existing)))
                        throw new InvalidOperationException("Staged explicit observer input drifted.");
                }
                else if (!CreateHardLink(staged, realObserverPath, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            else File.Copy(realObserverPath, staged, overwrite: true);
            return staged;
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLink(string path, string existing, IntPtr reserved);
}
