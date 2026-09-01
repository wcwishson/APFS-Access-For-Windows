using System.ComponentModel;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

internal sealed record PackagedServiceFileIdentity(
    string CanonicalPath,
    long Length,
    string Sha256,
    string LaunchIdentity);

internal sealed record PackagedServicePackageIdentity(
    PackagedServiceFileIdentity AppHost,
    IReadOnlyList<PackagedServiceFileIdentity> Companions);

internal sealed class PackagedServicePackageLease : IDisposable
{
    private const string ReservedDevelopmentRuntimeConfig =
        "{\"runtimeOptions\":{\"additionalProbingPaths\":[]}}";
    private readonly IReadOnlyList<FileStream> _leases;

    private PackagedServicePackageLease(
        PackagedServicePackageIdentity identity,
        IReadOnlyList<FileStream> leases)
    {
        Identity = identity;
        _leases = leases;
    }

    internal PackagedServicePackageIdentity Identity { get; }

    internal IReadOnlyList<SafeFileHandle> LeaseHandles
        => _leases.Select(static lease => lease.SafeFileHandle).ToArray();

    internal static PackagedServicePackageLease Acquire(string applicationPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Packaged service identity leases require Windows.");
        }

        var requestedPath = Path.GetFullPath(applicationPath);
        if (!string.Equals(Path.GetExtension(requestedPath), ".exe", StringComparison.OrdinalIgnoreCase) ||
            Path.GetFileName(requestedPath).Contains(':', StringComparison.Ordinal))
        {
            throw new CliElevationValidationException("Packaged service startup requires an exact executable apphost path.");
        }

        var leases = new List<FileStream>();
        try
        {
            var identities = new List<PackagedServiceFileIdentity>();
            var appHost = OpenAndCapture(requestedPath, leases);
            identities.Add(appHost);
            var packageRoot = Path.GetDirectoryName(appHost.CanonicalPath)
                ?? throw new CliElevationValidationException("The packaged service directory is unavailable.");
            if (!string.Equals(requestedPath, appHost.CanonicalPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new CliElevationValidationException("The packaged service apphost path is aliased or reparsed.");
            }

            var baseName = Path.GetFileNameWithoutExtension(appHost.CanonicalPath);
            var depsPath = Path.Combine(packageRoot, baseName + ".deps.json");
            var requiredPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                Path.Combine(packageRoot, baseName + ".dll"),
                depsPath,
                Path.Combine(packageRoot, baseName + ".runtimeconfig.json"),
            };
            var developmentRuntimeConfig = Path.Combine(packageRoot, baseName + ".runtimeconfig.dev.json");
            if (baseName.StartsWith("ApfsAccess.", StringComparison.OrdinalIgnoreCase))
            {
                ReserveDevelopmentRuntimeConfig(developmentRuntimeConfig, leases);
            }
            else if (File.Exists(developmentRuntimeConfig))
            {
                throw new CliElevationValidationException("Development probing paths are not permitted for packaged service startup.");
            }

            foreach (var requiredPath in requiredPaths.OrderBy(static path => path, StringComparer.OrdinalIgnoreCase))
            {
                identities.Add(OpenAndCaptureRequired(requiredPath, leases));
            }

            var depsLease = leases.Single(lease =>
                string.Equals(GetCanonicalPath(lease.SafeFileHandle), depsPath, StringComparison.OrdinalIgnoreCase));
            foreach (var assetPath in ReadRequiredPackageAssets(depsLease, packageRoot))
            {
                if (requiredPaths.Add(assetPath))
                {
                    identities.Add(OpenAndCaptureRequired(assetPath, leases));
                }
            }

            foreach (var settingsName in new[] { "appsettings.json", "appsettings.Development.json" })
            {
                var settingsPath = Path.Combine(packageRoot, settingsName);
                if (File.Exists(settingsPath) && requiredPaths.Add(settingsPath))
                {
                    identities.Add(OpenAndCaptureRequired(settingsPath, leases));
                }
            }

            var companions = identities
                .Skip(1)
                .OrderBy(static identity => identity.CanonicalPath, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return new PackagedServicePackageLease(
                new PackagedServicePackageIdentity(appHost, companions),
                leases);
        }
        catch (Exception primaryException)
        {
            try
            {
                DisposeLeases(leases);
            }
            catch (Exception cleanupException)
            {
                throw new CliElevationUnsafeOwnershipException(
                    "The rejected packaged service package could not release every identity lease.",
                    new AggregateException(primaryException, cleanupException));
            }

            ExceptionDispatchInfo.Capture(primaryException).Throw();
            throw;
        }
    }

    public void Dispose() => DisposeLeases(_leases);

    internal void Revalidate()
    {
        var expectedIdentities = new[] { Identity.AppHost }
            .Concat(Identity.Companions)
            .ToArray();
        foreach (var expected in expectedIdentities)
        {
            var lease = _leases.SingleOrDefault(candidate =>
                string.Equals(
                    GetCanonicalPath(candidate.SafeFileHandle),
                    expected.CanonicalPath,
                    StringComparison.OrdinalIgnoreCase));
            if (lease is null)
            {
                throw new CliElevationValidationException(
                    $"The packaged service identity lease for '{expected.CanonicalPath}' is missing.");
            }

            var observed = CaptureIdentity(lease);
            if (!string.Equals(observed.CanonicalPath, expected.CanonicalPath, StringComparison.OrdinalIgnoreCase) ||
                observed.Length != expected.Length ||
                !string.Equals(observed.Sha256, expected.Sha256, StringComparison.Ordinal) ||
                !string.Equals(observed.LaunchIdentity, expected.LaunchIdentity, StringComparison.Ordinal))
            {
                throw new CliElevationValidationException(
                    $"The packaged service file '{expected.CanonicalPath}' changed before process resume.");
            }
        }
    }

    private static void ReserveDevelopmentRuntimeConfig(
        string path,
        ICollection<FileStream> leases)
    {
        FileStream? reservation = null;
        Exception? validationException = null;
        try
        {
            reservation = new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.Read,
                bufferSize: 4 * 1024,
                FileOptions.DeleteOnClose | FileOptions.WriteThrough);
            using var writer = new StreamWriter(reservation, new UTF8Encoding(false), leaveOpen: true);
            writer.Write(ReservedDevelopmentRuntimeConfig);
            writer.Flush();
            reservation.Flush(flushToDisk: true);
            reservation.Position = 0;
            leases.Add(reservation);
            reservation = null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            validationException = new CliElevationValidationException(
                $"Development probing paths are not permitted for packaged service startup: {ex.Message}");
        }
        finally
        {
            if (reservation is not null)
            {
                try
                {
                    reservation.Dispose();
                }
                catch (Exception cleanupException) when (validationException is not null)
                {
                    throw new CliElevationUnsafeOwnershipException(
                        "The rejected development runtime configuration reservation could not be released.",
                        new AggregateException(validationException, cleanupException));
                }
            }
        }

        if (validationException is not null)
        {
            ExceptionDispatchInfo.Capture(validationException).Throw();
        }
    }

    private static PackagedServiceFileIdentity OpenAndCaptureRequired(
        string path,
        ICollection<FileStream> leases)
    {
        try
        {
            return OpenAndCapture(path, leases);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            throw new CliElevationValidationException($"The packaged service companion '{path}' is missing.");
        }
    }

    private static PackagedServiceFileIdentity OpenAndCapture(
        string path,
        ICollection<FileStream> leases)
    {
        var requestedPath = Path.GetFullPath(path);
        var lease = new FileStream(
            requestedPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.SequentialScan);
        try
        {
            var canonicalPath = GetCanonicalPath(lease.SafeFileHandle);
            if (!string.Equals(requestedPath, canonicalPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new CliElevationValidationException($"The packaged service file '{requestedPath}' is aliased or reparsed.");
            }

            leases.Add(lease);
            return CaptureIdentity(lease);
        }
        catch (Exception primaryException)
        {
            try
            {
                lease.Dispose();
            }
            catch (Exception cleanupException)
            {
                throw new CliElevationUnsafeOwnershipException(
                    $"The rejected package file lease for '{requestedPath}' could not be released.",
                    new AggregateException(primaryException, cleanupException));
            }

            ExceptionDispatchInfo.Capture(primaryException).Throw();
            throw;
        }
    }

    private static PackagedServiceFileIdentity CaptureIdentity(FileStream lease)
    {
        var canonicalPath = GetCanonicalPath(lease.SafeFileHandle);
        lease.Position = 0;
        var sha256 = Convert.ToHexString(SHA256.HashData(lease));
        lease.Position = 0;
        if (!GetFileInformationByHandle(lease.SafeFileHandle, out var information))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Could not capture the package file ID for '{canonicalPath}'.");
        }

        if (information.NumberOfLinks != 1)
        {
            throw new CliElevationValidationException(
                $"The packaged service file '{canonicalPath}' is hard-linked and cannot be launched unambiguously.");
        }

        var launchIdentity =
            $"{information.VolumeSerialNumber:X8}:{information.FileIndexHigh:X8}{information.FileIndexLow:X8}";
        return new PackagedServiceFileIdentity(canonicalPath, lease.Length, sha256, launchIdentity);
    }

    private static IReadOnlyList<string> ReadRequiredPackageAssets(FileStream depsLease, string packageRoot)
    {
        depsLease.Position = 0;
        using var document = JsonDocument.Parse(depsLease);
        depsLease.Position = 0;
        if (!document.RootElement.TryGetProperty("runtimeTarget", out var runtimeTarget) ||
            !runtimeTarget.TryGetProperty("name", out var targetNameElement) ||
            string.IsNullOrWhiteSpace(targetNameElement.GetString()) ||
            !document.RootElement.TryGetProperty("targets", out var targets) ||
            !targets.TryGetProperty(targetNameElement.GetString()!, out var target))
        {
            throw new CliElevationValidationException("The packaged service dependency manifest is incomplete.");
        }

        var assets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var library in target.EnumerateObject())
        {
            AddAssets(library.Value, "runtime", packageRoot, assets, required: true);
            AddAssets(library.Value, "native", packageRoot, assets, required: true);
            AddAssets(library.Value, "runtimeTargets", packageRoot, assets, required: true);
            AddAssets(library.Value, "resources", packageRoot, assets, required: false);
        }

        return assets.OrderBy(static path => path, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void AddAssets(
        JsonElement library,
        string sectionName,
        string packageRoot,
        ISet<string> assets,
        bool required)
    {
        if (!library.TryGetProperty(sectionName, out var section) || section.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var asset in section.EnumerateObject())
        {
            if (string.Equals(asset.Name, "_._", StringComparison.Ordinal))
            {
                continue;
            }

            var resolved = ResolvePackageAsset(packageRoot, asset.Name);
            if (resolved is not null)
            {
                assets.Add(resolved);
            }
            else if (required)
            {
                throw new CliElevationValidationException(
                    $"The packaged service dependency '{asset.Name}' is missing from the adjacent package.");
            }
        }
    }

    private static string? ResolvePackageAsset(string packageRoot, string assetName)
    {
        if (Path.IsPathRooted(assetName))
        {
            throw new CliElevationValidationException("The packaged service manifest contains a rooted dependency path.");
        }

        var directPath = Path.GetFullPath(
            Path.Combine(packageRoot, assetName.Replace('/', Path.DirectorySeparatorChar)));
        EnsureUnderPackageRoot(packageRoot, directPath);
        if (File.Exists(directPath))
        {
            return directPath;
        }

        var fileName = Path.GetFileName(assetName);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new CliElevationValidationException("The packaged service manifest contains an invalid dependency path.");
        }

        var flattenedPath = Path.Combine(packageRoot, fileName);
        return File.Exists(flattenedPath) ? flattenedPath : null;
    }

    private static void EnsureUnderPackageRoot(string packageRoot, string path)
    {
        var relative = Path.GetRelativePath(packageRoot, path);
        if (Path.IsPathRooted(relative) ||
            string.Equals(relative, "..", StringComparison.Ordinal) ||
            relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new CliElevationValidationException("The packaged service manifest escapes its package directory.");
        }
    }

    private static string GetCanonicalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (capacity <= 32_768)
        {
            var builder = new StringBuilder(capacity);
            var length = GetFinalPathNameByHandle(handle, builder, builder.Capacity, 0);
            if (length == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not resolve a canonical package path.");
            }

            if (length < builder.Capacity)
            {
                var path = builder.ToString();
                if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    return @"\\" + path[8..];
                }

                return path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ? path[4..] : path;
            }

            capacity = checked((int)length + 1);
        }

        throw new CliElevationValidationException("The canonical packaged service path is too long.");
    }

    private static void DisposeLeases(IEnumerable<FileStream> leases)
        => DisposeAllForTest(leases.Cast<IDisposable>());

    internal static void DisposeAllForTest(IEnumerable<IDisposable> leases)
    {
        List<Exception>? failures = null;
        foreach (var lease in leases.Reverse())
        {
            try
            {
                lease.Dispose();
            }
            catch (Exception ex)
            {
                failures ??= [];
                failures.Add(ex);
            }
        }

        if (failures is not null)
        {
            throw new AggregateException("One or more package identity leases could not be released.", failures);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        int filePathLength,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);
}
