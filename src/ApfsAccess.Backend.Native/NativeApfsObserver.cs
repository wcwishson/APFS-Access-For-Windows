using System.Diagnostics;
using System.Globalization;
using System.IO;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

// Task-1 native catalog evidence seam (managed side consumes observer JSON
// opaquely; no managed APFS byte parsing here).
internal sealed record ObserverRunResult(int ExitCode, string StandardOutput, string StandardError);

internal interface IObserverRunner
{
    ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments);
}

internal sealed class ProcessObserverRunner : IObserverRunner
{
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(60);

    public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(observerPath);
        ArgumentNullException.ThrowIfNull(arguments);

        var psi = new ProcessStartInfo
        {
            FileName = observerPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(observerPath) ?? AppContext.BaseDirectory,
        };
        foreach (var argument in arguments)
        {
            psi.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = psi };
        process.Start();
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        if (!process.WaitForExit((int)Math.Min(Timeout.TotalMilliseconds, int.MaxValue)))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
            }

            throw new TimeoutException(
                $"ApfsObserver.exe did not exit within {Timeout.TotalSeconds} seconds.");
        }

        return new ObserverRunResult(process.ExitCode, stdout, stderr);
    }
}

// Opaque catalog attachment selected for one legacy discovered volume.
internal sealed record CatalogAttachment(
    ulong VolumeObjectId,
    string? ContainerUuidHex,
    string CatalogVolumeId,
    ApfsCapabilityDecision Decision,
    IReadOnlyList<string> Reasons,
    bool AutoMountAllowed);

internal static class NativeApfsObserver
{
    public const string ObserverExeName = "ApfsObserver.exe";
    public const string PathOverrideVariable = "APFS_OBSERVER_PATH";
    public const string DiscoveryProfile = "managed-discovery";

    // Search order: APFS_OBSERVER_PATH env (wins) -> configured
    // NativeObserverPath -> AppContext.BaseDirectory/ApfsObserver.exe ->
    // BaseDirectory/native/ -> repo build output
    // build/ApfsAccess.ApfsRwEngine/Release/ -> artifacts/native/Release ->
    // artifacts/native/Debug (ancestor walk, mirroring the FsHost search).
    internal static string? ResolveNativeObserverPath(ServiceHostOptions options, string? baseDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        var fromEnv = FirstExistingPath(Environment.GetEnvironmentVariable(PathOverrideVariable));
        if (fromEnv is not null)
        {
            return fromEnv;
        }

        var configured = FirstExistingPath(options.NativeObserverPath);
        if (configured is not null)
        {
            return configured;
        }

        string baseDir;
        try
        {
            baseDir = Path.GetFullPath(baseDirectory ?? AppContext.BaseDirectory);
        }
        catch
        {
            return null;
        }

        var direct = new[]
        {
            Path.Combine(baseDir, ObserverExeName),
            Path.Combine(baseDir, "native", ObserverExeName),
        };
        foreach (var candidate in direct)
        {
            if (IsExistingFile(candidate))
            {
                return candidate;
            }
        }

        var relativeLayouts = new[]
        {
            Path.Combine("build", "ApfsAccess.ApfsRwEngine", "Release", ObserverExeName),
            Path.Combine("artifacts", "native", "Release", ObserverExeName),
            Path.Combine("artifacts", "native", "Debug", ObserverExeName),
        };
        var ancestor = baseDir;
        for (var level = 0; level < 8 && ancestor is not null; level++)
        {
            foreach (var relative in relativeLayouts)
            {
                var candidate = Path.Combine(ancestor, relative);
                if (IsExistingFile(candidate))
                {
                    return candidate;
                }
            }

            ancestor = Path.GetDirectoryName(ancestor);
        }

        return null;
    }

    internal static string BuildDeviceSlug(string devicePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(devicePath);
        var slash = devicePath.LastIndexOfAny(['/', '\\']);
        var baseName = slash < 0 ? devicePath : devicePath[(slash + 1)..];
        var slug = new string(baseName.Select(ch => IsSlugChar(ch) ? ch : '-').ToArray()).TrimStart('-');
        return IsValidSlug(slug) ? slug : "device";
    }

    internal static IReadOnlyList<string> BuildObserverArguments(
        string devicePath, string profile, string deviceSlug)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(devicePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(profile);
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceSlug);
        // Raw physical devices use --device (hashScope none); image files use
        // --image, mirroring the observer CLI contract.
        var sourceFlag = IsRawPhysicalDevicePath(devicePath) ? "--device" : "--image";
        return [sourceFlag, devicePath, "--profile", profile, "--mode", "collect", "--device-id", deviceSlug];
    }

    internal static ApfsObserverEvidence ParseAndValidateEvidence(string stdout)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stdout);
        ApfsObserverEvidence evidence;
        try
        {
            evidence = ApfsTopology.ParseEvidence(stdout);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"ApfsObserver.exe emitted malformed evidence JSON: {ex.Message}", ex);
        }

        if (!string.Equals(evidence.Format, ApfsTopology.EvidenceFormat, StringComparison.Ordinal) ||
            evidence.Version != ApfsTopology.EvidenceVersion ||
            !string.Equals(evidence.ObserverId, ApfsTopology.ObserverId, StringComparison.Ordinal) ||
            evidence.Synthetic ||
            string.IsNullOrWhiteSpace(evidence.Mode) ||
            string.IsNullOrWhiteSpace(evidence.Profile) ||
            evidence.Source is null ||
            evidence.SecondarySources is null ||
            evidence.Topology is null)
        {
            throw new InvalidOperationException(
                "ApfsObserver.exe emitted an evidence envelope that failed fail-closed validation.");
        }

        return evidence;
    }

    // Catalog attach rules (freeze section 6, managed half): the observer
    // snapshot is consumed opaquely. Single-container single-volume snapshots
    // attach to the single legacy volume regardless of name; otherwise legacy
    // volumes match observer volumes by exact (ordinal) name, unique-or-null.
    // Ambiguous or unmatched entries stay null (FsHost enforces at mount).
    internal static CatalogAttachment?[] ResolveCatalogAttachments(
        IReadOnlyList<string> legacyVolumeNames, ApfsTopologySnapshot? snapshot)
    {
        ArgumentNullException.ThrowIfNull(legacyVolumeNames);
        var attachments = new CatalogAttachment?[legacyVolumeNames.Count];
        if (snapshot is null)
        {
            return attachments;
        }

        if (snapshot.Containers.Count == 1 &&
            snapshot.Volumes.Count == 1 &&
            legacyVolumeNames.Count == 1)
        {
            attachments[0] = TryBuildAttachment(snapshot.Volumes[0], snapshot);
            return attachments;
        }

        for (var index = 0; index < legacyVolumeNames.Count; index++)
        {
            var matches = snapshot.Volumes
                .Where(volume => string.Equals(volume.Name, legacyVolumeNames[index], StringComparison.Ordinal))
                .ToArray();
            attachments[index] = matches.Length == 1
                ? TryBuildAttachment(matches[0], snapshot)
                : null;
        }

        return attachments;
    }

    private static CatalogAttachment? TryBuildAttachment(
        ApfsVolumeRecord volume, ApfsTopologySnapshot snapshot)
    {
        if (!ulong.TryParse(
                volume.ObjectId,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var objectId) ||
            objectId == 0)
        {
            return null;
        }

        var container = snapshot.Containers.FirstOrDefault(
            candidate => string.Equals(candidate.Id, volume.ContainerId, StringComparison.Ordinal));
        if (container is null)
        {
            return null;
        }

        var capability = ApfsVolumeCapabilities.Evaluate(volume, container);
        return new CatalogAttachment(
            VolumeObjectId: objectId,
            ContainerUuidHex: container.Uuid,
            CatalogVolumeId: volume.Id,
            Decision: capability.Decision,
            Reasons: capability.Reasons,
            AutoMountAllowed: capability.AutoMountAllowed);
    }

    private static string? FirstExistingPath(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return null;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(candidate);
        }
        catch
        {
            return null;
        }

        return File.Exists(fullPath) ? fullPath : null;
    }

    private static bool IsExistingFile(string candidate)
    {
        try
        {
            return File.Exists(candidate);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsSlugChar(char ch)
        => char.IsAsciiLetterOrDigit(ch) || ch is '_' or '.' or '-';

    private static bool IsValidSlug(string? slug)
        => !string.IsNullOrWhiteSpace(slug) &&
           slug.Length <= 128 &&
           slug.All(IsSlugChar);

    private static bool IsRawPhysicalDevicePath(string path)
        => !string.IsNullOrWhiteSpace(path) &&
           (path.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\\?\PhysicalDrive", StringComparison.OrdinalIgnoreCase));
}
