using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ApfsAccess.Backend.Native;

// Frozen contract v1.3 section 7 (managed side): protected JSON session
// manifest for one APFS container. FsHost launches ONE process per container
// with `--container-manifest <file>`; the native loader owns no-follow path
// validation and refuses schema violations, container-UUID mismatches, and
// unknown/duplicate OIDs. Managed owns byte-identical checksum computation,
// collision checks, and a write self-verify step (fail closed on mismatch).
public sealed record ContainerManifestVolume(
    ulong ObjectId,
    string ContainerUuid,
    string? Name,
    string MountPoint,
    bool RequestedWrite,
    string? RecoveryIdentity,
    bool InitiallyActive = true);

public sealed record WrittenContainerManifest(
    string ManifestPath,
    string ManifestSha256,
    string ContainerUuid,
    string Device,
    ulong DeviceOffsetBytes,
    IReadOnlyList<ContainerManifestVolume> Volumes);

public sealed class ContainerManifestException : InvalidOperationException
{
    public ContainerManifestException(string message)
        : base(message)
    {
    }

    public ContainerManifestException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public static class ContainerManifestWriter
{
    public const string ManifestFormat = "apfs-access-container-manifest";
    public const int ManifestVersion = 1;

    private const string ChecksumDomain = "manifest-check-v1";
    // Binding checksum rule (both sides implement byte-identically): SHA-256
    // (lowercase hex) over UTF-8 bytes of `manifest-check-v1\n` +
    // `<containerUuid>\n<device>\n<deviceOffsetBytes decimal>\n` + per volume
    // in array order
    // `<objectId decimal>\n<containerUuid>\n<name>\n<mount>\n<W|R>\n<recoveryIdentity>\n`
    // (missing optional name/recoveryIdentity = empty string; hex lowercase).
    // RequestedWrite maps to `W` (true) or `R` (false).
    // Dormant rows select v2: use manifest-check-v2 and append A/I plus newline
    // after each row's recovery identity. All-active callers retain exact v1 bytes.
    public static string ComputeManifestSha256(
        string containerUuid,
        string device,
        ulong deviceOffsetBytes,
        IReadOnlyList<ContainerManifestVolume> volumes)
    {
        ArgumentNullException.ThrowIfNull(volumes);
        var normalizedContainer = NormalizeContainerUuid(containerUuid);
        ArgumentException.ThrowIfNullOrWhiteSpace(device);

        var builder = new StringBuilder();
        var version = volumes.All(static volume => volume.InitiallyActive) ? 1 : 2;
        builder.Append(version == 1 ? ChecksumDomain : "manifest-check-v2").Append('\n');
        builder.Append(normalizedContainer).Append('\n');
        builder.Append(device).Append('\n');
        builder.Append(deviceOffsetBytes.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (var volume in volumes)
        {
            ArgumentNullException.ThrowIfNull(volume);
            builder.Append(volume.ObjectId.ToString(CultureInfo.InvariantCulture)).Append('\n');
            builder.Append(NormalizeContainerUuid(volume.ContainerUuid)).Append('\n');
            builder.Append(volume.Name ?? string.Empty).Append('\n');
            builder.Append(volume.MountPoint).Append('\n');
            builder.Append(volume.RequestedWrite ? "W" : "R").Append('\n');
            builder.Append(volume.RecoveryIdentity ?? string.Empty).Append('\n');
            if (version == 2) builder.Append(volume.InitiallyActive ? "A" : "I").Append('\n');
        }

        var bytes = Encoding.UTF8.GetBytes(builder.ToString());
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    public static string NormalizeContainerUuid(string? containerUuid)
    {
        if (string.IsNullOrWhiteSpace(containerUuid))
        {
            throw new ContainerManifestException("Container UUID is required for a container manifest.");
        }

        var normalized = containerUuid.Trim().ToLowerInvariant();
        if (normalized.Length != 32 || !normalized.All(static ch =>
                (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
        {
            throw new ContainerManifestException(
                $"Container UUID '{containerUuid}' is not 32 lowercase hex digits.");
        }

        return normalized;
    }

    public static WrittenContainerManifest WriteManifest(
        string containerUuid,
        string devicePath,
        ulong deviceOffsetBytes,
        IReadOnlyList<ContainerManifestVolume> volumes,
        string? tempRoot = null)
    {
        ArgumentNullException.ThrowIfNull(volumes);
        var normalizedContainer = NormalizeContainerUuid(containerUuid);
        if (string.IsNullOrWhiteSpace(devicePath))
        {
            throw new ContainerManifestException("Device path is required for a container manifest.");
        }

        if (volumes.Count == 0 || !volumes.Any(static volume => volume.InitiallyActive))
        {
            throw new ContainerManifestException("A container manifest requires at least one volume.");
        }

        var seenObjectIds = new HashSet<ulong>();
        var seenMountPoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenRecoveryIdentities = new HashSet<string>(StringComparer.Ordinal);
        foreach (var volume in volumes)
        {
            ArgumentNullException.ThrowIfNull(volume);
            if (volume.ObjectId == 0)
            {
                throw new ContainerManifestException("Manifest volume object IDs must be nonzero.");
            }

            if (!seenObjectIds.Add(volume.ObjectId))
            {
                throw new ContainerManifestException(
                    $"Duplicate manifest volume object ID {volume.ObjectId}.");
            }

            if (!string.Equals(
                    NormalizeContainerUuid(volume.ContainerUuid),
                    normalizedContainer,
                    StringComparison.Ordinal))
            {
                throw new ContainerManifestException(
                    $"Manifest volume object ID {volume.ObjectId} belongs to a different container.");
            }

            if (!volume.InitiallyActive &&
                (volume.MountPoint.Length != 0 || !volume.RequestedWrite))
                throw new ContainerManifestException("Dormant census members require admitted recovery write access and no mount target.");

            if (volume.InitiallyActive && string.IsNullOrWhiteSpace(volume.MountPoint))
            {
                throw new ContainerManifestException(
                    $"Manifest volume object ID {volume.ObjectId} is missing its mount point.");
            }

            var mountKey = NormalizeMountTargetForComparison(volume.MountPoint);
            if (volume.InitiallyActive && !seenMountPoints.Add(mountKey))
            {
                throw new ContainerManifestException(
                    $"Duplicate manifest mount target '{volume.MountPoint}'.");
            }

            if (volume.RequestedWrite && string.IsNullOrWhiteSpace(volume.RecoveryIdentity))
            {
                throw new ContainerManifestException(
                    $"Writable manifest volume object ID {volume.ObjectId} is missing its recovery identity.");
            }

            if (!string.IsNullOrEmpty(volume.RecoveryIdentity) &&
                !seenRecoveryIdentities.Add(volume.RecoveryIdentity))
            {
                throw new ContainerManifestException(
                    $"Duplicate manifest recovery identity '{volume.RecoveryIdentity}'.");
            }
        }

        string directory;
        try
        {
            directory = ResolveManifestDirectory(tempRoot);
            Directory.CreateDirectory(directory);
        }
        catch (Exception ex) when (ex is not ContainerManifestException)
        {
            throw new ContainerManifestException(
                "Unable to prepare the D:-rooted container manifest directory.", ex);
        }

        var manifestSha256 = ComputeManifestSha256(
            normalizedContainer, devicePath, deviceOffsetBytes, volumes);
        var fileName = $"container_{normalizedContainer}_{Guid.NewGuid():N}.container-manifest.json";
        var manifestPath = Path.Combine(directory, fileName);

        try
        {
            using (var stream = new FileStream(
                       manifestPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None))
            {
                WriteManifestJson(
                    stream,
                    normalizedContainer,
                    devicePath,
                    deviceOffsetBytes,
                    manifestSha256,
                    volumes);
            }
        }
        catch (Exception ex) when (ex is not ContainerManifestException)
        {
            TryDeleteQuietly(manifestPath);
            throw new ContainerManifestException(
                $"Unable to write the container manifest to '{manifestPath}'.", ex);
        }

        // Self-verify: recompute the checksum from the parsed file content
        // (not from the in-memory inputs) and fail closed on any mismatch.
        try
        {
            SelfVerifyManifestFile(manifestPath, normalizedContainer, devicePath, deviceOffsetBytes, volumes);
        }
        catch (Exception ex) when (ex is not ContainerManifestException)
        {
            TryDeleteQuietly(manifestPath);
            throw new ContainerManifestException(
                $"Container manifest self-verify failed for '{manifestPath}'.", ex);
        }

        return new WrittenContainerManifest(
            manifestPath,
            manifestSha256,
            normalizedContainer,
            devicePath,
            deviceOffsetBytes,
            volumes.ToArray());
    }

    internal static string ResolveManifestDirectory(string? runtimeRoot = null)
    {
        try
        {
            var tempRoot = Path.GetFullPath(runtimeRoot ?? Path.GetTempPath());
            return Path.Combine(tempRoot, "ApfsAccess", "manifests");
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ContainerManifestException(
                "Unable to resolve the container-manifest runtime directory.", ex);
        }
    }

    internal static string NormalizeMountTargetForComparison(string mountPoint)
    {
        var normalized = mountPoint.Trim().Replace('/', '\\');
        try
        {
            if (Path.IsPathFullyQualified(normalized))
            {
                normalized = Path.GetFullPath(normalized);
            }
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ContainerManifestException(
                $"Manifest mount target '{mountPoint}' is invalid.", ex);
        }

        var root = Path.GetPathRoot(normalized);
        if (!string.Equals(root, normalized, StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized.TrimEnd('\\');
        }

        return normalized;
    }

    private static void WriteManifestJson(
        Stream stream,
        string containerUuid,
        string device,
        ulong deviceOffsetBytes,
        string manifestSha256,
        IReadOnlyList<ContainerManifestVolume> volumes)
    {
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
        writer.WriteStartObject();
        writer.WriteString("format", ManifestFormat);
        var version = volumes.All(static volume => volume.InitiallyActive) ? 1 : 2;
        writer.WriteNumber("version", version);
        writer.WriteString("containerUuid", containerUuid);
        writer.WriteString("device", device);
        writer.WriteNumber("deviceOffsetBytes", deviceOffsetBytes);
        writer.WriteString("manifestSha256", manifestSha256);
        writer.WriteStartArray("volumes");
        foreach (var volume in volumes)
        {
            writer.WriteStartObject();
            writer.WriteNumber("objectId", volume.ObjectId);
            writer.WriteString("containerUuid", NormalizeContainerUuid(volume.ContainerUuid));
            writer.WriteString("name", volume.Name ?? string.Empty);
            writer.WriteString("mount", volume.MountPoint);
            writer.WriteBoolean("requestedWrite", volume.RequestedWrite);
            writer.WriteString("recoveryIdentity", volume.RecoveryIdentity ?? string.Empty);
            if (version == 2) writer.WriteBoolean("initiallyActive", volume.InitiallyActive);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void SelfVerifyManifestFile(
        string manifestPath,
        string expectedContainerUuid,
        string expectedDevice,
        ulong expectedDeviceOffsetBytes,
        IReadOnlyList<ContainerManifestVolume> expectedVolumes)
    {
        using var stream = File.OpenRead(manifestPath);
        using var document = JsonDocument.Parse(stream);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new ContainerManifestException("Manifest self-verify: root is not an object.");
        }

        if (!root.TryGetProperty("format", out var format) ||
            format.ValueKind != JsonValueKind.String ||
            !string.Equals(format.GetString(), ManifestFormat, StringComparison.Ordinal))
        {
            throw new ContainerManifestException("Manifest self-verify: unexpected format marker.");
        }

        if (!root.TryGetProperty("version", out var version) ||
            version.ValueKind != JsonValueKind.Number ||
            !version.TryGetInt32(out var versionNumber) ||
            versionNumber != (expectedVolumes.All(static volume => volume.InitiallyActive) ? 1 : 2))
        {
            throw new ContainerManifestException("Manifest self-verify: unexpected version.");
        }

        if (!root.TryGetProperty("manifestSha256", out var sha) ||
            sha.ValueKind != JsonValueKind.String)
        {
            throw new ContainerManifestException("Manifest self-verify: manifestSha256 is missing.");
        }

        if (!root.TryGetProperty("volumes", out var volumesElement) ||
            volumesElement.ValueKind != JsonValueKind.Array ||
            volumesElement.GetArrayLength() != expectedVolumes.Count)
        {
            throw new ContainerManifestException("Manifest self-verify: volume list does not round-trip.");
        }

        var parsedVolumes = new List<ContainerManifestVolume>(expectedVolumes.Count);
        foreach (var element in volumesElement.EnumerateArray())
        {
            parsedVolumes.Add(new ContainerManifestVolume(
                ObjectId: GetRequiredUInt64(element, "objectId"),
                ContainerUuid: GetRequiredString(element, "containerUuid"),
                Name: GetOptionalString(element, "name"),
                MountPoint: GetRequiredString(element, "mount"),
                RequestedWrite: GetRequiredBoolean(element, "requestedWrite"),
                RecoveryIdentity: GetOptionalString(element, "recoveryIdentity"),
                InitiallyActive: versionNumber == 1 || GetRequiredBoolean(element, "initiallyActive")));
        }

        var parsedContainer = GetRequiredString(root, "containerUuid");
        var parsedDevice = GetRequiredString(root, "device");
        var parsedOffset = GetRequiredUInt64(root, "deviceOffsetBytes");
        var recomputed = ComputeManifestSha256(parsedContainer, parsedDevice, parsedOffset, parsedVolumes);

        if (!string.Equals(parsedContainer, expectedContainerUuid, StringComparison.Ordinal) ||
            !string.Equals(parsedDevice, expectedDevice, StringComparison.Ordinal) ||
            parsedOffset != expectedDeviceOffsetBytes ||
            !string.Equals(sha.GetString(), recomputed, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(sha.GetString(), ComputeManifestSha256(
                expectedContainerUuid, expectedDevice, expectedDeviceOffsetBytes, expectedVolumes),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ContainerManifestException("Manifest self-verify: checksum or identity mismatch.");
        }
    }

    private static string GetRequiredString(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            value.GetString() is not { } text)
        {
            throw new ContainerManifestException($"Manifest self-verify: '{property}' is missing.");
        }

        return text;
    }

    private static string? GetOptionalString(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Null => null,
            _ => throw new ContainerManifestException($"Manifest self-verify: '{property}' is not a string."),
        };
    }

    private static ulong GetRequiredUInt64(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetUInt64(out var number))
        {
            throw new ContainerManifestException($"Manifest self-verify: '{property}' is not a u64 number.");
        }

        return number;
    }

    private static bool GetRequiredBoolean(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value) ||
            (value.ValueKind != JsonValueKind.True && value.ValueKind != JsonValueKind.False))
        {
            throw new ContainerManifestException($"Manifest self-verify: '{property}' is not a boolean.");
        }

        return value.ValueKind == JsonValueKind.True;
    }

    private static void TryDeleteQuietly(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }
}
