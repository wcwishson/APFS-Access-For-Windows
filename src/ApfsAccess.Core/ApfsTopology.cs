using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ApfsAccess.Core;

// Observer evidence records. Field names match
// tests/fixtures/apfs/observer-evidence.schema.json exactly; managed code
// consumes observer JSON opaquely and never parses APFS bytes.
//
// NOTE (freeze v1.1): the schema requires `readonlyFeatureBits` on every
// container and volume and a top-level `secondarySources` list. The records
// below keep `readonlyFeatureBits` optional-nullable (JSON-absent => null =>
// treated as empty by the evaluator) so pre-v1.1 hand-built JSON still
// parses; `secondarySources` is optional-nullable on the record but REQUIRED
// by envelope validation (absent => fail closed, enforced in
// NativeApfsObserver.ParseAndValidateEvidence).

public sealed record ApfsDiskRecord(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("deviceIdentifier")] string DeviceIdentifier,
    [property: JsonPropertyName("uuid")] string? Uuid,
    [property: JsonPropertyName("sizeBytes")] long SizeBytes);

public sealed record ApfsPartitionRecord(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("uuid")] string Uuid,
    [property: JsonPropertyName("diskId")] string DiskId,
    [property: JsonPropertyName("index")] int Index,
    [property: JsonPropertyName("startByte")] long StartByte,
    [property: JsonPropertyName("sizeBytes")] long SizeBytes,
    [property: JsonPropertyName("typeGuid")] string TypeGuid,
    [property: JsonPropertyName("usage")] string Usage);

public sealed record ApfsStoreRecord(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("uuid")] string Uuid,
    [property: JsonPropertyName("partitionId")] string PartitionId,
    [property: JsonPropertyName("containerId")] string ContainerId,
    [property: JsonPropertyName("offsetBytes")] long OffsetBytes,
    [property: JsonPropertyName("sizeBytes")] long SizeBytes,
    [property: JsonPropertyName("blockSizeBytes"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? BlockSizeBytes = null,
    [property: JsonPropertyName("totalBlocks"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ulong? TotalBlocks = null,
    [property: JsonPropertyName("diskId"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? DiskId = null);

public sealed record ApfsContainerRecord(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("uuid")] string Uuid,
    [property: JsonPropertyName("blockSizeBytes")] long BlockSizeBytes,
    [property: JsonPropertyName("storeIds")] IReadOnlyList<string> StoreIds,
    [property: JsonPropertyName("volumeIds")] IReadOnlyList<string> VolumeIds,
    [property: JsonPropertyName("fusion")] bool Fusion,
    [property: JsonPropertyName("checkpointXid")] string CheckpointXid,
    [property: JsonPropertyName("compatibleFeatureBits")] IReadOnlyList<string> CompatibleFeatureBits,
    [property: JsonPropertyName("unknownFeatureBits")] IReadOnlyList<string> UnknownFeatureBits,
    [property: JsonPropertyName("incompatibleFeatureBits")] IReadOnlyList<string> IncompatibleFeatureBits,
    [property: JsonPropertyName("readonlyFeatureBits")] IReadOnlyList<string>? ReadonlyFeatureBits = null,
    [property: JsonPropertyName("sharedSpace")] ApfsSharedSpaceProjection? SharedSpace = null);

public sealed record ApfsVolumeRecord(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("uuid")] string Uuid,
    [property: JsonPropertyName("objectId")] string ObjectId,
    [property: JsonPropertyName("containerId")] string ContainerId,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("nameUtf8Valid")] bool NameUtf8Valid,
    [property: JsonPropertyName("roles")] IReadOnlyList<string> Roles,
    [property: JsonPropertyName("roleRaw")] long RoleRaw,
    [property: JsonPropertyName("groupId")] string? GroupId,
    [property: JsonPropertyName("caseMode")] string CaseMode,
    [property: JsonPropertyName("encryptionMode")] string EncryptionMode,
    [property: JsonPropertyName("locked")] bool Locked,
    [property: JsonPropertyName("compatibleFeatureBits")] IReadOnlyList<string> CompatibleFeatureBits,
    [property: JsonPropertyName("unknownFeatureBits")] IReadOnlyList<string> UnknownFeatureBits,
    [property: JsonPropertyName("incompatibleFeatureBits")] IReadOnlyList<string> IncompatibleFeatureBits,
    [property: JsonPropertyName("superblockBlock")] string SuperblockBlock,
    [property: JsonPropertyName("superblockXid")] string SuperblockXid,
    [property: JsonPropertyName("readonlyFeatureBits")] IReadOnlyList<string>? ReadonlyFeatureBits = null,
    [property: JsonPropertyName("roleName")] string? RoleName = null,
    [property: JsonPropertyName("groupUuid")] string? GroupUuid = null,
    [property: JsonPropertyName("groupMetadataValid")] bool? GroupMetadataValid = null,
    [property: JsonPropertyName("groupAssociationStatus")] string? GroupAssociationStatus = null);

public sealed record ApfsGroupRecord(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("uuid")] string Uuid,
    [property: JsonPropertyName("volumeIds")] IReadOnlyList<string> VolumeIds,
    [property: JsonPropertyName("containerId")] string? ContainerId = null,
    [property: JsonPropertyName("associationStatus")] string? AssociationStatus = null,
    [property: JsonPropertyName("systemVolumeId")] string? SystemVolumeId = null,
    [property: JsonPropertyName("dataVolumeId")] string? DataVolumeId = null);

// One checkpoint observation shared by all consumers. Null projection means
// unknown; within a known projection null reserve/quota means unset. Snapshot
// and purgeable accounting remain unknown. Availability is not allocation admission.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ApfsSpaceAmount(
    [property: JsonPropertyName("blocks"), JsonRequired, JsonConverter(typeof(ApfsUInt64StringConverter))] ulong Blocks,
    [property: JsonPropertyName("bytes"), JsonRequired, JsonConverter(typeof(ApfsUInt64StringConverter))] ulong Bytes);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ApfsVolumeSpaceProjection(
    [property: JsonPropertyName("volumeId"), JsonRequired] string VolumeId,
    [property: JsonPropertyName("objectId"), JsonRequired, JsonConverter(typeof(ApfsUInt64StringConverter))] ulong ObjectId,
    [property: JsonPropertyName("allocated"), JsonRequired] ApfsSpaceAmount Allocated,
    [property: JsonPropertyName("reserve"), JsonRequired] ApfsSpaceAmount? Reserve,
    [property: JsonPropertyName("quota"), JsonRequired] ApfsSpaceAmount? Quota,
    [property: JsonPropertyName("siblingReserveRemaining"), JsonRequired] ApfsSpaceAmount SiblingReserveRemaining,
    [property: JsonPropertyName("available"), JsonRequired] ApfsSpaceAmount Available,
    [property: JsonPropertyName("snapshot"), JsonRequired] ApfsSpaceAmount? Snapshot,
    [property: JsonPropertyName("purgeable"), JsonRequired] ApfsSpaceAmount? Purgeable);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ApfsSharedSpaceProjection(
    [property: JsonPropertyName("containerId"), JsonRequired] string ContainerId,
    [property: JsonPropertyName("checkpointXid"), JsonRequired, JsonConverter(typeof(ApfsUInt64StringConverter))] ulong CheckpointXid,
    [property: JsonPropertyName("allocationUnitBytes"), JsonRequired] uint AllocationUnitBytes,
    [property: JsonPropertyName("total"), JsonRequired] ApfsSpaceAmount Total,
    [property: JsonPropertyName("free"), JsonRequired] ApfsSpaceAmount Free,
    [property: JsonPropertyName("used"), JsonRequired] ApfsSpaceAmount Used,
    [property: JsonPropertyName("volumes"), JsonRequired] IReadOnlyList<ApfsVolumeSpaceProjection> Volumes);

public sealed class ApfsUInt64StringConverter : JsonConverter<ulong>
{
    public override ulong Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String && reader.GetString() is { } text &&
            ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) &&
            value.ToString(CultureInfo.InvariantCulture) == text) return value;
        throw new JsonException("Expected a canonical unsigned 64-bit decimal string.");
    }

    public override void Write(Utf8JsonWriter writer, ulong value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.ToString(CultureInfo.InvariantCulture));
}

public sealed record ApfsTopologySnapshot(
    [property: JsonPropertyName("disks")] IReadOnlyList<ApfsDiskRecord> Disks,
    [property: JsonPropertyName("partitions")] IReadOnlyList<ApfsPartitionRecord> Partitions,
    [property: JsonPropertyName("stores")] IReadOnlyList<ApfsStoreRecord> Stores,
    [property: JsonPropertyName("containers")] IReadOnlyList<ApfsContainerRecord> Containers,
    [property: JsonPropertyName("volumes")] IReadOnlyList<ApfsVolumeRecord> Volumes,
    [property: JsonPropertyName("groups")] IReadOnlyList<ApfsGroupRecord> Groups);

public sealed record ApfsEvidenceSource(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("sizeBytes")] long SizeBytes,
    [property: JsonPropertyName("hashScope")] string HashScope,
    [property: JsonPropertyName("sha256")] string? Sha256);

[JsonConverter(typeof(ApfsObserverEvidenceJsonConverter))]
public record ApfsObserverEvidence(
    [property: JsonPropertyName("format")] string Format,
    [property: JsonPropertyName("version")] int Version,
    [property: JsonPropertyName("observerId")] string ObserverId,
    [property: JsonPropertyName("observerVersion")] string ObserverVersion,
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("profile")] string Profile,
    [property: JsonPropertyName("synthetic")] bool Synthetic,
    [property: JsonPropertyName("source")] ApfsEvidenceSource Source,
    [property: JsonPropertyName("topology")] ApfsTopologySnapshot Topology,
    [property: JsonPropertyName("secondarySources")] IReadOnlyList<ApfsEvidenceSource>? SecondarySources = null,
    [property: JsonPropertyName("topologyMetadataVersion")] int? TopologyMetadataVersion = null)
{
    internal ApfsObserverEvidence CopyEvidenceRecord() => new(this);
}

// Canonical managed identity grammar (freeze section 3) plus the legacy
// `device|volumeName` translation. Typed IDs are additive; legacy VolumeId
// strings are untouched elsewhere.
public static class ApfsTopology
{
    public const string EvidenceFormat = "apfs-access-raw-evidence";
    public const int EvidenceVersion = 1;
    public const int TopologyMetadataVersion = 1;
    public const string ObserverId = "apfs-access-owned-raw-observer";

    private static readonly JsonSerializerOptions EvidenceOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
    };

    public static ApfsObserverEvidence ParseEvidence(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        return JsonSerializer.Deserialize<ApfsObserverEvidence>(json, EvidenceOptions)
            ?? throw new JsonException("Observer evidence JSON deserialized to null.");
    }

    // ---- Canonical ID builders / validators (freeze section 3) ----

    public static string BuildDiskId(string slug)
    {
        if (!IsValidSlug(slug))
        {
            throw new ArgumentException("Disk slug must be a nonempty [A-Za-z0-9_.\\-] token.", nameof(slug));
        }

        return "apfs-disk:" + slug;
    }

    public static bool TryParseDiskId(string? id, out string slug)
    {
        slug = string.Empty;
        if (!TryStripPrefix(id, "apfs-disk:", out var tail) || !IsValidSlug(tail))
        {
            return false;
        }

        slug = tail;
        return true;
    }

    public static string BuildPartitionId(Guid partitionUuid)
        => "apfs-part:" + partitionUuid.ToString("D", CultureInfo.InvariantCulture);

    public static bool TryParsePartitionId(string? id, out Guid partitionUuid)
    {
        partitionUuid = Guid.Empty;
        if (!TryStripPrefix(id, "apfs-part:", out var tail) || !IsLowercaseGuidD(tail, out var guid))
        {
            return false;
        }

        partitionUuid = guid;
        return true;
    }

    public static string BuildStoreId(Guid partitionUuid)
        => "apfs-store:" + partitionUuid.ToString("D", CultureInfo.InvariantCulture);

    public static string BuildRawStoreId() => "apfs-store:raw";

    public static bool TryParseStoreId(string? id, out Guid? partitionUuid, out bool isRaw)
    {
        partitionUuid = null;
        isRaw = false;
        if (!TryStripPrefix(id, "apfs-store:", out var tail) || tail.Length == 0)
        {
            return false;
        }

        if (tail == "raw")
        {
            isRaw = true;
            return true;
        }

        if (!IsLowercaseGuidD(tail, out var guid))
        {
            return false;
        }

        partitionUuid = guid;
        return true;
    }

    public static string BuildContainerId(string containerHex32)
    {
        if (!IsHex32(containerHex32))
        {
            throw new ArgumentException("Container hex32 must be 32 lowercase hex chars.", nameof(containerHex32));
        }

        return "apfs-container:" + containerHex32;
    }

    public static bool TryParseContainerId(string? id, out string containerHex32)
    {
        containerHex32 = string.Empty;
        if (!TryStripPrefix(id, "apfs-container:", out var tail) || !IsHex32(tail))
        {
            return false;
        }

        containerHex32 = tail;
        return true;
    }

    // Container-membership match shared by service, worker, and CLI surfaces.
    // Accepts the canonical apfs-container:hex32 shape, bare hex32/Guid text,
    // and case variants; the live inventory row stays authoritative and this
    // helper only compares spellings, never admits a container by itself.
    public static bool MatchesContainerUuid(string? requested, string? member)
    {
        if (string.IsNullOrWhiteSpace(requested) || string.IsNullOrWhiteSpace(member)) return false;
        var normalized = CanonicalizeContainerUuid(requested);
        var candidate = member.Trim();
        return string.Equals(normalized, candidate, StringComparison.OrdinalIgnoreCase) ||
            TopologyAdmission.SameUuid(normalized, candidate);
    }

    public static string CanonicalizeContainerUuid(string value)
    {
        var trimmed = value.Trim();
        return TryParseContainerId(trimmed, out var hex) ? hex : trimmed;
    }

    public static string BuildVolumeId(string containerHex32, ulong objectId)
    {
        if (!IsHex32(containerHex32))
        {
            throw new ArgumentException("Container hex32 must be 32 lowercase hex chars.", nameof(containerHex32));
        }

        return "apfs-vol:" + containerHex32 + ":" + objectId.ToString(CultureInfo.InvariantCulture);
    }

    public static bool TryParseVolumeId(string? id, out string containerHex32, out ulong objectId)
    {
        containerHex32 = string.Empty;
        objectId = 0;
        if (!TryStripPrefix(id, "apfs-vol:", out var tail))
        {
            return false;
        }

        var separator = tail.LastIndexOf(':');
        if (separator < 32)
        {
            return false;
        }

        var hex = tail[..separator];
        var oid = tail[(separator + 1)..];
        if (!IsHex32(hex) || !IsCanonicalU64(oid, out var parsed))
        {
            return false;
        }

        containerHex32 = hex;
        objectId = parsed;
        return true;
    }

    public static string BuildGroupId(string groupHex32)
    {
        if (!IsHex32(groupHex32))
        {
            throw new ArgumentException("Group hex32 must be 32 lowercase hex chars.", nameof(groupHex32));
        }

        return "apfs-group:" + groupHex32;
    }

    public static bool TryParseGroupId(string? id, out string groupHex32)
    {
        groupHex32 = string.Empty;
        if (!TryStripPrefix(id, "apfs-group:", out var tail) || !IsHex32(tail))
        {
            return false;
        }

        groupHex32 = tail;
        return true;
    }

    // ---- Legacy device|volumeName <-> typed lookup ----

    // Forward: the volume name must be unique on the device (case-insensitive,
    // matching legacy VolumeId semantics) or lookup fails.
    public static bool TryResolveTypedVolumeId(
        ApfsTopologySnapshot? snapshot,
        string? deviceId,
        string? volumeName,
        out string? typedVolumeId,
        out string error)
    {
        typedVolumeId = null;
        error = string.Empty;
        if (snapshot is null)
        {
            error = "No topology snapshot was provided.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(deviceId))
        {
            error = "No device id was provided.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(volumeName))
        {
            error = $"No volume name was provided for device '{deviceId}'.";
            return false;
        }

        var matches = VolumesOnDevice(snapshot, deviceId)
            .Where(volume => string.Equals(volume.Name, volumeName, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (matches.Length == 0)
        {
            error = $"Volume name '{volumeName}' was not found on device '{deviceId}'.";
            return false;
        }

        if (matches.Length > 1)
        {
            error = $"Volume name '{volumeName}' is ambiguous on device '{deviceId}' ({matches.Length} matches).";
            return false;
        }

        typedVolumeId = matches[0].Id;
        return true;
    }

    // Reverse: always succeeds when the typed id resolves; LossyReverse is set
    // when the legacy form cannot round-trip (name collides on the device or
    // the volume is reachable from several devices).
    public static bool TryBuildLegacyVolumeId(
        ApfsTopologySnapshot? snapshot,
        string? typedVolumeId,
        out string? legacyVolumeId,
        out bool lossyReverse,
        out string error)
    {
        legacyVolumeId = null;
        lossyReverse = false;
        error = string.Empty;
        if (snapshot is null)
        {
            error = "No topology snapshot was provided.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(typedVolumeId))
        {
            error = "No typed volume id was provided.";
            return false;
        }

        var volume = snapshot.Volumes.FirstOrDefault(
            candidate => string.Equals(candidate.Id, typedVolumeId, StringComparison.Ordinal));
        if (volume is null)
        {
            error = $"Unknown volume id '{typedVolumeId}'.";
            return false;
        }

        var deviceIds = DeviceIdentifiersForVolume(snapshot, volume);
        if (deviceIds.Count == 0)
        {
            error = $"Volume '{typedVolumeId}' has no resolvable device.";
            return false;
        }

        var deviceId = deviceIds[0];
        if (deviceIds.Count > 1)
        {
            lossyReverse = true;
        }

        var siblings = VolumesOnDevice(snapshot, deviceId)
            .Count(sibling => !string.Equals(sibling.Id, volume.Id, StringComparison.Ordinal) &&
                              string.Equals(sibling.Name, volume.Name, StringComparison.OrdinalIgnoreCase));
        if (siblings > 0)
        {
            lossyReverse = true;
        }

        legacyVolumeId = deviceId + "|" + volume.Name;
        return true;
    }

    // ---- Private helpers ----

    private static bool TryStripPrefix(string? id, string prefix, out string tail)
    {
        tail = string.Empty;
        if (string.IsNullOrEmpty(id) || !id.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        tail = id[prefix.Length..];
        return true;
    }

    private static bool IsValidSlug(string? slug)
    {
        if (string.IsNullOrWhiteSpace(slug))
        {
            return false;
        }

        foreach (var ch in slug)
        {
            if (!(char.IsAsciiLetterOrDigit(ch) || ch == '_' || ch == '.' || ch == '-'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsHex32(string? value)
    {
        if (value is null || value.Length != 32)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (!char.IsAsciiHexDigitLower(ch))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsLowercaseGuidD(string? value, out Guid guid)
    {
        guid = Guid.Empty;
        return value is not null &&
               Guid.TryParseExact(value, "D", out guid) &&
               string.Equals(guid.ToString("D", CultureInfo.InvariantCulture), value, StringComparison.Ordinal);
    }

    private static bool IsCanonicalU64(string? value, out ulong parsed)
    {
        parsed = 0;
        return value is not null &&
               ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out parsed) &&
               string.Equals(parsed.ToString(CultureInfo.InvariantCulture), value, StringComparison.Ordinal);
    }

    private static IReadOnlyList<ApfsVolumeRecord> VolumesOnDevice(ApfsTopologySnapshot snapshot, string deviceId)
    {
        var diskIds = new HashSet<string>(
            snapshot.Disks
                .Where(disk => string.Equals(disk.DeviceIdentifier, deviceId, StringComparison.OrdinalIgnoreCase))
                .Select(disk => disk.Id),
            StringComparer.Ordinal);
        if (diskIds.Count == 0)
        {
            return Array.Empty<ApfsVolumeRecord>();
        }

        var containers = snapshot.Containers
            .Where(container => DiskIdsForContainer(snapshot, container).Overlaps(diskIds))
            .Select(container => container.Id)
            .ToHashSet(StringComparer.Ordinal);
        return snapshot.Volumes
            .Where(volume => containers.Contains(volume.ContainerId))
            .ToArray();
    }

    private static HashSet<string> DiskIdsForContainer(ApfsTopologySnapshot snapshot, ApfsContainerRecord container)
    {
        var partitionToDisk = snapshot.Partitions.ToDictionary(
            partition => partition.Id, partition => partition.DiskId, StringComparer.Ordinal);
        var stores = snapshot.Stores.ToDictionary(store => store.Id, StringComparer.Ordinal);
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var storeId in container.StoreIds)
        {
            if (!stores.TryGetValue(storeId, out var store))
            {
                continue;
            }

            // Partitionless (raw) stores carry an empty partition id; they back
            // the partitionless disk(s). When every disk owns partitions
            // (malformed observer output), fall back to every disk.
            if (string.IsNullOrEmpty(store.PartitionId))
            {
                var partitionless = snapshot.Disks
                    .Where(disk => !snapshot.Partitions.Any(partition =>
                        string.Equals(partition.DiskId, disk.Id, StringComparison.Ordinal)))
                    .ToArray();
                var targets = partitionless.Length > 0 ? partitionless : snapshot.Disks.ToArray();
                foreach (var disk in targets)
                {
                    result.Add(disk.Id);
                }

                continue;
            }

            if (partitionToDisk.TryGetValue(store.PartitionId, out var diskId))
            {
                result.Add(diskId);
            }
        }

        return result;
    }

    private static IReadOnlyList<string> DeviceIdentifiersForVolume(
        ApfsTopologySnapshot snapshot, ApfsVolumeRecord volume)
    {
        var container = snapshot.Containers.FirstOrDefault(
            candidate => string.Equals(candidate.Id, volume.ContainerId, StringComparison.Ordinal));
        if (container is null)
        {
            return Array.Empty<string>();
        }

        var diskIds = DiskIdsForContainer(snapshot, container);
        return snapshot.Disks
            .Where(disk => diskIds.Contains(disk.Id))
            .Select(disk => disk.DeviceIdentifier)
            .ToArray();
    }
}
