using System.Text.Json.Nodes;

namespace ApfsAccess.Backend.Native.Tests;

// Hand-built observer evidence envelopes for seam-level tests (no native
// binary involved). The real-binary integration tests cover byte truth.
internal static class ObserverEvidenceJson
{
    internal sealed record VolumeJson(
        string Name,
        ulong ObjectId,
        ulong FsFlags = 0x1,
        ushort Role = 32,
        string[]? Roles = null,
        string EncryptionMode = "none",
        bool Locked = false,
        ulong Features = 0,
        ulong ReadonlyFeatures = 0,
        ulong IncompatibleFeatures = 0);

    internal static string BuildSingleContainer(
        string containerHex32,
        VolumeJson[] volumes,
        string deviceSlug = "test-image",
        ulong checkpointXid = 7,
        string profile = "managed-discovery",
        string? devicePath = null)
        => BuildContainers(
            [(containerHex32, volumes)],
            deviceSlug,
            checkpointXid,
            profile,
            devicePath);

    // Fusion two-member evidence envelope for seam-level tests (no native
    // binary involved). Mirrors the real --store-a/--store-b --mode fusion
    // shape: Source echoes storeAPath, exactly one secondary echoes
    // storeBPath, two disks keyed by per-file slugs, two stores, one Fusion
    // container declaring both stores. Store.DiskId stays null: the observer
    // does not prove which file backs which store.
    internal static string BuildFusionPair(
        string containerHex32,
        VolumeJson[] volumes,
        string storeAPath,
        string storeBPath,
        ulong checkpointXid = 20,
        string profile = "managed-discovery")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(containerHex32);
        ArgumentException.ThrowIfNullOrWhiteSpace(storeAPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(storeBPath);
        var slugA = SlugOf(storeAPath);
        var slugB = SlugOf(storeBPath);
        var storeIdA = $"apfs-store:{containerHex32}-a";
        var storeIdB = $"apfs-store:{containerHex32}-b";
        var volumeIds = new JsonArray();
        var volumeNodes = new JsonArray();
        foreach (var volume in volumes)
        {
            var volumeId = $"apfs-vol:{containerHex32}:{volume.ObjectId}";
            volumeIds.Add(volumeId);
            volumeNodes.Add(BuildVolumeNode(containerHex32, volume, checkpointXid));
        }

        return new JsonObject
        {
            ["format"] = "apfs-access-raw-evidence",
            ["version"] = 1,
            ["observerId"] = "apfs-access-owned-raw-observer",
            ["observerVersion"] = "1.0.0",
            ["mode"] = "fusion",
            ["profile"] = profile,
            ["synthetic"] = false,
            ["source"] = new JsonObject
            {
                ["kind"] = "image",
                ["path"] = storeAPath,
                ["sizeBytes"] = 8388608,
                ["hashScope"] = "none",
                ["sha256"] = null,
            },
            ["secondarySources"] = new JsonArray
            {
                new JsonObject
                {
                    ["kind"] = "image",
                    ["path"] = storeBPath,
                    ["sizeBytes"] = 8388608,
                    ["hashScope"] = "none",
                    ["sha256"] = null,
                },
            },
            ["topology"] = new JsonObject
            {
                ["disks"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["id"] = $"apfs-disk:{slugA}",
                        ["deviceIdentifier"] = storeAPath,
                        ["uuid"] = null,
                        ["sizeBytes"] = 8388608,
                    },
                    new JsonObject
                    {
                        ["id"] = $"apfs-disk:{slugB}",
                        ["deviceIdentifier"] = storeBPath,
                        ["uuid"] = null,
                        ["sizeBytes"] = 8388608,
                    },
                },
                ["partitions"] = new JsonArray(),
                ["stores"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["id"] = storeIdA,
                        ["uuid"] = containerHex32,
                        ["partitionId"] = string.Empty,
                        ["containerId"] = $"apfs-container:{containerHex32}",
                        ["offsetBytes"] = 0,
                        ["sizeBytes"] = 8388608,
                    },
                    new JsonObject
                    {
                        ["id"] = storeIdB,
                        ["uuid"] = containerHex32,
                        ["partitionId"] = string.Empty,
                        ["containerId"] = $"apfs-container:{containerHex32}",
                        ["offsetBytes"] = 0,
                        ["sizeBytes"] = 8388608,
                    },
                },
                ["containers"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["id"] = $"apfs-container:{containerHex32}",
                        ["uuid"] = containerHex32,
                        ["blockSizeBytes"] = 4096,
                        ["storeIds"] = new JsonArray { storeIdA, storeIdB },
                        ["volumeIds"] = volumeIds,
                        ["fusion"] = true,
                        ["checkpointXid"] = checkpointXid.ToString(),
                        ["compatibleFeatureBits"] = new JsonArray { "0x1" },
                        ["readonlyFeatureBits"] = new JsonArray(),
                        ["unknownFeatureBits"] = new JsonArray(),
                        ["incompatibleFeatureBits"] = new JsonArray(),
                    },
                },
                ["volumes"] = volumeNodes,
                ["groups"] = new JsonArray(),
            },
        }.ToJsonString();
    }

    private static string SlugOf(string devicePath)
    {
        var slash = devicePath.LastIndexOfAny(['/', '\\']);
        var baseName = slash < 0 ? devicePath : devicePath[(slash + 1)..];
        var slug = new string(baseName.Select(ch => char.IsLetterOrDigit(ch) || ch is '.' or '_' or '-' ? ch : '-').ToArray()).TrimStart('-');
        return string.IsNullOrEmpty(slug) ? "device" : slug;
    }

    internal static string BuildContainers(
        (string ContainerHex32, VolumeJson[] Volumes)[] containers,
        string deviceSlug = "test-image",
        ulong checkpointXid = 7,
        string profile = "managed-discovery",
        string? devicePath = null)
    {
        ArgumentNullException.ThrowIfNull(containers);
        // Path-bound source identity for the discovery bind gate: the real
        // observer echoes the probed path, and BindDiscoveryTopology refuses
        // rows from any other source. When devicePath is supplied, the
        // envelope carries it (source + sole disk) exactly like BuildFusionPair.
        var boundSlug = devicePath is null ? deviceSlug : SlugOf(devicePath);
        var boundIdentifier = devicePath ?? deviceSlug;
        var boundPath = devicePath ?? "given-path";
        var storeNodes = new JsonArray();
        var containerNodes = new JsonArray();
        var volumeNodes = new JsonArray();
        foreach (var (containerHex32, volumes) in containers)
        {
            var volumeIds = new JsonArray();
            foreach (var volume in volumes)
            {
                var volumeId = $"apfs-vol:{containerHex32}:{volume.ObjectId}";
                volumeIds.Add(volumeId);
                volumeNodes.Add(BuildVolumeNode(containerHex32, volume, checkpointXid));
            }

            storeNodes.Add(new JsonObject
            {
                ["id"] = $"apfs-store:{containerHex32}",
                ["uuid"] = containerHex32,
                ["partitionId"] = string.Empty,
                ["containerId"] = $"apfs-container:{containerHex32}",
                ["offsetBytes"] = 0,
                ["sizeBytes"] = 8388608,
            });
            containerNodes.Add(new JsonObject
            {
                ["id"] = $"apfs-container:{containerHex32}",
                ["uuid"] = containerHex32,
                ["blockSizeBytes"] = 4096,
                ["storeIds"] = new JsonArray { $"apfs-store:{containerHex32}" },
                ["volumeIds"] = volumeIds,
                ["fusion"] = false,
                ["checkpointXid"] = checkpointXid.ToString(),
                ["compatibleFeatureBits"] = new JsonArray { "0x1" },
                ["readonlyFeatureBits"] = new JsonArray(),
                ["unknownFeatureBits"] = new JsonArray(),
                ["incompatibleFeatureBits"] = new JsonArray(),
            });
        }

        var evidence = new JsonObject
        {
            ["format"] = "apfs-access-raw-evidence",
            ["version"] = 1,
            ["observerId"] = "apfs-access-owned-raw-observer",
            ["observerVersion"] = "1.0.0",
            ["mode"] = "collect",
            ["profile"] = profile,
            ["synthetic"] = false,
            ["source"] = new JsonObject
            {
                ["kind"] = "image",
                ["path"] = boundPath,
                ["sizeBytes"] = 8388608,
                ["hashScope"] = "none",
                ["sha256"] = null,
            },
            ["secondarySources"] = new JsonArray(),
            ["topology"] = new JsonObject
            {
                ["disks"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["id"] = $"apfs-disk:{boundSlug}",
                        ["deviceIdentifier"] = boundIdentifier,
                        ["uuid"] = null,
                        ["sizeBytes"] = 8388608,
                    },
                },
                ["partitions"] = new JsonArray(),
                ["stores"] = storeNodes,
                ["containers"] = containerNodes,
                ["volumes"] = volumeNodes,
                ["groups"] = new JsonArray(),
            },
        };
        return evidence.ToJsonString();
    }

    private static JsonObject BuildVolumeNode(string containerHex32, VolumeJson volume, ulong checkpointXid)
        => new()
        {
            ["id"] = $"apfs-vol:{containerHex32}:{volume.ObjectId}",
            ["uuid"] = string.Empty,
            ["objectId"] = volume.ObjectId.ToString(),
            ["containerId"] = $"apfs-container:{containerHex32}",
            ["name"] = volume.Name,
            ["nameUtf8Valid"] = true,
            ["roles"] = new JsonArray((volume.Roles ?? ["data"]).Select(role => (JsonNode)role).ToArray()),
            ["roleRaw"] = (long)volume.Role,
            ["groupId"] = null,
            ["caseMode"] = "insensitive",
            ["encryptionMode"] = volume.EncryptionMode,
            ["locked"] = volume.Locked,
            ["compatibleFeatureBits"] = ToBits(volume.Features),
            ["readonlyFeatureBits"] = ToBits(volume.ReadonlyFeatures),
            ["unknownFeatureBits"] = new JsonArray(),
            ["incompatibleFeatureBits"] = volume.IncompatibleFeatures == 0x1 ? new JsonArray() : ToBits(volume.IncompatibleFeatures),
            ["superblockBlock"] = "12",
            ["superblockXid"] = checkpointXid.ToString(),
        };

    private static JsonArray ToBits(ulong value)
    {
        var bits = new JsonArray();
        for (var bit = 0; bit < 64; bit++)
        {
            if ((value & (1UL << bit)) != 0)
            {
                bits.Add($"0x{(1UL << bit):x}");
            }
        }

        return bits;
    }
}
