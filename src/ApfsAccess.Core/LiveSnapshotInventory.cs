using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ApfsAccess.Core;

public sealed record LiveSnapshotEntry(string Xid, string CreateTimeNs, string Name,
    string SuperblockPhysicalBlock, string OmapPhysicalBlock, string OmapTreePhysicalBlock,
    string RootOid, string RootPhysicalBlock, string ExtentrefPhysicalBlock)
{
    public IReadOnlyList<string> DeleteIdentity(string checkpointXid) =>
        [Xid, Name, SuperblockPhysicalBlock, OmapPhysicalBlock, OmapTreePhysicalBlock,
            RootOid, RootPhysicalBlock, ExtentrefPhysicalBlock, checkpointXid];
}

public sealed record LiveSnapshotInventory(string ContainerUuid, string VolumeUuid, string VolumeOid,
    string CheckpointXid, string StoreOffsetBytes, string StoreSizeBytes, IReadOnlyList<LiveSnapshotEntry> Snapshots)
{
    public const int MaximumResponseBytes = 128 * 1024;
    public const string Format = "apfs-access-live-snapshot-inventory";

    public bool MatchesScope(VerifyScope scope) =>
        TopologyAdmission.SameUuid(ContainerUuid, scope.ContainerId[15..]) &&
        TopologyAdmission.SameUuid(VolumeUuid, scope.VolumeUuid) && VolumeOid == scope.VolumeObjectId &&
        StoreOffsetBytes == scope.StoreOffsetBytes && StoreSizeBytes == scope.StoreSizeBytes;

    public bool MatchesScope(LiveVolumeVerificationScope scope) =>
        TopologyAdmission.SameUuid(ContainerUuid, scope.ContainerUuid) &&
        TopologyAdmission.SameUuid(VolumeUuid, scope.VolumeUuid) && VolumeOid == scope.VolumeOid &&
        StoreOffsetBytes == scope.StoreOffsetBytes && StoreSizeBytes == scope.StoreSizeBytes;

    public JsonElement ToJson() => JsonSerializer.SerializeToElement(new
    {
        format = Format, version = 1, containerUuid = ContainerUuid, volumeUuid = VolumeUuid,
        volumeOid = VolumeOid, checkpointXid = CheckpointXid, storeOffsetBytes = StoreOffsetBytes,
        storeSizeBytes = StoreSizeBytes, snapshots = Snapshots.Select(s => new
        {
            xid = s.Xid, createTimeNs = s.CreateTimeNs, name = s.Name, uuid = (string?)null,
            superblockPhysicalBlock = s.SuperblockPhysicalBlock, omapPhysicalBlock = s.OmapPhysicalBlock,
            omapTreePhysicalBlock = s.OmapTreePhysicalBlock, rootOid = s.RootOid,
            rootPhysicalBlock = s.RootPhysicalBlock, extentrefPhysicalBlock = s.ExtentrefPhysicalBlock
        })
    });

    public static LiveSnapshotInventory Parse(JsonElement root)
    {
        try
        {
            if (Encoding.UTF8.GetByteCount(root.GetRawText()) > MaximumResponseBytes)
                throw new InvalidDataException("Snapshot inventory exceeds the response bound.");
            Fields(root, "format", "version", "containerUuid", "volumeUuid", "volumeOid", "checkpointXid",
                "storeOffsetBytes", "storeSizeBytes", "snapshots");
            if (Text(root, "format") != Format || root.GetProperty("version").GetRawText() != "1")
                throw new InvalidDataException("Snapshot inventory format or version is invalid.");
            var container = Uuid(root, "containerUuid"); var volume = Uuid(root, "volumeUuid");
            var oid = Number(root, "volumeOid"); var checkpoint = Number(root, "checkpointXid");
            var offset = Number(root, "storeOffsetBytes", true); var size = Number(root, "storeSizeBytes");
            if (ulong.Parse(size, CultureInfo.InvariantCulture) > ulong.MaxValue - ulong.Parse(offset, CultureInfo.InvariantCulture))
                throw new InvalidDataException("Snapshot inventory window overflows.");
            var items = root.GetProperty("snapshots");
            if (items.ValueKind != JsonValueKind.Array || items.GetArrayLength() > 64)
                throw new InvalidDataException("Snapshot inventory count is invalid.");
            var entries = new List<LiveSnapshotEntry>(); var names = new HashSet<string>(StringComparer.Ordinal);
            ulong previous = 0;
            foreach (var item in items.EnumerateArray())
            {
                Fields(item, "xid", "createTimeNs", "name", "uuid", "superblockPhysicalBlock", "omapPhysicalBlock",
                    "omapTreePhysicalBlock", "rootOid", "rootPhysicalBlock", "extentrefPhysicalBlock");
                var xid = Number(item, "xid"); var value = ulong.Parse(xid, CultureInfo.InvariantCulture);
                var name = Text(item, "name");
                if (value <= previous || name.Length is < 1 or > 255 || name.Any(c => c is '\0' or '\r' or '\n') ||
                    !names.Add(name) || item.GetProperty("uuid").ValueKind != JsonValueKind.Null)
                    throw new InvalidDataException("Snapshot inventory identity is invalid or duplicated.");
                previous = value;
                entries.Add(new(xid, Number(item, "createTimeNs", true), name,
                    Number(item, "superblockPhysicalBlock"), Number(item, "omapPhysicalBlock"),
                    Number(item, "omapTreePhysicalBlock"), Number(item, "rootOid"),
                    Number(item, "rootPhysicalBlock"), Number(item, "extentrefPhysicalBlock")));
            }
            return new(container, volume, oid, checkpoint, offset, size, entries);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException)
        { throw new InvalidDataException("Malformed live snapshot inventory.", ex); }
    }

    private static void Fields(JsonElement item, params string[] fields)
    {
        if (item.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected snapshot object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in item.EnumerateObject())
            if (!fields.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name))
                throw new InvalidDataException("Unknown or duplicate snapshot field.");
        if (seen.Count != fields.Length) throw new InvalidDataException("Missing snapshot field.");
    }

    private static string Text(JsonElement item, string key) => item.GetProperty(key).GetString()
        ?? throw new InvalidDataException("Missing snapshot text.");

    private static string Uuid(JsonElement item, string key)
    {
        var text = Text(item, key);
        if (text.Length != 32 || text.All(c => c == '0') || text.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new InvalidDataException("Invalid snapshot UUID.");
        return text;
    }

    private static string Number(JsonElement item, string key, bool allowZero = false)
    {
        var text = Text(item, key);
        if (!ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ||
            (!allowZero && value == 0) || value.ToString(CultureInfo.InvariantCulture) != text)
            throw new InvalidDataException("Invalid snapshot decimal identity.");
        return text;
    }
}
