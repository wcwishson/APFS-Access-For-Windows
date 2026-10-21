using System.Globalization;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Tray;

public sealed record SnapshotInventoryEntry(string Name, string Xid, string CreateTimeNs, IReadOnlyList<string> DeleteIdentity)
{
    internal JsonElement? NativeIdentity { get; init; }
}

public sealed record SnapshotInventoryView(string CheckpointXid, IReadOnlyList<SnapshotInventoryEntry> Entries)
{
    internal JsonElement? ImageInventory { get; init; }
    public static SnapshotInventoryView Parse(JsonElement inventory, DriveDashboardRow row)
    {
        try
        {
            if (inventory.TryGetProperty("format", out var format) && format.GetString() == LiveSnapshotInventory.Format)
            {
                var live = LiveSnapshotInventory.Parse(inventory);
                if (row.SnapshotScope is null || !live.MatchesScope(row.SnapshotScope))
                    throw new InvalidDataException("Live snapshot inventory belongs to a different source window.");
                return new(live.CheckpointXid, live.Snapshots.Select(s =>
                    new SnapshotInventoryEntry(s.Name, s.Xid, s.CreateTimeNs, s.DeleteIdentity(live.CheckpointXid))).ToArray());
            }
            if (inventory.GetProperty("format").GetString() != "apfs-access-snapshot-inventory" ||
                inventory.GetProperty("version").GetInt32() != 1 || !inventory.GetProperty("readOnly").GetBoolean() ||
                !string.Equals(inventory.GetProperty("source").GetProperty("path").GetString(), row.DeviceId, StringComparison.OrdinalIgnoreCase) ||
                !TopologyAdmission.SameUuid(inventory.GetProperty("containerUuid").GetString(), row.CatalogContainerUuid) ||
                !TopologyAdmission.SameUuid(inventory.GetProperty("volumeUuid").GetString(), row.CatalogVolumeUuid) ||
                inventory.GetProperty("volumeOid").GetString() != row.CatalogVolumeObjectId?.ToString(CultureInfo.InvariantCulture))
                throw new InvalidDataException("Snapshot inventory belongs to a different volume.");
            var checkpoint = Number(inventory, "checkpointXid");
            var entries = new List<SnapshotInventoryEntry>();
            var names = new HashSet<string>(StringComparer.Ordinal);
            var xids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in inventory.GetProperty("snapshots").EnumerateArray())
            {
                var name = item.GetProperty("name").GetString();
                var xid = Number(item, "xid");
                if (name is null || name.Length is < 1 or > 255 || name.Any(c => c is '\0' or '\r' or '\n') ||
                    !names.Add(name) || !xids.Add(xid)) throw new InvalidDataException("Invalid snapshot name or duplicate identity.");
                string[] identity = [xid, name, Number(item, "superblockPhysicalBlock"), Number(item, "omapPhysicalBlock"),
                    Number(item, "omapTreePhysicalBlock"), Number(item, "rootOid"), Number(item, "rootPhysicalBlock"),
                    Number(item, "extentrefPhysicalBlock"), checkpoint];
                entries.Add(new(name, xid, Number(item, "createTimeNs", true), identity) { NativeIdentity = item.Clone() });
            }
            return new(checkpoint, entries) { ImageInventory = inventory.Clone() };
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { throw new InvalidDataException("Service returned malformed snapshot inventory.", ex); }
    }

    private static string Number(JsonElement item, string key, bool allowZero = false)
    {
        var text = item.GetProperty(key).GetString();
        if (!ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ||
            (!allowZero && value == 0) || value.ToString(CultureInfo.InvariantCulture) != text)
            throw new InvalidDataException("Invalid snapshot numeric identity.");
        return text!;
    }
}
