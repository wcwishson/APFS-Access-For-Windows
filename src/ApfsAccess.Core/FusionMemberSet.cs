using System.Text.Json.Serialization;

namespace ApfsAccess.Core;

// Authoritative managed identity for one complete two-member Fusion set.
// This is the single shared Fusion member-set model for native observer
// output, backend discovery, service, CLI, tray projection, and recovery.
// Content/role truth stays native (NXSB fusion UUID + role bit + exact file
// identity verified at open/bind); this record binds the exact observed
// member paths to their catalog store IDs, container UUID, and checkpoint
// generation so every layer names the same set. Members are always stored in
// canonical StoreId-ordinal order with the disk order's file attached
// positionally (both lists are complete two-element sets from one observed
// invocation); tier roles are established natively at open, never here, so
// swapped CLI inputs deterministically fail the path-echo check instead of
// silently swapping members. Anything but a complete observed pair fails
// closed via TryCreate: missing, duplicated, swapped, ambiguous,
// generation-mismatched, or malformed inputs never yield a set.
public sealed record FusionMemberRecord(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("storeId")] string StoreId,
    [property: JsonPropertyName("sizeBytes")] long SizeBytes,
    [property: JsonPropertyName("sha256")] string? Sha256);

public sealed record FusionMemberSet(
    [property: JsonPropertyName("containerUuid")] string ContainerUuid,
    [property: JsonPropertyName("checkpointXid")] string CheckpointXid,
    [property: JsonPropertyName("primaryPath")] string PrimaryPath,
    [property: JsonPropertyName("members")] IReadOnlyList<FusionMemberRecord> Members)
{
    public static bool TryCreate(
        ApfsObserverEvidence evidence,
        string deviceIdA,
        string deviceIdB,
        out FusionMemberSet? set,
        out string error)
    {
        set = null;
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(deviceIdA) || string.IsNullOrWhiteSpace(deviceIdB) ||
            string.Equals(deviceIdA, deviceIdB, StringComparison.OrdinalIgnoreCase))
        {
            error = "Fusion members must be two distinct store paths.";
            return false;
        }

        var snapshot = evidence.Topology;
        if (snapshot is null ||
            !string.Equals(evidence.Mode, "fusion", StringComparison.Ordinal) ||
            evidence.Source is null ||
            !string.Equals(evidence.Source.Path, deviceIdA, StringComparison.OrdinalIgnoreCase) ||
            evidence.SecondarySources is not { Count: 1 } ||
            evidence.SecondarySources[0] is null ||
            !string.Equals(evidence.SecondarySources[0].Path, deviceIdB, StringComparison.OrdinalIgnoreCase) ||
            snapshot.Disks.Count != 2 || snapshot.Stores.Count != 2 || snapshot.Containers.Count != 1)
        {
            error = "Fusion evidence is not a complete observed two-member set.";
            return false;
        }

        var disks = snapshot.Disks.Where(static d => d is not null).ToArray();
        var stores = snapshot.Stores.Where(static s => s is not null).ToArray();
        if (disks.Length != 2 || stores.Length != 2)
        {
            error = "Fusion evidence members are ambiguous.";
            return false;
        }

        var diskIdentifiers = new HashSet<string>(
            disks.Select(static d => d.DeviceIdentifier), StringComparer.OrdinalIgnoreCase);
        if (diskIdentifiers.Count != 2 ||
            !diskIdentifiers.Contains(deviceIdA) ||
            !diskIdentifiers.Contains(deviceIdB))
        {
            error = "Fusion evidence disks do not echo both member paths.";
            return false;
        }

        var container = snapshot.Containers[0];
        if (container is null || !container.Fusion || container.StoreIds.Count != 2)
        {
            error = "Fusion evidence has no single two-store Fusion container.";
            return false;
        }

        var declared = new HashSet<string>(container.StoreIds, StringComparer.Ordinal);
        var actual = new HashSet<string>(stores.Select(static s => s.Id), StringComparer.Ordinal);
        if (!declared.SetEquals(actual))
        {
            error = "Fusion container store list does not match observed stores.";
            return false;
        }

        var sources = new[] { evidence.Source, evidence.SecondarySources[0] };
        var orderedDisks = disks.OrderBy(static d => d.Id, StringComparer.Ordinal).ToArray();
        var orderedStores = stores.OrderBy(static s => s.Id, StringComparer.Ordinal).ToArray();
        var members = new List<FusionMemberRecord>(2);
        for (var i = 0; i < 2; i++)
        {
            var source = sources.FirstOrDefault(s =>
                string.Equals(s.Path, orderedDisks[i].DeviceIdentifier, StringComparison.OrdinalIgnoreCase));
            if (source is null || source.SizeBytes < 1)
            {
                error = "Fusion member file evidence is missing.";
                return false;
            }

            members.Add(new FusionMemberRecord(
                source.Path, orderedStores[i].Id, source.SizeBytes, source.Sha256));
        }

        set = new FusionMemberSet(
            container.Uuid, container.CheckpointXid, deviceIdA, members);
        return true;
    }
}
