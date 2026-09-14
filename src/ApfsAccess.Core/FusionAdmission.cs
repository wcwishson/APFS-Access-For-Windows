namespace ApfsAccess.Core;

// Complete-set mount gate for Fusion containers. Pure and total: given one
// catalog container record and an optional proven FusionMemberSet, it decides
// whether the set may be treated as a coherent mountable unit. A missing,
// mismatched, or stale set is never healthy: it yields an explicit refusal
// reason naming the defect. Non-Fusion containers are not this gate's
// concern and pass through as SingleStore. This gate does not open anything
// by itself; mount flows must require Complete and surface Reason otherwise.
// Tier roles and content identity stay native (verified at open/bind).
public static class FusionAdmission
{
    public sealed record Decision(bool Complete, string ReasonCode, string Message);

    public static Decision Evaluate(ApfsContainerRecord container, FusionMemberSet? provenSet)
    {
        ArgumentNullException.ThrowIfNull(container);
        if (!container.Fusion)
        {
            return new Decision(true, "SingleStore", "Container is not Fusion-backed.");
        }

        if (provenSet is null)
        {
            return new Decision(false, "FusionIncompleteMemberSet",
                $"Fusion container '{container.Id}' has no proven two-member set; refusing a partial mount.");
        }

        // This gate is pure and total: JSON-shaped nulls (missing arrays,
        // null members) from deserialized evidence must refuse, never
        // throw. NullReferenceException here would be a fail-open crash
        // in exactly the malformed inputs this gate exists to catch.
        // Whitespace-only identifiers refuse too: blank strings survive
        // JSON exactly like nulls, and equal garbage must never pass an
        // identity check. Independent review findings.
        if (string.IsNullOrWhiteSpace(provenSet.ContainerUuid) || string.IsNullOrWhiteSpace(container.Uuid))
        {
            return new Decision(false, "FusionContainerMismatch",
                $"Proven set container '{provenSet.ContainerUuid}' does not match container '{container.Uuid}'.");
        }

        if (!string.Equals(provenSet.ContainerUuid, container.Uuid, StringComparison.OrdinalIgnoreCase))
        {
            return new Decision(false, "FusionContainerMismatch",
                $"Proven set container '{provenSet.ContainerUuid}' does not match container '{container.Uuid}'.");
        }

        if (provenSet.Members is not { Count: 2 } ||
            provenSet.Members.Any(static m => m is null || string.IsNullOrEmpty(m.StoreId)))
        {
            return new Decision(false, "FusionIncompleteMemberSet",
                $"Proven set for container '{container.Uuid}' does not name two valid members.");
        }

        var provenStores = provenSet.Members.Select(static m => m.StoreId).ToArray();
        if (new HashSet<string>(provenStores, StringComparer.Ordinal).Count != 2)
        {
            return new Decision(false, "FusionIncompleteMemberSet",
                $"Proven set for container '{container.Uuid}' does not name two distinct members.");
        }

        if (container.StoreIds is not { Count: 2 } ||
            new HashSet<string>(container.StoreIds, StringComparer.Ordinal).Count != 2)
        {
            return new Decision(false, "FusionStoreMismatch",
                $"Proven member stores do not match Fusion container '{container.Id}' store list.");
        }

        var declared = new HashSet<string>(container.StoreIds, StringComparer.Ordinal);
        var proven = new HashSet<string>(provenStores, StringComparer.Ordinal);
        if (!declared.SetEquals(proven))
        {
            return new Decision(false, "FusionStoreMismatch",
                $"Proven member stores do not match Fusion container '{container.Id}' store list.");
        }

        if (string.IsNullOrWhiteSpace(provenSet.CheckpointXid) || string.IsNullOrWhiteSpace(container.CheckpointXid) ||
            !string.Equals(provenSet.CheckpointXid, container.CheckpointXid, StringComparison.Ordinal))
        {
            return new Decision(false, "FusionGenerationMismatch",
                $"Proven set generation '{provenSet.CheckpointXid}' is stale for container '{container.Id}' " +
                $"at generation '{container.CheckpointXid}'.");
        }

        return new Decision(true, "FusionCompleteSet",
            $"Fusion container '{container.Id}' has a complete proven two-member set.");
    }
}
