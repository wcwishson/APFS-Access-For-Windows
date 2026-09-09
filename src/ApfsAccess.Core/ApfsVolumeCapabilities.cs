namespace ApfsAccess.Core;

// Single capability decision for a volume mount target, derived from parsed
// observer flags only (freeze section 4). Managed code treats every feature
// list opaquely: it never interprets individual bit values.
public enum ApfsCapabilityDecision
{
    Writable = 0,
    Readable = 1,
    Locked = 2,
    ReadOnlyFeature = 3,
    Unsupported = 4,
}

public sealed record ApfsVolumeCapability(
    ApfsCapabilityDecision Decision,
    IReadOnlyList<string> Reasons,
    bool AutoMountAllowed);

public static class ApfsVolumeCapabilities
{
    public const string ReasonUnknownIncompatibleBits = "unknown-incompatible-bits";
    public const string ReasonUnknownFeatures = "unknown-features";
    public const string ReasonReadonlyFeatures = "readonly-features";
    public const string ReasonLockedEncrypted = "locked-encrypted";

    public static string SpecialRoleReason(string role) => "special-role:" + role;

    // Refusals and role evidence must survive coexisting readonly features:
    // incompatible -> unknown -> encryption/locked -> roles -> readonly.
    // Only Writable allows automount. Compatible bits never gate.
    public static ApfsVolumeCapability Evaluate(ApfsVolumeRecord volume, ApfsContainerRecord container)
    {
        ArgumentNullException.ThrowIfNull(volume);
        ArgumentNullException.ThrowIfNull(container);

        if (volume.IncompatibleFeatureBits.Count > 0 || container.IncompatibleFeatureBits.Count > 0)
        {
            return new ApfsVolumeCapability(
                ApfsCapabilityDecision.Unsupported, [ReasonUnknownIncompatibleBits], false);
        }

        if (volume.UnknownFeatureBits.Count > 0 || container.UnknownFeatureBits.Count > 0)
        {
            // Frozen NOTE: unknownFeatureBits covers readonly-unknown bits too,
            // so every unknown entry is Unsupported (conservative).
            return new ApfsVolumeCapability(
                ApfsCapabilityDecision.Unsupported, [ReasonUnknownFeatures], false);
        }

        if (volume.Locked ||
            string.Equals(volume.EncryptionMode, "password", StringComparison.Ordinal) ||
            string.Equals(volume.EncryptionMode, "hardware-bound", StringComparison.Ordinal) ||
            string.Equals(volume.EncryptionMode, "unknown", StringComparison.Ordinal))
        {
            return new ApfsVolumeCapability(
                ApfsCapabilityDecision.Locked, [ReasonLockedEncrypted], false);
        }

        var specialRoles = volume.Roles
            .Where(role => !string.Equals(role, "data", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        // Empty role lists cannot occur in schema-valid evidence; fail closed
        // as unknown rather than promoting to writable.
        if (volume.Roles.Count == 0 || specialRoles.Length > 0)
        {
            var reasons = volume.Roles.Count == 0
                ? new[] { SpecialRoleReason("unknown") }
                : specialRoles.Select(SpecialRoleReason).ToArray();
            return new ApfsVolumeCapability(ApfsCapabilityDecision.Readable, reasons, false);
        }

        // Only ordinary, unlocked roles reach this verdict, so readonly features
        // cannot hide a role that the inspection policy would otherwise refuse.
        if ((volume.ReadonlyFeatureBits?.Count ?? 0) > 0 ||
            (container.ReadonlyFeatureBits?.Count ?? 0) > 0)
        {
            return new ApfsVolumeCapability(
                ApfsCapabilityDecision.ReadOnlyFeature, [ReasonReadonlyFeatures], false);
        }

        return new ApfsVolumeCapability(ApfsCapabilityDecision.Writable, [], true);
    }
}
