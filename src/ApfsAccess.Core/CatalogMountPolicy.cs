namespace ApfsAccess.Core;

// Consume the catalog's typed verdict, never APFS role/feature bits. Identity
// fields alone are also used by legacy backends and are not a capability verdict.
public static class CatalogMountPolicy
{
    public static bool AllowsOrdinaryMount(ApfsCapabilityDecision? decision,
        IReadOnlyList<string>? reasons, bool? autoMountAllowed)
        => IsLegacy(decision, reasons, autoMountAllowed) ||
           decision == ApfsCapabilityDecision.Writable &&
           reasons is { Count: 0 } && autoMountAllowed == true;

    public static bool AllowsOrdinaryMount(VolumeInfo volume)
        => AllowsOrdinaryMount(volume.CatalogDecision, volume.CatalogReasons, volume.CatalogAutoMountAllowed);

    public static bool AllowsReadOnlyInspection(VolumeInfo volume)
    {
        if (volume.IsEncrypted || !volume.SupportsExplorerMount) return false;
        if (AllowsOrdinaryMount(volume)) return true;
        if (volume.CatalogAutoMountAllowed != false || volume.CatalogReasons is not { Count: > 0 } reasons)
            return false;

        return volume.CatalogDecision switch
        {
            ApfsCapabilityDecision.Readable => reasons.All(IsKnownSpecialRoleReason),
            ApfsCapabilityDecision.ReadOnlyFeature => reasons.All(reason =>
                reason == ApfsVolumeCapabilities.ReasonReadonlyFeatures),
            _ => false,
        };
    }

    public static bool AllowsMount(VolumeInfo volume, bool explicitReadOnlyInspection)
        => !volume.IsEncrypted && volume.SupportsExplorerMount &&
           (explicitReadOnlyInspection ? AllowsReadOnlyInspection(volume) : AllowsOrdinaryMount(volume));

    public static string Refusal(VolumeInfo volume, MountAccessMode? requestedMode)
        => $"Volume '{volume.VolumeName}': " +
           (requestedMode == MountAccessMode.ReadWrite
               ? "read/write mount refused by catalog mount policy; protected/special roles cannot be made writable. "
               : "automatic mount or inspection refused by catalog mount policy. ") +
           $"Catalog: {volume.CatalogDecision?.ToString() ?? "missing"} " +
           $"({string.Join(", ", volume.CatalogReasons ?? [])}). " +
           (AllowsReadOnlyInspection(volume)
               ? "Use an explicit read-only mount request for this exact volume to inspect it."
               : "The catalog does not prove this volume readable, or Explorer mounting is unavailable.");

    private static bool IsLegacy(ApfsCapabilityDecision? decision, IReadOnlyList<string>? reasons, bool? autoMountAllowed)
        => decision is null && reasons is null && autoMountAllowed is null;

    private static bool IsKnownSpecialRoleReason(string reason) => reason is
        "special-role:system" or "special-role:recovery" or "special-role:vm" or
        "special-role:preboot" or "special-role:installer" or "special-role:baseband" or
        "special-role:ts" or "special-role:update" or "special-role:xart" or
        "special-role:hardware" or "special-role:backup" or "special-role:enterprise" or
        "special-role:prelogin" or "special-role:image";
}
