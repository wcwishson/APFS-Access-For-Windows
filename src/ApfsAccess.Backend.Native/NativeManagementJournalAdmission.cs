using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public static class NativeManagementJournalAdmission
{
    public static void RequireClearRoot(string? root, bool allowNativeEvidence = false)
        => RequireClearRoot(root, allowNativeEvidence, null);

    private static void RequireClearRoot(string? root, bool allowNativeEvidence, string? originalRepairPlanId)
    {
        if (root is null) throw new IOException("ManagementJournalRoot inspection is required before image mutation.");
        NativeApfsVolumeManagement.ValidateStoreRoot(root);
        ImageRepairPersistence.RequireNoPending(root, originalRepairPlanId);
        var count = 0;
        foreach (var entry in Directory.EnumerateFileSystemEntries(root))
        {
            if (++count > 2048) throw new IOException("ManagementJournalRoot census exceeds its bound.");
            var attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("ManagementJournalRoot contains an unproved alias.");
            if (!allowNativeEvidence && (Path.GetFileName(entry).Contains(".vmt1", StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileName(entry).Contains(".vif1", StringComparison.OrdinalIgnoreCase)) ||
                (Path.GetFileName(entry).StartsWith("managed-", StringComparison.OrdinalIgnoreCase) &&
                 !Path.GetFileName(entry).StartsWith("managed-volume-", StringComparison.Ordinal) &&
                 !Path.GetFileName(entry).StartsWith(ImageRepairPersistence.Prefix, StringComparison.Ordinal)) ||
                Path.GetFileName(entry).StartsWith("ordinary-image-", StringComparison.Ordinal) && Path.GetExtension(entry) != ".json")
                throw new IOException("Management journal disposition is unproved: " + entry);
        }
    }
    public static void RequireImage(string? root, string image, string offset, VolumeTopologyRequest? original = null)
        => RequireImageCore(root, image, offset, original, null);

    internal static void RequireRepairImage(ImageRepairInvocation invocation, ImageRepairIntent? original)
    {
        if (original is not null && (!original.Pending || original.Offer != invocation.Approval ||
            original.Offer.Scope != invocation.Scope || original.JournalPath != invocation.JournalPath ||
            original.EvidenceDirectory != invocation.EvidenceDirectory || original.JournalRoot != invocation.JournalRoot))
            throw new IOException("ImageRepairOriginalAcceptedLineageRequired");
        RequireImageCore(invocation.JournalRoot, invocation.Scope.ImagePath, invocation.Scope.StoreOffsetBytes, null, original?.Offer.PlanId);
    }

    private static void RequireImageCore(string? root, string image, string offset, VolumeTopologyRequest? original, string? originalRepairPlanId)
    {
        RequireClearRoot(root, true, originalRepairPlanId);
        var tool = new[] { Path.Combine(AppContext.BaseDirectory, "VolumeKeeperInspect.exe"),
            Path.Combine(AppContext.BaseDirectory, "native", "VolumeKeeperInspect.exe") }
            .FirstOrDefault(p => File.Exists(p) && NativeApfsObserver.IsPackagedObserverPath(p)) ??
            throw new IOException("VolumeKeeperInspectNotPackaged");
        NativeApfsSnapshotReader.ValidateLocalFile(tool);
        var before = NativeApfsVolumeManagement.SourceIdentity(image, offset, false);
        var wire = new ProcessObserverRunner().Run(tool, ["--image", image, "--offset", offset, "--journal-directory", root!], CancellationToken.None);
        ValidateInspection(wire, root!, before, original);
        if (before != NativeApfsVolumeManagement.SourceIdentity(image, offset, false)) throw new IOException("KeeperInspectionSourceChanged");
    }
    internal static void ValidateInspection(ObserverRunResult wire, string root, string source, VolumeTopologyRequest? original)
    {
        if (System.Text.Encoding.UTF8.GetByteCount(wire.StandardOutput) > 1024 * 1024) throw new InvalidDataException("Keeper inspection exceeds its bound.");
        using var document = System.Text.Json.JsonDocument.Parse(wire.StandardOutput);
        var j = document.RootElement;
        void Need(bool ok, string reason) { if (!ok) throw new InvalidDataException(reason); }
        void Fields(System.Text.Json.JsonElement e, string names)
        { var fields = names.Split(' ').ToHashSet(); foreach (var p in e.EnumerateObject()) Need(fields.Remove(p.Name), "Unknown or duplicate keeper inspection field."); Need(fields.Count == 0, "Missing keeper inspection field."); }
        Fields(j, "schemaVersion admitted error sourceIdentity locator journals");
        Need(j.GetProperty("schemaVersion").GetInt32() == 1 && j.GetProperty("sourceIdentity").GetString() == source &&
            j.GetProperty("locator").GetString() == source[..64], "Keeper inspection source binding mismatch.");
        var journals = j.GetProperty("journals").EnumerateArray().ToArray();
        Need(journals.Length is >= 2 and <= 2050, "Keeper inspection journal census missing.");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var canonical = new HashSet<string>();
        var blocked = false;
        var allowedOwn = original is null ? null : original.ImageOptions is null ? "vmt1" : "vif1";
        foreach (var entry in journals)
        {
            Fields(entry, "family path state error");
            var family = entry.GetProperty("family").GetString(); var path = entry.GetProperty("path").GetString();
            var state = entry.GetProperty("state").GetString(); var error = entry.GetProperty("error").GetString();
            Need(family is "vmt1" or "vif1" && ApfsAccess.Core.VolumeTopologyProfile.LocalPath(path) &&
                string.Equals(Path.GetDirectoryName(path), root, StringComparison.OrdinalIgnoreCase) && seen.Add(path!), "Keeper inspection path/family mismatch.");
            var isCanonical = path!.EndsWith("." + family, StringComparison.Ordinal);
            if (isCanonical) Need(canonical.Add(family!), "Duplicate canonical keeper journal.");
            Need(state is "missing" or "prepared" or "accepted" or "anchor-durable" or "completed" or "cancelled" or "invalid" && error is not null, "Unknown keeper journal state.");
            if (state is "missing" or "completed" or "cancelled") { Need(error == "", "Terminal keeper evidence contains an error."); continue; }
            blocked = true;
            Need(original is not null && original.SourceIdentity[..64] == source[..64] && family == allowedOwn && isCanonical &&
                state is "prepared" or "accepted" or "anchor-durable" && error == "", "Pending or invalid foreign keeper evidence blocks this operation.");
        }
        Need(canonical.SetEquals(["vmt1", "vif1"]), "Incomplete keeper family census.");
        var admitted = j.GetProperty("admitted").GetBoolean(); var diagnostic = j.GetProperty("error").GetString();
        Need(admitted == !blocked && wire.ExitCode == (admitted ? 0 : 1) &&
            (admitted ? diagnostic == "" : diagnostic?.StartsWith("VolumeKeeperAdmissionBlocked:", StringComparison.Ordinal) == true), "Keeper inspection exit or disposition mismatch.");
    }
}
