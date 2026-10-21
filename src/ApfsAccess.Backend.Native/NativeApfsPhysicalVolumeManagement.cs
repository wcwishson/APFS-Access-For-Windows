using System.Globalization;
using System.Text;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsBackend
{
    private NativeRawSnapshotLaunch.HardwareQualification RequirePhysicalVolumeOptions(string? binding, bool enabled)
    {
        var q = NativeRawSnapshotLaunch.CaptureQualification(_options.RawSnapshotHardwareQualification);
        if (q is null || q.Scheme != RawSnapshotHardwareQualificationScheme.QualifiedSerialTuple || q.BusType != 7 ||
            string.IsNullOrWhiteSpace(q.QualifiedSerial) || q.QualifiedVpdType is not null ||
            enabled && (!_options.EnablePhysicalVolumeManagement || !_options.EnableNativeWrite ||
                !_options.NativeWriteAllowRawPhysicalDevices || !_options.NativeWriteRequireCanonicalCommit ||
                !_options.NativeWriteStrictMode || _options.WriteBackendMode != "Native" || _options.AllowWriteOnUnsupportedFeatures))
            throw new IOException("PhysicalVolumeManagementNotQualified");
        if (binding is not null)
        {
            var parsed = VolumePhysicalBinding.Parse(binding);
            if (parsed.Vendor != q.Vendor || parsed.Product != q.Product || parsed.Serial != q.QualifiedSerial) throw new IOException("PhysicalVolumeQualificationChanged");
        }
        return q;
    }

    public Task<VolumeTopologyObservation> ObserveVolumeTopologyAsync(VerifyScope scope, DeviceInventory inventory,
        string operation, CancellationToken token)
    {
        if (!VolumePhysicalBinding.IsDevicePath(scope.ImagePath)) return ObserveVolumeTopologyAsync(scope, inventory, token);
        return Task.Run(() =>
        {
            if (!VolumeTopologyProfile.IsPhysicalManagement(scope, operation) ||
                operation is "format" or "erase" or "grow" or "shrink" && !_options.EnableImageResizeFormat || !_options.EnableImageManagementMutations)
                throw new IOException("PhysicalVolumeOperationUnsupported");
            var qualification = RequirePhysicalVolumeOptions(null, true);
            NativeManagementJournalAdmission.RequireClearRoot(_options.ManagementJournalRoot, true);
            var spool = Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT") ?? throw new IOException("Original production spool root is not configured.");
            var recovery = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT") ?? throw new IOException("Stable recovery root is not configured.");
            NativeApfsVolumeManagement.ValidateStoreRoot(spool);NativeApfsVolumeManagement.ValidateStoreRoot(recovery);
            var tool = new[] { Path.Combine(AppContext.BaseDirectory, "VolumePhysicalObserve.exe"), Path.Combine(AppContext.BaseDirectory, "native", "VolumePhysicalObserve.exe") }
                .FirstOrDefault(p => File.Exists(p) && NativeApfsObserver.IsPackagedObserverPath(p)) ?? throw new IOException("VolumePhysicalObserveNotPackaged");
            NativeApfsSnapshotReader.ValidateLocalFile(tool);
            var wire = _observerRunner.Run(tool, ["--device", scope.ImagePath,
                "--base", scope.StoreOffsetBytes, "--limit", scope.StoreSizeBytes, "--vendor", qualification.Vendor,
                "--product", qualification.Product, "--serial", qualification.QualifiedSerial!, "--container", scope.ContainerId[15..],
                "--volume", scope.VolumeUuid, "--oid", scope.VolumeObjectId, "--xid", scope.CheckpointXid], token);
            return ParsePhysicalObservation(wire, scope, inventory, spool, qualification.Vendor, qualification.Product, qualification.QualifiedSerial);
        }, token);
    }

    internal static VolumeTopologyObservation ParsePhysicalObservation(ObserverRunResult wire, VerifyScope scope,
        DeviceInventory inventory, string spool, string vendor, string product, string? qualifiedSerial = null)
    {
        static void Need(bool ok, string why) { if (!ok) throw new InvalidDataException(why); }
        Need(Encoding.UTF8.GetByteCount(wire.StandardOutput) <= 256 * 1024, "Physical observation exceeds its bound.");
        using var doc = JsonDocument.Parse(wire.StandardOutput);var j = doc.RootElement;
        void Fields(JsonElement e, string names)
        { var fields = names.Split(' ').ToHashSet();foreach (var p in e.EnumerateObject()) Need(fields.Remove(p.Name), "Unknown or duplicate physical observation field.");Need(fields.Count == 0, "Missing physical observation field."); }
        string Text(string key) => j.GetProperty(key).GetString() ?? throw new InvalidDataException("Null physical observation field.");
        Fields(j, "schemaVersion operation readOnly exclusiveLease targetWrites outcome error device image bindingHex offsetBytes storeSizeBytes sourceIdentity containerUuid checkpointXid blockBytes nextOid volumes");
        Need(wire.ExitCode == 0 && j.GetProperty("schemaVersion").GetInt32() == 1 && Text("operation") == "volume-physical-observe" &&
            j.GetProperty("readOnly").GetBoolean() && j.GetProperty("exclusiveLease").GetBoolean() && Text("targetWrites") == "0" &&
            Text("outcome") == "complete" && Text("error") == "", "Physical source observation was not complete.");
        var binding = VolumePhysicalBinding.Parse(Text("bindingHex"));
        Need(VolumeTopologyProfile.IsPhysicalFormat(scope, "format") && Text("device") == scope.ImagePath &&
            Text("image") == binding.Instance && binding.Vendor == vendor && binding.Product == product &&
            (qualifiedSerial is null || binding.Serial == qualifiedSerial) &&
            Text("offsetBytes") == scope.StoreOffsetBytes && binding.BaseOffset.ToString(CultureInfo.InvariantCulture) == scope.StoreOffsetBytes &&
            Text("storeSizeBytes") == scope.StoreSizeBytes && binding.Limit.ToString(CultureInfo.InvariantCulture) == scope.StoreSizeBytes &&
            Text("sourceIdentity") == binding.SourceIdentity && Text("containerUuid") == scope.ContainerId[15..] &&
            Text("checkpointXid") == scope.CheckpointXid && Text("blockBytes") == "4096" && VolumeTopologyProfile.Number(Text("nextOid"), false),
            "Physical observation scope changed.");
        Need(TopologyAdmission.Validate(inventory) && inventory.Device.DeviceId == scope.ImagePath, "Physical inventory source changed.");
        var rows = inventory.Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, Text("containerUuid"))).ToArray();
        var volumes = j.GetProperty("volumes").EnumerateArray().Select(v =>
        {
            Fields(v, "volumeUuid oid");var uuid = v.GetProperty("volumeUuid").GetString();var oid = v.GetProperty("oid").GetString();
            Need(VolumeTopologyProfile.Uuid(uuid) && VolumeTopologyProfile.Number(oid, false), "Invalid physical sibling identity.");
            var selected = rows.Where(r => TopologyAdmission.SameUuid(r.CatalogVolumeUuid, uuid) && r.CatalogVolumeObjectId?.ToString(CultureInfo.InvariantCulture) == oid).ToArray();
            var identity = BuildRecoveryIdentityFromComponents(binding.PartitionGuid, Text("containerUuid"), ulong.Parse(oid!, CultureInfo.InvariantCulture), false);
            Need(selected.Length == 1 && selected[0].RecoveryIdentity == identity && identity is not null, "Physical original WAL identity changed.");
            var derived = VolumeTopologyProfile.DeriveManagementScope(inventory, selected[0], "format");
            Need(derived.Scope is { } s && s.CheckpointXid == scope.CheckpointXid && s.StoreOffsetBytes == scope.StoreOffsetBytes && s.StoreSizeBytes == scope.StoreSizeBytes,
                "Physical sibling window changed.");
            return new VolumeTopologyWal(oid!, uuid!, NativeRecoveryStorage.CanonicalWal(spool, identity!));
        }).ToArray();
        NativeApfsVolumeManagement.ValidateCensus(volumes);
        Need(rows.Length == volumes.Length && rows.Length is >= 1 and <= 100, "Incomplete physical sibling census.");
        return new(scope.ImagePath, scope.StoreOffsetBytes, scope.StoreSizeBytes, binding.SourceIdentity, Text("containerUuid"),
            scope.CheckpointXid, "4096", Text("nextOid"), spool, volumes, Text("bindingHex"));
    }
}
