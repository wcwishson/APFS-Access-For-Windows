using System.Globalization;
using System.Text;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeBackupImageWriteLaunch
{
    private string heldVolumeName = "";
    internal static NativeBackupImageWriteLaunch PrepareHeld(VolumeInfo volume, string journalRoot,
        ObserverRunResult wire, RawSnapshotHardwareQualification qualification, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var c = volume.BackupImageWrite ?? throw new IOException("BackupHeldCandidateAbsent");
        journalRoot = NativeSnapshotBrowseLaunch.ValidateLocalPath(journalRoot);
        if (!Directory.Exists(journalRoot) || !BackupImageMountPolicy.HasCandidate(volume) || c.PartitionUuid is null ||
            Encoding.UTF8.GetByteCount(wire.StandardOutput) > 256 * 1024) throw new IOException("BackupHeldObservationInvalid");
        using var document = JsonDocument.Parse(wire.StandardOutput);
        var j = document.RootElement;
        static void Fields(JsonElement value, string expected)
        {
            var fields = expected.Split(' ').ToHashSet(StringComparer.Ordinal);
            if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("BackupHeldObservationShape");
            foreach (var property in value.EnumerateObject())
                if (!fields.Remove(property.Name)) throw new InvalidDataException("BackupHeldObservationField");
            if (fields.Count != 0) throw new InvalidDataException("BackupHeldObservationIncomplete");
        }
        Fields(j, "schemaVersion operation readOnly exclusiveLease targetWrites outcome error device image bindingHex offsetBytes storeSizeBytes sourceIdentity containerUuid checkpointXid blockBytes nextOid volumes");
        string Text(string key) => j.GetProperty(key).GetString() ?? throw new InvalidDataException("BackupHeldObservationNull");
        var binding = VolumePhysicalBinding.Parse(Text("bindingHex"));
        if (wire.ExitCode != 0 || j.GetProperty("schemaVersion").GetInt32() != 1 || Text("operation") != "volume-physical-observe" ||
            !j.GetProperty("readOnly").GetBoolean() || !j.GetProperty("exclusiveLease").GetBoolean() || Text("targetWrites") != "0" ||
            Text("outcome") != "complete" || Text("error") != "" || Text("device") != volume.DeviceId || Text("image") != binding.Instance ||
            qualification.Scheme != RawSnapshotHardwareQualificationScheme.QualifiedSerialTuple || qualification.BusType != 7 ||
            qualification.QualifiedVpdType is not null || qualification.Vendor != binding.Vendor || qualification.Product != binding.Product ||
            qualification.QualifiedSerial != binding.Serial || !TopologyAdmission.SameUuid(c.PartitionUuid, binding.PartitionGuid.ToString()) ||
            binding.BaseOffset != c.StoreOffsetBytes || binding.Limit != c.StoreSizeBytes ||
            Text("offsetBytes") != c.StoreOffsetBytes.ToString(CultureInfo.InvariantCulture) ||
            Text("storeSizeBytes") != c.StoreSizeBytes.ToString(CultureInfo.InvariantCulture) || Text("sourceIdentity") != binding.SourceIdentity ||
            Text("containerUuid") != Guid.Parse(c.ContainerUuid).ToString("N") ||
            Text("checkpointXid") != c.CheckpointXid.ToString(CultureInfo.InvariantCulture) || Text("blockBytes") != "4096" ||
            !VolumeTopologyProfile.Number(Text("nextOid"), false)) throw new IOException("BackupHeldObservedSourceChanged");
        var volumes = j.GetProperty("volumes");
        if (volumes.ValueKind != JsonValueKind.Array || volumes.GetArrayLength() != 1) throw new IOException("BackupHeldSiblingCensusChanged");
        Fields(volumes[0], "volumeUuid oid");
        if (!TopologyAdmission.SameUuid(volumes[0].GetProperty("volumeUuid").GetString(), c.VolumeUuid) ||
            volumes[0].GetProperty("oid").GetString() != c.VolumeObjectId.ToString(CultureInfo.InvariantCulture) ||
            NativeApfsBackend.BuildRecoveryIdentityFromComponents(binding.PartitionGuid, Guid.Parse(c.ContainerUuid).ToString("N"), c.VolumeObjectId, false) != volume.RecoveryIdentity)
            throw new IOException("BackupHeldOriginalIdentityChanged");
        var owner = new NativeBackupImageWriteLaunch();
        try
        {
            owner.heldVolumeName = volume.VolumeName;
            owner.pins.AddRange(NativeSnapshotBrowseLaunch.PinAncestors(Path.Combine(journalRoot, "journal")));
            owner.Selection = new(volume.DeviceId, checked((long)c.StoreSizeBytes), "", "", Guid.Parse(c.ContainerUuid).ToString("N"),
                Guid.Parse(c.VolumeUuid).ToString("N"), c.VolumeObjectId.ToString(CultureInfo.InvariantCulture),
                c.CheckpointXid.ToString(CultureInfo.InvariantCulture), 0, volume.RecoveryIdentity!, journalRoot,
                Text("bindingHex"), binding.SourceIdentity, c.StoreOffsetBytes);
            token.ThrowIfCancellationRequested(); return owner;
        }
        catch { owner.Dispose(); throw; }
    }

    private IReadOnlyList<string> BuildHeldHostArguments(string mount, string status, string lifetime, string gate, string token, int parentPid)
    {
        var s = Selection;
        return ["--enable-backup-held-writes", "--backup-held-binding", s.PhysicalBinding!, "--device", s.Image,
            "--volume", heldVolumeName,
            "--device-offset", s.StoreOffsetBytes.ToString(CultureInfo.InvariantCulture), "--allow-raw-physical-write",
            "--container-id", s.ContainerUuid, "--volume-oid", s.VolumeOid, "--backup-held-volume-uuid", s.VolumeUuid,
            "--backup-held-checkpoint-xid", s.CheckpointXid, "--management-journal-directory", s.JournalRoot,
            "--recovery-identity", s.RecoveryIdentity, "--readwrite", "--write-backend", "Native", "--write-safety-level", "Strict",
            "--write-max-dirty-transactions", "1", "--write-recovery-policy", "FailClosed", "--write-crash-replay-mode", "ReplayIfSafe",
            "--allow-legacy-scaffold-for-fixtures", "false", "--write-require-canonical-commit", "true", "--write-integrity-check-on-mount", "true",
            "--mount", mount, "--parent-pid", parentPid.ToString(CultureInfo.InvariantCulture), "--lifetime-file", lifetime,
            "--startup-gate-file", gate, "--startup-gate-token", token, "--status-file", status];
    }

    private bool MatchesHeldReadyStatus(JsonElement j, int hostPid)
    {
        var b = j.GetProperty("backupHeldWriter"); var s = Selection;
        if (b.ValueKind != JsonValueKind.Object || b.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != b.EnumerateObject().Count()) return false;
        var accepted = b.GetProperty("acceptedSequence").GetUInt64();
        return released && hostPid > 0 && j.GetProperty("hostPid").GetInt32() == hostPid && j.GetProperty("mountReady").GetBoolean() &&
            !j.GetProperty("recoveryActive").GetBoolean() && j.GetProperty("writeBackend").GetString() == "Native" &&
            b.GetProperty("profile").GetString() == "bounded-backup-held-v1" && b.GetProperty("roleRaw").GetInt32() == 384 &&
            b.GetProperty("startupAdmitted").GetBoolean() && b.GetProperty("sourceCurrent").GetBoolean() &&
            b.GetProperty("nativeWriteEnabled").GetBoolean() && !b.GetProperty("writeDegraded").GetBoolean() &&
            b.GetProperty("bindingHex").GetString() == s.PhysicalBinding && b.GetProperty("sourceIdentity").GetString() == s.PhysicalSourceIdentity &&
            b.GetProperty("volumeOid").GetUInt64().ToString(CultureInfo.InvariantCulture) == s.VolumeOid && b.GetProperty("volumeUuid").GetString() == s.VolumeUuid &&
            b.GetProperty("admittedCheckpointXid").GetUInt64().ToString(CultureInfo.InvariantCulture) == s.CheckpointXid &&
            b.GetProperty("apfsDurableSequence").GetUInt64() == accepted && b.GetProperty("cleanupSequence").GetUInt64() == accepted &&
            j.GetProperty("walAcceptedSequence").GetUInt64() == accepted && j.GetProperty("walApfsDurableSequence").GetUInt64() == accepted &&
            j.GetProperty("walCleanupSequence").GetUInt64() == accepted;
    }
}
