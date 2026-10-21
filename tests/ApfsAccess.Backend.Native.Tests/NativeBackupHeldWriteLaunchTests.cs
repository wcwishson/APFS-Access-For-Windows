using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeBackupHeldWriteLaunchTests : IDisposable
{
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Volume = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private readonly string root = Path.Combine(@"D:\ApfsAccessScratch\WindowsClosure\backup-image-writer-profile-20261017", "managed-held-" + Guid.NewGuid().ToString("N"));
    public NativeBackupHeldWriteLaunchTests() => Directory.CreateDirectory(root);
    private static string Binding()
    {
        using var bytes = new MemoryStream();
        void N(ulong value) { Span<byte> n = stackalloc byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(n, value); bytes.Write(n); }
        void T(string value) { N((ulong)value.Length); bytes.Write(Encoding.ASCII.GetBytes(value)); }
        N(0x3646495653465041); N(1); const string instance = @"USBSTOR\DISK&VEN_QUALIFIED&PROD_STORAGE\SERIAL42&0";
        N((ulong)instance.Length); foreach (var c in instance) N(c);
        N(1); N(7); T("Qualified"); T("Storage"); T("0001"); T("SERIAL42");
        bytes.Write(Guid.Parse("cccccccccccccccccccccccccccccccc").ToByteArray(true));
        bytes.Write(Guid.Parse("dddddddddddddddddddddddddddddddd").ToByteArray(true));
        N(1048576); N(1048576); N(1048576); N(1048576); N(4 * 1048576); N(4096); N(4096);
        return Convert.ToHexStringLower(bytes.ToArray());
    }
    private static RawSnapshotHardwareQualification Qualification => new() {
        Scheme = RawSnapshotHardwareQualificationScheme.QualifiedSerialTuple, BusType = 7,
        Vendor = "Qualified", Product = "Storage", QualifiedSerial = "SERIAL42" };
    private static VolumeInfo Row()
    {
        var recovery = NativeApfsBackend.BuildRecoveryIdentityFromComponents(Guid.Parse("dddddddddddddddddddddddddddddddd"), Container, 101, false);
        return new("apfs-vol:" + Container + ":101", @"\\.\PhysicalDrive42", "Backup", false,
            RecoveryIdentity: recovery, CatalogVolumeId: "apfs-vol:" + Container + ":101", CatalogContainerUuid: Container,
            CatalogVolumeObjectId: 101, CatalogDecision: ApfsCapabilityDecision.Readable, CatalogReasons: ["special-role:backup"],
            CatalogAutoMountAllowed: false, CatalogVolumeUuid: Volume,
            BackupImageWrite: new(Container, Volume, 101, 20, 1048576, 1048576, "dddddddddddddddddddddddddddddddd"));
    }
    private static JsonObject Observation()
    {
        var hex = Binding(); var b = VolumePhysicalBinding.Parse(hex);
        return JsonSerializer.SerializeToNode(new { schemaVersion = 1, operation = "volume-physical-observe", readOnly = true,
            exclusiveLease = true, targetWrites = "0", outcome = "complete", error = "", device = Row().DeviceId,
            image = b.Instance, bindingHex = hex, offsetBytes = "1048576", storeSizeBytes = "1048576", sourceIdentity = b.SourceIdentity,
            containerUuid = Container, checkpointXid = "20", blockBytes = "4096", nextOid = "1000",
            volumes = new[] { new { volumeUuid = Volume, oid = "101" } } })!.AsObject();
    }
    private NativeBackupImageWriteLaunch Prepare(JsonObject? value = null, VolumeInfo? row = null, CancellationToken token = default) =>
        NativeBackupImageWriteLaunch.PrepareHeld(row ?? Row(), root, new(0, (value ?? Observation()).ToJsonString(), ""), Qualification, token);

    [Fact]
    public void PhysicalObserverEnvelopeAndOriginalIdentityAreExactAndCancellable()
    {
        using var launch = Prepare();
        Assert.Equal(Row().RecoveryIdentity, launch.Selection.RecoveryIdentity);
        Assert.Equal(Binding(), launch.Selection.PhysicalBinding);
        foreach (var field in new[] { "device", "image", "sourceIdentity", "containerUuid", "checkpointXid", "offsetBytes", "storeSizeBytes" }) {
            var changed = Observation(); changed[field] = "foreign";
            Assert.Throws<IOException>(() => Prepare(changed));
        }
        var unknown = Observation(); unknown["unexpected"] = true;
        Assert.Throws<InvalidDataException>(() => Prepare(unknown));
        var sibling = Observation(); sibling["volumes"]!.AsArray().Add(JsonSerializer.SerializeToNode(new { volumeUuid = Volume, oid = "102" }));
        Assert.Throws<IOException>(() => Prepare(sibling));
        Assert.Throws<IOException>(() => Prepare(row: Row() with { RecoveryIdentity = "foreign" }));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => Prepare(token: cancelled.Token));
    }

    [Fact]
    public void HeldReadyRequiresNativeSourceCensusAndAllOriginalWatermarks()
    {
        using var launch = Prepare();
        var args = launch.BuildHostArguments(@"R:\", Path.Combine(root, "status"), Path.Combine(root, "lifetime"),
            Path.Combine(root, "gate"), new string('a', 64), 123);
        Assert.Contains("--enable-backup-held-writes", args); Assert.Contains("--allow-raw-physical-write", args);
        Assert.DoesNotContain("--enable-backup-image-writes", args);
        var j = JsonSerializer.SerializeToNode(new { hostPid = 123, mountReady = true, recoveryActive = false, writeBackend = "Native",
            walAcceptedSequence = 9UL, walApfsDurableSequence = 9UL, walCleanupSequence = 9UL,
            backupHeldWriter = new { profile = "bounded-backup-held-v1", roleRaw = 384, volumeOid = 101UL, volumeUuid = Volume,
                admittedCheckpointXid = 20UL, bindingHex = launch.Selection.PhysicalBinding,
                sourceIdentity = launch.Selection.PhysicalSourceIdentity, sourceCurrent = true, startupAdmitted = true,
                nativeWriteEnabled = true, writeDegraded = false, acceptedSequence = 9UL, apfsDurableSequence = 9UL, cleanupSequence = 9UL } })!.AsObject();
        Assert.False(launch.MatchesReadyStatus(JsonSerializer.SerializeToElement(j), 123));
        launch.ReleaseForExclusiveStart(); Assert.True(launch.MatchesReadyStatus(JsonSerializer.SerializeToElement(j), 123));
        foreach (var field in new[] { "sourceCurrent", "startupAdmitted", "nativeWriteEnabled" }) {
            var changed = j.DeepClone().AsObject(); changed["backupHeldWriter"]![field] = false;
            Assert.False(launch.MatchesReadyStatus(JsonSerializer.SerializeToElement(changed), 123));
        }
        var debt = j.DeepClone().AsObject(); debt["backupHeldWriter"]!["cleanupSequence"] = 8UL;
        Assert.False(launch.MatchesReadyStatus(JsonSerializer.SerializeToElement(debt), 123));
        Assert.Throws<InvalidOperationException>(launch.ReleaseForExclusiveStart);
    }
    public void Dispose() { }
}
