using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeBackupImageWriteLaunchTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "backup-writer-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "backup.apfs");
    private string Journal => Path.Combine(directory, "journal");
    private const string Container = "apfs-container:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    public NativeBackupImageWriteLaunchTests() { Directory.CreateDirectory(Journal); File.WriteAllBytes(Image, new byte[8192]); }
    public void Dispose() => Directory.Delete(directory, true);
    private NativeBackupImageWriteLaunch Prepare(JsonObject? inventory = null, CancellationToken token = default)
        => NativeBackupImageWriteLaunch.Prepare(Image, Container, "101", Journal,
            (_, _, _, _) => JsonSerializer.SerializeToElement(inventory ?? Inventory()), token);
    private JsonObject Inventory() => JsonSerializer.SerializeToNode(new {
        format = "apfs-access-snapshot-inventory", version = 1, readOnly = true,
        source = new { kind = "image", path = Image, sizeBytes = 8192, hashScope = "full", sha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Image))) },
        containerUuid = new string('a', 32), volumeUuid = new string('b', 32), volumeId = "apfs-vol:" + new string('a', 32) + ":101",
        volumeOid = "101", checkpointXid = "20", storeOffsetBytes = "0", storeSizeBytes = "8192",
        snapshots = new[] { new { xid = "10", name = "history", createTimeNs = "0", superblockPhysicalBlock = "1", omapPhysicalBlock = "2",
            omapTreePhysicalBlock = "3", rootOid = "4", rootPhysicalBlock = "5", extentrefPhysicalBlock = "6" } }
    })!.AsObject();
    private JsonObject Status(NativeBackupImageWriteLaunch launch) => JsonSerializer.SerializeToNode(new {
        hostPid = 123, mountReady = true, writeBackend = "Native", recoveryActive = false,
        walAcceptedSequence = 3UL, walApfsDurableSequence = 3UL, walCleanupSequence = 3UL,
        backupImageWriter = new { profile = "bounded-backup-image-v1", roleRaw = 384, volumeOid = 101UL,
            volumeUuid = launch.Selection.VolumeUuid, admittedCheckpointXid = 20UL, sourceSha256 = launch.Selection.SourceSha256,
            fileIdentity = launch.Selection.FileIdentity, nativeWriteEnabled = true, writeDegraded = false }
    })!.AsObject();

    [Fact]
    public void NormalAppDriveRootAndPrivateDirectoryUseSameBoundedHostSelection()
    {
        using var launch = Prepare();
        using var gate = HostStartupGate.Create(directory);
        foreach (var mount in new[] { @"R:\", Path.Combine(directory, "mount") })
        {
            var args = launch.BuildHostArguments(mount, Path.Combine(directory, "status"),
                Path.Combine(directory, "lifetime"), gate.FilePath, gate.AuthorizationToken, 123);
            Assert.Contains("--enable-backup-image-writes", args);
            Assert.Contains(mount, args);
            Assert.Contains(launch.Selection.FileIdentity, args);
            Assert.Contains(launch.Selection.RecoveryIdentity, args);
            Assert.Contains(gate.AuthorizationToken, args);
        }
        foreach (var token in new[] { new string('a', 31), new string('a', 63), new string('g', 32) })
            Assert.Throws<ArgumentException>(() => launch.BuildHostArguments(@"R:\", Path.Combine(directory, "status"),
                Path.Combine(directory, "lifetime"), gate.FilePath, token, 123));
        foreach (var mount in new[] { "R:", @"R:\alias\..\mount", @"\\.\PhysicalDrive3", @"\\server\share", @"R:\mount:stream" })
            Assert.Throws<ArgumentException>(() => launch.BuildHostArguments(mount, Path.Combine(directory, "status"),
                Path.Combine(directory, "lifetime"), Path.Combine(directory, "gate"), new string('a', 64), 123));
    }

    [Fact]
    public void ExclusiveHandoffIsOneShotAndRecoveryIdentitySurvivesOwnWrites()
    {
        using var first = Prepare(); var identity = first.Selection.RecoveryIdentity; var hash = first.Selection.SourceSha256;
        Assert.Equal(80, first.Selection.FileIdentity.Length);
        Assert.Throws<IOException>(() => { using var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); });
        Assert.False(first.MatchesReadyStatus(JsonSerializer.SerializeToElement(Status(first)), 123));
        first.ReleaseForExclusiveStart();
        Assert.Throws<InvalidOperationException>(() => first.ReleaseForExclusiveStart());
        using (var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.None)) writer.WriteByte(17);
        Assert.True(first.MatchesReadyStatus(JsonSerializer.SerializeToElement(Status(first)), 123));
        using var second = Prepare(); Assert.Equal(identity, second.Selection.RecoveryIdentity); Assert.NotEqual(hash, second.Selection.SourceSha256);
    }
    [Theory]
    [InlineData("volumeUuid", "cccccccccccccccccccccccccccccccc")]
    [InlineData("sourceSha256", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
    [InlineData("profile", "ordinary")]
    [InlineData("fileIdentity", "wrong")]
    public void SubstitutionCannotBecomeReady(string field, string replacement)
    {
        using var launch = Prepare(); launch.ReleaseForExclusiveStart(); var status = Status(launch);
        status["backupImageWriter"]![field] = replacement;
        Assert.False(launch.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), 123));
    }
    [Fact]
    public void ForeignPidUncleanDebtAndDuplicateAuthorityRefuse()
    {
        using var launch = Prepare(); launch.ReleaseForExclusiveStart(); var status = Status(launch);
        Assert.False(launch.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), 124));
        status["walCleanupSequence"] = 2; Assert.False(launch.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), 123));
        var text = Status(launch).ToJsonString(); using var duplicate = JsonDocument.Parse(text[..^1] + ",\"mountReady\":true}");
        Assert.False(launch.MatchesReadyStatus(duplicate.RootElement, 123));
    }
    [Fact]
    public void SliceInventoryExistingWriterAndCancellationReleaseAllLeases()
    {
        var inventory = Inventory(); inventory["storeOffsetBytes"] = "4096"; inventory["storeSizeBytes"] = "4096";
        Assert.Throws<ArgumentException>(() => Prepare(inventory));
        using (var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) Assert.Throws<IOException>(() => Prepare());
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); Assert.ThrowsAny<OperationCanceledException>(() => Prepare(token: cancelled.Token));
        using var released = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.None);
    }

    [Fact]
    public void AppHandoffRetainsOriginalDiscoveryNamespaceOnlyAfterFreshSelectionMatches()
    {
        using var launch = Prepare();
        var s = launch.Selection;
        var row = new ApfsAccess.Core.VolumeInfo("apfs-vol:" + s.ContainerUuid + ":101", Image, "Backup", true,
            SupportsNativeWrite: true, RecoveryIdentity: NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, s.ContainerUuid, 101, true),
            CatalogVolumeId: "apfs-vol:" + s.ContainerUuid + ":101", CatalogContainerUuid: s.ContainerUuid,
            CatalogVolumeObjectId: 101, CatalogDecision: ApfsAccess.Core.ApfsCapabilityDecision.Readable,
            CatalogReasons: ["special-role:backup"], CatalogAutoMountAllowed: false, CatalogVolumeUuid: s.VolumeUuid,
            BackupImageWrite: new(s.ContainerUuid, s.VolumeUuid, 101, 20, 8192));
        Assert.Throws<IOException>(() => launch.BindDiscoveredSelection(row with {
            BackupImageWrite = row.BackupImageWrite! with { CheckpointXid = 21 } }));
        Assert.Throws<IOException>(() => launch.BindDiscoveredSelection(row with {
            DeviceId = @"\\.\PhysicalDrive3" }));
        launch.BindDiscoveredSelection(row);
        Assert.Equal(row.RecoveryIdentity, launch.Selection.RecoveryIdentity);
        Assert.Equal(s.FileIdentity, launch.Selection.FileIdentity);
        Assert.Equal(s.SourceSha256, launch.Selection.SourceSha256);
        launch.ReleaseForExclusiveStart();
        Assert.Throws<IOException>(() => launch.BindDiscoveredSelection(row));
    }
}
