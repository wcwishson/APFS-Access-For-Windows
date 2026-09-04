using System.Diagnostics;

namespace ApfsAccess.Backend.Native.Tests;

// Frozen contract v1.3 section 7 (managed side): the FsHost-written
// container status file `{containerUuid, ownerPid, leaseHeld,
// checkpointXid, volumes:[{objectId, canonicalId, mounted, ready,
// writable, recoveryIdentity}]}`. Missing/stale files are Unknown and must
// never report healthy.
public sealed class ContainerStatusTests
{
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";

    [Fact]
    public void TryRead_ValidFile_IsKnownWithPerVolumeStates()
    {
        using var temp = DTempDirectory.Create("container-status-valid");
        var path = Path.Combine(temp.Path, "container.status.json");
        File.WriteAllText(path, ValidStatusJson(Environment.ProcessId));

        var status = ContainerStatusReader.TryRead(path, ContainerHex);

        Assert.True(status.IsKnown);
        Assert.Null(status.UnknownReason);
        Assert.Equal(ContainerHex, status.ContainerUuid);
        Assert.Equal(Environment.ProcessId, status.OwnerPid);
        Assert.Equal(
            CurrentProcessStartFileTimeUtc,
            status.OwnerStartFileTimeUtc);
        Assert.True(status.LeaseHeld);
        Assert.Equal(7UL, status.CheckpointXid);
        Assert.True(status.RecoveryRequired);
        Assert.Equal(102UL, status.RecoveryVolumeObjectId);
        Assert.Equal("SessionCommitRecoveryRequired", status.RecoveryReason);
        Assert.Equal(2, status.Volumes.Count);
        Assert.Equal(101UL, status.Volumes[0].ObjectId);
        Assert.Equal($"apfs-vol:{ContainerHex}:101", status.Volumes[0].CanonicalId);
        Assert.True(status.Volumes[0].Mounted);
        Assert.True(status.Volumes[0].Ready);
        Assert.False(status.Volumes[0].Writable);
        Assert.Equal("rec-101", status.Volumes[0].RecoveryIdentity);
        Assert.False(status.Volumes[0].RecoveryActive);
        Assert.False(status.Volumes[0].WriteDegraded);
        Assert.Equal(string.Empty, status.Volumes[0].RecoveryReason);
        Assert.False(status.Volumes[1].Ready);
        Assert.True(status.Volumes[1].RecoveryActive);
        Assert.True(status.Volumes[1].WriteDegraded);
        Assert.Equal("CommitPersistFailed", status.Volumes[1].RecoveryReason);
    }

    [Fact]
    public void TryRead_CheckpointXidAcceptsDecimalString()
    {
        using var temp = DTempDirectory.Create("container-status-xid");
        var path = Path.Combine(temp.Path, "container.status.json");
        File.WriteAllText(
            path,
            ValidStatusJson(Environment.ProcessId).Replace("\"checkpointXid\": 7", "\"checkpointXid\": \"9\""));

        var status = ContainerStatusReader.TryRead(path, ContainerHex);

        Assert.True(status.IsKnown);
        Assert.Equal(9UL, status.CheckpointXid);
    }

    [Fact]
    public void TryRead_MissingFile_IsUnknownNeverHealthy()
    {
        using var temp = DTempDirectory.Create("container-status-missing");
        var status = ContainerStatusReader.TryRead(
            Path.Combine(temp.Path, "absent.status.json"), ContainerHex);

        Assert.False(status.IsKnown);
        Assert.Equal(ContainerStatusUnknownReasons.Missing, status.UnknownReason);
        Assert.Empty(status.Volumes);
    }

    [Fact]
    public void TryRead_StaleFile_IsUnknownNeverHealthy()
    {
        using var temp = DTempDirectory.Create("container-status-stale");
        var path = Path.Combine(temp.Path, "container.status.json");
        File.WriteAllText(path, ValidStatusJson(Environment.ProcessId));

        var stale = ContainerStatusReader.TryRead(path, ContainerHex, maxAge: TimeSpan.Zero);
        Assert.False(stale.IsKnown);
        Assert.Equal(ContainerStatusUnknownReasons.Stale, stale.UnknownReason);

        File.SetLastWriteTimeUtc(path, DateTime.UtcNow - TimeSpan.FromHours(1));
        var old = ContainerStatusReader.TryRead(path, ContainerHex);
        Assert.False(old.IsKnown);
        Assert.Equal(ContainerStatusUnknownReasons.Stale, old.UnknownReason);
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("[]")]
    [InlineData("""{"containerUuid": "zzz", "ownerPid": 1, "leaseHeld": true, "checkpointXid": 1, "volumes": []}""")]
    [InlineData("""{"ownerPid": 1, "leaseHeld": true, "checkpointXid": 1, "volumes": []}""")]
    [InlineData("""{"containerUuid": "a9cb92d28b7c4b599eab633c7625f491", "leaseHeld": true, "checkpointXid": 1, "volumes": []}""")]
    [InlineData("""{"containerUuid": "a9cb92d28b7c4b599eab633c7625f491", "ownerPid": 1, "checkpointXid": 1, "volumes": []}""")]
    [InlineData("""{"containerUuid": "a9cb92d28b7c4b599eab633c7625f491", "ownerPid": 1, "leaseHeld": "yes", "checkpointXid": 1, "volumes": []}""")]
    [InlineData("""{"containerUuid": "a9cb92d28b7c4b599eab633c7625f491", "ownerPid": 1, "leaseHeld": true, "volumes": []}""")]
    [InlineData("""{"containerUuid": "a9cb92d28b7c4b599eab633c7625f491", "ownerPid": 1, "leaseHeld": true, "checkpointXid": 1}""")]
    [InlineData("""{"containerUuid": "a9cb92d28b7c4b599eab633c7625f491", "ownerPid": 1, "leaseHeld": true, "checkpointXid": 1, "volumes": [{}]}""")]
    [InlineData("""{"containerUuid": "a9cb92d28b7c4b599eab633c7625f491", "ownerPid": 1, "leaseHeld": true, "checkpointXid": 1, "volumes": [{"objectId": 101, "canonicalId": "x", "mounted": "yes", "ready": true, "writable": false}]}""")]
    public void TryRead_SchemaViolation_IsUnknownNeverHealthy(string body)
    {
        using var temp = DTempDirectory.Create("container-status-schema");
        var path = Path.Combine(temp.Path, "container.status.json");
        File.WriteAllText(path, body);

        var status = ContainerStatusReader.TryRead(path, ContainerHex);

        Assert.False(status.IsKnown);
        Assert.Equal(ContainerStatusUnknownReasons.SchemaViolation, status.UnknownReason);
    }

    [Fact]
    public void TryRead_ContainerMismatch_IsUnknown()
    {
        using var temp = DTempDirectory.Create("container-status-mismatch");
        var path = Path.Combine(temp.Path, "container.status.json");
        File.WriteAllText(path, ValidStatusJson(Environment.ProcessId));

        var status = ContainerStatusReader.TryRead(path, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        Assert.False(status.IsKnown);
        Assert.Equal(ContainerStatusUnknownReasons.ContainerMismatch, status.UnknownReason);
    }

    [Fact]
    public void TryRead_DeadOwnerPid_IsUnknown()
    {
        using var temp = DTempDirectory.Create("container-status-owner");
        using var exited = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            ArgumentList = { "/c", "exit 0" },
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        Assert.NotNull(exited);
        Assert.True(exited!.WaitForExit(10_000));
        var deadPid = exited.Id;
        exited.Dispose();

        var path = Path.Combine(temp.Path, "container.status.json");
        File.WriteAllText(path, ValidStatusJson(deadPid));

        var status = ContainerStatusReader.TryRead(path, ContainerHex);

        Assert.False(status.IsKnown);
        Assert.Equal(ContainerStatusUnknownReasons.OwnerNotAlive, status.UnknownReason);
    }

    [Fact]
    public void TryRead_ReusedOwnerPidWithWrongStartTime_IsUnknown()
    {
        using var temp = DTempDirectory.Create("container-status-owner-reused");
        var path = Path.Combine(temp.Path, "container.status.json");
        File.WriteAllText(
            path,
            ValidStatusJson(Environment.ProcessId).Replace(
                $"\"ownerStartFileTimeUtc\": {CurrentProcessStartFileTimeUtc}",
                $"\"ownerStartFileTimeUtc\": {CurrentProcessStartFileTimeUtc + 1}"));

        var status = ContainerStatusReader.TryRead(path, ContainerHex);

        Assert.False(status.IsKnown);
        Assert.Equal(
            ContainerStatusUnknownReasons.OwnerIdentityMismatch,
            status.UnknownReason);
    }

    [Fact]
    public void TryRead_DroppedLease_IsKnownButNotHeld()
    {
        using var temp = DTempDirectory.Create("container-status-lease");
        var path = Path.Combine(temp.Path, "container.status.json");
        File.WriteAllText(
            path,
            ValidStatusJson(Environment.ProcessId).Replace("\"leaseHeld\": true", "\"leaseHeld\": false"));

        var status = ContainerStatusReader.TryRead(path, ContainerHex);

        Assert.True(status.IsKnown);
        Assert.False(status.LeaseHeld);
    }

    private static string ValidStatusJson(int ownerPid)
        => $$"""
        {
          "containerUuid": "{{ContainerHex}}",
          "ownerPid": {{ownerPid}},
          "ownerStartFileTimeUtc": {{CurrentProcessStartFileTimeUtc}},
          "leaseHeld": true,
          "checkpointXid": 7,
          "recoveryRequired": true,
          "recoveryVolumeObjectId": 102,
          "recoveryReason": "SessionCommitRecoveryRequired",
          "volumes": [
            {"objectId": 101, "canonicalId": "apfs-vol:{{ContainerHex}}:101", "mounted": true, "ready": true, "writable": false, "recoveryIdentity": "rec-101", "recoveryActive": false, "writeDegraded": false, "recoveryReason": ""},
            {"objectId": 102, "canonicalId": "apfs-vol:{{ContainerHex}}:102", "mounted": true, "ready": false, "writable": false, "recoveryActive": true, "writeDegraded": true, "recoveryReason": "CommitPersistFailed"}
          ]
        }
        """;

    private static long CurrentProcessStartFileTimeUtc
    {
        get
        {
            using var process = Process.GetCurrentProcess();
            return process.StartTime.ToUniversalTime().ToFileTimeUtc();
        }
    }
}
