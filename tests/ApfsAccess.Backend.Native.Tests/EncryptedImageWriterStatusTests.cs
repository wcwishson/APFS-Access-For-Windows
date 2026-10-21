using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class EncryptedImageWriterStatusTests
{
    private static readonly EncryptedImageProfile Profile = new(@"D:\private.apfs", "image-writer-v1:1:2:8192:0:8192", 0, 8192,
        "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 1026, 7, 0, 2, 0, 2,
        "33333333-3333-3333-3333-333333333333", "includes-header") { Writable = true };

    private static Dictionary<string, object?> Status(bool terminal = false) => new()
    {
        ["hostPid"] = 1234, ["mountReady"] = !terminal, ["explicitReadOnly"] = false,
        ["immutableEncryptedImage"] = false, ["encryptedSourceId"] = Profile.SourceId,
        ["encryptedContainerUuid"] = Guid.Parse(Profile.ContainerUuid).ToString("N"),
        ["encryptedVolumeUuid"] = Guid.Parse(Profile.VolumeUuid).ToString("N"),
        ["encryptedVolumeOid"] = Profile.VolumeObjectId, ["encryptedSelectionCheckpointXid"] = Profile.CheckpointXid,
        ["encryptedCheckpointXid"] = 9ul, ["encryptedFailureReason"] = "None",
        ["encryptedFailureTickMs"] = 0ul,
        ["encryptedHealth"] = terminal ? "StoppingReadWrite" : "ReadWrite", ["walRecoveryStateValid"] = true,
        ["writeBackend"] = "Native", ["commitModel"] = "CanonicalApfsCheckpoint", ["nativeWriteReadiness"] = "CommitReady",
        ["walAcceptedSequence"] = 20ul, ["walApfsDurableSequence"] = 20ul, ["walCleanupSequence"] = 20ul,
        ["dirtyTransactionCount"] = 0, ["volumeLabel"] = "Private image"
    };
    private static bool Observe(Dictionary<string, object?> s, bool terminal, out NativeEncryptedImageServiceSession.Observation? observed)
        => NativeEncryptedImageServiceSession.TryObserve(Profile, JsonSerializer.SerializeToElement(s), 1234, terminal, out observed);

    [Fact] public void ExactOwnerStatusDistinguishesNormalPendingWorkFromFailedOrUncleanStop()
    {
        Assert.True(Observe(Status(), false, out var ready));
        Assert.Equal(9ul, ready!.Checkpoint);
        var pending = Status(); pending["walApfsDurableSequence"] = 19ul; pending["walCleanupSequence"] = 18ul;
        Assert.True(Observe(pending, false, out var active));
        Assert.True(active!.Accepted > active.Cleaned);
        var pendingDelete = Status(); pendingDelete["dirtyTransactionCount"] = 2;
        Assert.True(Observe(pendingDelete, false, out var deleteState)); Assert.Equal(2, deleteState!.DirtyTransactions);
        Assert.True(Observe(Status(true), true, out var stopped));
        Assert.Equal(20ul, stopped!.Cleaned);
        pending["mountReady"] = false; pending["encryptedHealth"] = "StoppingReadWrite";
        Assert.False(Observe(pending, true, out var refused)); Assert.Null(refused);
        var delete = Status(true); delete["dirtyTransactionCount"] = 1;
        Assert.False(Observe(delete, true, out refused)); Assert.Null(refused);
    }

    [Fact] public void EveryIdentitySelectorAndDurabilityGuardRefusesWithEmptyOutput()
    {
        var controls = new Dictionary<string, object?> {
            ["hostPid"] = 1235, ["mountReady"] = false, ["explicitReadOnly"] = true,
            ["immutableEncryptedImage"] = true, ["encryptedSourceId"] = "image-writer-v1:1:3:8192:0:8192",
            ["encryptedContainerUuid"] = new string('4', 32), ["encryptedVolumeUuid"] = new string('5', 32),
            ["encryptedVolumeOid"] = 1027ul, ["encryptedSelectionCheckpointXid"] = 8ul,
            ["encryptedCheckpointXid"] = 6ul, ["encryptedFailureReason"] = "IoDeadlineExceeded",
            ["encryptedFailureTickMs"] = 123ul,
            ["walRecoveryStateValid"] = false, ["encryptedHealth"] = "FailedReadWrite", ["writeBackend"] = "Disabled",
            ["commitModel"] = "ScaffoldCheckpoint", ["nativeWriteReadiness"] = "RecoveryMode",
            ["walApfsDurableSequence"] = 21ul, ["walCleanupSequence"] = 21ul
        };
        foreach (var (key, value) in controls)
        {
            var changed = Status(); changed[key] = value;
            Assert.False(Observe(changed, false, out var refused), key); Assert.Null(refused);
            var missing = Status(); missing.Remove(key);
            Assert.False(Observe(missing, false, out refused), key); Assert.Null(refused);
        }
        var ro = Profile with { Writable = false, SourceId = "windows-file:1:2:8192:3:scope:0:8192" };
        Assert.False(NativeEncryptedImageServiceSession.TryObserve(ro, JsonSerializer.SerializeToElement(Status()), 1234, false, out _));
    }

    [Fact] public void StaleReadyAndTerminalStatusCannotRollBackObservedPublication()
    {
        Assert.True(Observe(Status(), false, out var prior));
        foreach (var terminal in new[] { false, true })
        {
            Assert.True(NativeEncryptedImageServiceSession.TryObserve(Profile,
                JsonSerializer.SerializeToElement(Status(terminal)), 1234, terminal, out _, prior));
            foreach (var field in new[] { "encryptedCheckpointXid", "walAcceptedSequence", "walApfsDurableSequence", "walCleanupSequence" })
            {
                var stale = Status(terminal);
                if (field == "encryptedCheckpointXid") stale[field] = 8ul;
                else if (field == "walAcceptedSequence")
                {
                    stale[field] = 19ul; stale["walApfsDurableSequence"] = 19ul; stale["walCleanupSequence"] = 19ul;
                }
                else if (field == "walApfsDurableSequence")
                {
                    stale[field] = 19ul; stale["walCleanupSequence"] = 19ul;
                }
                else stale[field] = 19ul;
                // These are valid first observations for a live owner. The
                // previously observed boundary is what makes them stale.
                if (!terminal) Assert.True(Observe(stale, false, out _));
                Assert.False(NativeEncryptedImageServiceSession.TryObserve(Profile,
                    JsonSerializer.SerializeToElement(stale), 1234, terminal, out var refused, prior));
                Assert.Null(refused);
            }
        }
        var next = Status(); next["encryptedCheckpointXid"] = 10ul;
        next["walAcceptedSequence"] = 24ul; next["walApfsDurableSequence"] = 23ul;
        next["walCleanupSequence"] = 22ul; next["dirtyTransactionCount"] = 1;
        Assert.True(NativeEncryptedImageServiceSession.TryObserve(Profile,
            JsonSerializer.SerializeToElement(next), 1234, false, out var pending, prior));
        Assert.Equal(10ul, pending!.Checkpoint); Assert.Equal(22ul, pending.Cleaned);
        var stop = Status(true); stop["encryptedCheckpointXid"] = 10ul;
        stop["walAcceptedSequence"] = 24ul; stop["walApfsDurableSequence"] = 24ul; stop["walCleanupSequence"] = 24ul;
        Assert.True(NativeEncryptedImageServiceSession.TryObserve(Profile,
            JsonSerializer.SerializeToElement(stop), 1234, true, out var clean, pending));
        Assert.Equal(24ul, clean!.Cleaned);
    }

    [Fact] public async Task WritableRegistrationIsExplicitAndDoesNotTakeReadLeaseOrStartHost()
    {
        var directory = EncryptedImageWriteLaunchTests.DirectoryPath();
        var path = Path.Combine(directory, "image.apfs"); File.WriteAllBytes(path, new byte[8192]);
        var p = EncryptedImageWriteLaunchTests.Profile(path);
        using (var refused = new NativeApfsBackend(new ServiceHostOptions { ManagementJournalRoot = directory }))
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => refused.RegisterEncryptedImageAsync(p, default));
            Assert.Empty(await refused.GetMountStateAsync(default));
        }
        using var backend = new NativeApfsBackend(new ServiceHostOptions { EnableNativeWrite = true, ManagementJournalRoot = directory });
        await backend.RegisterEncryptedImageAsync(p, default);
        var volume = Assert.Single(await backend.ProbeVolumesAsync(path, default));
        Assert.True(volume.SupportsReadWrite); Assert.True(volume.SupportsNativeWrite);
        Assert.Equal(EncryptedVolumeState.Locked, volume.EncryptionState); Assert.Equal(p, volume.RegisteredImage);
        Assert.Empty(await backend.GetMountStateAsync(default));
        using var writer = File.OpenHandle(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.False(writer.IsInvalid);
    }
}
