using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray.Tests;

public sealed class EncryptedWriterDashboardTests
{
    private static EncryptedImageProfile Profile => new(@"D:\writer.apfs", "image-writer-v1:1:2:8192:0:8192", 0, 8192,
        "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 1026, 7, 0, 2, 0, 2,
        "33333333-3333-3333-3333-333333333333", "includes-header") { Writable = true };
    private static StatusChangedPayload Status()
    {
        var p = Profile;
        var volume = new VolumeInfo(p.VolumeId, p.ImagePath, "Encrypted image", true, IsEncrypted: true,
            RecoveryIdentity: p.Contract, CatalogVolumeId: p.VolumeId, CatalogContainerUuid: p.ContainerUuid,
            CatalogVolumeObjectId: p.VolumeObjectId, CatalogDecision: ApfsCapabilityDecision.Locked,
            CatalogVolumeUuid: p.VolumeUuid, RegisteredImage: p, EncryptionState: EncryptedVolumeState.Unlocked);
        var owner = new MountedVolumeDisplay(p.VolumeId, @"D:\private-mount", "Image", p.ImagePath, "Image", MountAccessMode.ReadWrite,
            RecoveryIdentity: p.Contract, State: RuntimeState.MountedRw, WriteEnabled: true, WriteBackend: "Native",
            CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint, NativeWriteReadiness: NativeWriteReadiness.CommitReady,
            NativeWriteEngineState: NativeWriteEngineState.Transactional, NativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite, LastCommitXid: 8, MountReady: true, HostProcessId: 1234,
            WalAcceptedSequence: 4, WalApfsDurableSequence: 4, WalCleanupSequence: 4,
            CatalogVolumeId: p.VolumeId, CatalogContainerUuid: p.ContainerUuid, CatalogVolumeObjectId: p.VolumeObjectId,
            HasRuntimeStatus: true, CatalogVolumeUuid: p.VolumeUuid, HostProcessCreationTimeFileTimeUtc: 123);
        return new(RuntimeState.MountedRw, [owner.MountPoint], null, DateTime.UtcNow, [], true, [], MountedVolumes: [owner],
            ConnectedInventory: [new(new(p.ImagePath, "Private image", true), [volume])]);
    }
    [Fact] public void ExactRuntimeOwnerShowsWritableAndPendingWorkKeepsItsOwnState()
    {
        var status = Status();
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.Equal(DriveDashboardState.HealthyReadWrite, row.State); Assert.Equal(DashboardPalette.Green, row.Palette);
        Assert.True(row.CanOpen); Assert.True(row.CanLock); Assert.False(row.CanUnlock);
        var pending = status.MountedVolumes![0] with { WalCleanupSequence = 3, PendingDurability = true, DirtyTransactionCount = 1 };
        row = Assert.Single(DriveDashboardPresenter.BuildRows(status with { MountedVolumes = [pending] }));
        Assert.Equal(DriveDashboardState.FinishingWrites, row.State); Assert.Equal(DashboardPalette.Blue, row.Palette);
        Assert.Equal("Finishing writes", row.StateText); Assert.DoesNotContain("Unlocked", row.StateText);
        Assert.True(row.CanLock); Assert.False(row.CanUnlock);
    }
    [Theory]
    [InlineData("runtime")] [InlineData("identity")] [InlineData("container")] [InlineData("volume")]
    [InlineData("oid")] [InlineData("pid")] [InlineData("creation")] [InlineData("ready")]
    [InlineData("mode")] [InlineData("backend")] [InlineData("engine")] [InlineData("xid")]
    [InlineData("watermarks")] [InlineData("recovery")]
    [InlineData("error-pending")] [InlineData("fallback-pending")] [InlineData("state-pending")]
    public void RegisteredWritableProfileDoesNotOverrideMissingOrContradictoryOwner(string fault)
    {
        var status = Status(); var owner = status.MountedVolumes![0];
        owner = fault switch {
            "runtime" => owner with { HasRuntimeStatus = false }, "identity" => owner with { RecoveryIdentity = "other" },
            "container" => owner with { CatalogContainerUuid = Guid.NewGuid().ToString("D") },
            "volume" => owner with { CatalogVolumeUuid = Guid.NewGuid().ToString("D") }, "oid" => owner with { CatalogVolumeObjectId = 1027 },
            "pid" => owner with { HostProcessId = 0 }, "creation" => owner with { HostProcessCreationTimeFileTimeUtc = 0 },
            "ready" => owner with { MountReady = false }, "mode" => owner with { AccessMode = MountAccessMode.ReadOnly },
            "backend" => owner with { WriteBackend = "Disabled" }, "engine" => owner with { NativeWriteEngineState = NativeWriteEngineState.Scaffold },
            "xid" => owner with { LastCommitXid = 6 }, "watermarks" => owner with { WalApfsDurableSequence = 5 },
            "error-pending" => owner with { State = RuntimeState.Error, PendingDurability = true },
            "fallback-pending" => owner with { NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback, PendingDurability = true },
            "state-pending" => owner with { State = RuntimeState.Idle, PendingDurability = true },
            _ => owner with { RecoveryActive = true, RecoveryReason = "AcceptedDebt" }
        };
        var rows = DriveDashboardPresenter.BuildRows(status with { MountedVolumes = [owner] });
        Assert.NotEmpty(rows);
        Assert.All(rows, row => {
            Assert.Equal(DriveDashboardState.Problem, row.State); Assert.Equal(DashboardPalette.Red, row.Palette);
            Assert.DoesNotContain("Unlocked", row.StateText); Assert.False(row.CanOpen); Assert.False(row.CanUnlock);
        });
    }
    [Fact] public void CleanLockedImageCanUnlockAgainWithoutMountedOwnershipClaim()
    {
        var status = Status(); var device = status.ConnectedInventory![0]; var volume = device.Volumes[0];
        var next = Profile with { CheckpointXid = 8 };
        volume = volume with { RegisteredImage = next, RecoveryIdentity = next.Contract, EncryptionState = EncryptedVolumeState.Locked };
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status with {
            State = RuntimeState.Idle, MountedVolumes = [], MountPoints = [], ConnectedInventory = [device with { Volumes = [volume] }] }));
        Assert.True(row.CanUnlock); Assert.False(row.CanLock); Assert.False(row.CanOpen); Assert.Equal("Locked", row.StateText);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public void LockObservationDisplaysLockedOnlyWhenServiceConfirmsIt(bool refused)
    {
        var status=Status(); var device=status.ConnectedInventory![0]; var volume=device.Volumes[0];
        volume=volume with { EncryptionState=refused?EncryptedVolumeState.Failed:EncryptedVolumeState.Locked };
        var snapshot=status with { State=RuntimeState.Idle,MountedVolumes=[],MountPoints=[],ConnectedInventory=[device with { Volumes=[volume] }] };
        foreach (var repeat in Enumerable.Range(0,3))
        {
            var row=Assert.Single(DriveDashboardPresenter.BuildRows(snapshot));
            Assert.False(row.CanOpen); Assert.False(row.CanLock); Assert.True(row.CanUnlock);
            Assert.Equal(refused?"Unlock or lock failed":"Locked",row.StateText);
            if (refused) Assert.Equal(DriveDashboardState.Problem,row.State);
        }
    }
}
