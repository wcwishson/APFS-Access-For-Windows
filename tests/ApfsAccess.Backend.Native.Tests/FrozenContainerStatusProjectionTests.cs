using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class FrozenContainerStatusProjectionTests
{
    [FrozenStatusFact]
    public void ActualSavedNativeChildrenCarryIndependentWatermarksCanonicalLabelsAndCapabilities()
    {
        var text = File.ReadAllText(Environment.GetEnvironmentVariable("APFSACCESS_FROZEN_CONTAINER_STATUS")!);
        var status = ContainerStatusReader.Parse(text);
        using var source = JsonDocument.Parse(text);
        Assert.Equal(source.RootElement.GetProperty("checkpointXid").GetUInt64(), status.CheckpointXid);
        var displays = status.Volumes.Select(child =>
        {
            var native = source.RootElement.GetProperty("volumes").EnumerateArray().Single(v => v.GetProperty("objectId").GetUInt64() == child.ObjectId);
            var diagnostic = ContainerRuntimeDiagnostics.Project(true, status.IsKnown, status.LeaseHeld,
                child.Ready, child.Writable, child.RecoveryActive, child.WriteDegraded, status.CheckpointXid);
            var projected = ContainerRuntimeDiagnostics.ApplyWatermarks(new(child.CanonicalId, child.ObjectId == 101 ? "E:\\" : "F:\\",
                MountAccessMode.ReadWrite, CommitModel: diagnostic.CommitModel, NativeWriteReadiness: diagnostic.Readiness,
                NativeWriteEngineState: diagnostic.EngineState, NativeWriteValidationState: diagnostic.ValidationState,
                LastCommitXid: status.CheckpointXid, MountReady: child.Ready, HostProcessId: status.OwnerPid,
                SnapshotInventorySupported: child.SnapshotInventorySupported, SnapshotMutationSupported: child.SnapshotMutationSupported,
                VolumeVerificationSupported: child.VolumeVerificationSupported, VolumeVerificationScope: child.VolumeVerificationScope), status.IsKnown, child);
            var display = Assert.Single(MountedStatusProjection.FromMounts([projected]));
            Assert.Equal(native.GetProperty("walAcceptedSequence").GetUInt64(), display.WalAcceptedSequence);
            Assert.Equal(native.GetProperty("walApfsDurableSequence").GetUInt64(), display.WalApfsDurableSequence);
            Assert.Equal(native.GetProperty("walCleanupSequence").GetUInt64(), display.WalCleanupSequence);
            Assert.True(display.HasRuntimeStatus); Assert.False(display.PendingDurability);
            Assert.Equal(NativeWriteCommitModel.CanonicalApfsCheckpoint, display.CommitModel);
            Assert.Equal(NativeWriteReadiness.CommitReady, display.NativeWriteReadiness);
            Assert.Equal(NativeWriteEngineState.Transactional, display.NativeWriteEngineState);
            Assert.Equal(NativeWriteValidationState.CanonicalImageValidated, display.NativeWriteValidationState);
            Assert.Equal(native.GetProperty("snapshotInventorySupported").GetBoolean(), display.SnapshotInventorySupported);
            Assert.Equal(native.GetProperty("snapshotMutationSupported").GetBoolean(), display.SnapshotMutationSupported);
            Assert.Equal(native.GetProperty("volumeVerificationSupported").GetBoolean(), display.VolumeVerificationSupported);
            return display;
        }).ToArray();
        Assert.NotEqual(0UL, displays[0].WalAcceptedSequence); Assert.NotEqual(0UL, displays[1].WalAcceptedSequence);
        Assert.NotEqual(displays[0].WalAcceptedSequence, displays[1].WalAcceptedSequence);
        File.WriteAllText(Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!, "frozen-container-projection.json"), JsonSerializer.Serialize(displays));
    }
    [FrozenStatusFact]
    public void SavedChildPartialOrImpossibleWatermarksRefuseAndPendingCleanupIsCarried()
    {
        var text = File.ReadAllText(Environment.GetEnvironmentVariable("APFSACCESS_FROZEN_CONTAINER_STATUS")!);
        var partial = JsonNode.Parse(text)!; partial["volumes"]![0]!.AsObject().Remove("walCleanupSequence");
        Assert.Throws<ContainerManifestException>(() => ContainerStatusReader.Parse(partial.ToJsonString()));
        var accepted = JsonNode.Parse(text)!["volumes"]![0]!["walAcceptedSequence"]!.GetValue<ulong>();
        var impossible = JsonNode.Parse(text)!; impossible["volumes"]![0]!["walApfsDurableSequence"] = accepted + 1;
        Assert.Throws<ContainerManifestException>(() => ContainerStatusReader.Parse(impossible.ToJsonString()));
        var pending = JsonNode.Parse(text)!; pending["volumes"]![0]!["walCleanupSequence"] = accepted - 1;
        var status = ContainerStatusReader.Parse(pending.ToJsonString());
        var projected = ContainerRuntimeDiagnostics.ApplyWatermarks(new("v", "E:\\", MountAccessMode.ReadWrite), true, status.Volumes[0]);
        Assert.True(Assert.Single(MountedStatusProjection.FromMounts([projected])).PendingDurability);
        var absent = ContainerRuntimeDiagnostics.ApplyWatermarks(projected, false, status.Volumes[0]);
        var unknown = Assert.Single(MountedStatusProjection.FromMounts([absent])); Assert.False(unknown.HasRuntimeStatus); Assert.True(unknown.PendingDurability);
    }
}
public sealed class FrozenStatusFactAttribute : FactAttribute
{
    public FrozenStatusFactAttribute() { if (Environment.GetEnvironmentVariable("APFSACCESS_FROZEN_CONTAINER_STATUS") is null) Skip = "A saved native container status document is required."; }
}
