using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed class RuntimeStatusPublisherTests
{
    [Fact]
    public void Publish_SkipsStatusChangedEvent_WhenOnlyTimestampChanges()
    {
        var publisher = new RuntimeStatusPublisher();
        var delivered = new List<StatusChangedPayload>();
        publisher.StatusChanged += delivered.Add;
        var payload = NewPayload();

        publisher.Publish(payload);
        publisher.Publish(payload with { TimestampUtc = payload.TimestampUtc.AddSeconds(1) });

        Assert.Single(delivered);
        Assert.Equal(payload.TimestampUtc.AddSeconds(1), publisher.Latest.TimestampUtc);
    }

    [Fact]
    public void Publish_RaisesStatusChangedEvent_WhenSemanticStateChanges()
    {
        var publisher = new RuntimeStatusPublisher();
        var delivered = new List<StatusChangedPayload>();
        publisher.StatusChanged += delivered.Add;
        var payload = NewPayload();

        publisher.Publish(payload);
        publisher.Publish(payload with
        {
            TimestampUtc = payload.TimestampUtc.AddSeconds(1),
            Warnings = ["Copy operation is still in progress."],
        });

        Assert.Equal(2, delivered.Count);
    }

    private static StatusChangedPayload NewPayload()
        => new(
            RuntimeState.MountedRw,
            ["E:\\"],
            LastError: null,
            TimestampUtc: new DateTime(2026, 5, 25, 12, 0, 0, DateTimeKind.Utc),
            Warnings: Array.Empty<string>(),
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "E:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS USB",
                    AccessMode: MountAccessMode.ReadWrite),
            ],
            WriteBackend: "Native",
            CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            NativeWriteReadiness: NativeWriteReadiness.CommitReady,
            NativeWriteEngineState: NativeWriteEngineState.HardwareValidated,
            NativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);
}
