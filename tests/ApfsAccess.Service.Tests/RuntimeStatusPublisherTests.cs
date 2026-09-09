using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed class RuntimeStatusPublisherTests
{
    [Fact]
    public async Task ConditionalPublicationNotifiesOnlyAfterCallerReleasesLocks()
    {
        var publisher = new RuntimeStatusPublisher();
        var expected = NewPayload();
        publisher.Publish(expected);
        var delivered = 0;
        publisher.StatusChanged += payload =>
        {
            // Another thread must be able to acquire the publisher lock during delivery.
            Assert.True(Task.Run(() => publisher.Latest).Wait(TimeSpan.FromSeconds(2)));
            Interlocked.Increment(ref delivered);
        };
        var projected = expected with { MountedVolumes = expected.MountedVolumes!.Select(m => m with
            { DriveLetterPreference = new(null, "T", "E", "next-mount", "Saved", "ET", true) }).ToArray() };
        Assert.True(publisher.TryPublish(expected, projected, out var notification));
        Assert.Equal(0, delivered);
        Assert.Same(projected, publisher.Latest);
        Assert.Equal(expected, projected with { MountedVolumes = expected.MountedVolumes });
        Assert.NotNull(notification);
        await Task.Run(notification);
        Assert.Equal(1, delivered);
        Assert.True(publisher.TryPublish(projected, projected with { TimestampUtc = projected.TimestampUtc.AddSeconds(1) }, out notification));
        Assert.Null(notification);
    }

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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InventoryRescansUpdateLatestWithoutRepeatedNotifications(bool conditional)
    {
        var publisher = new RuntimeStatusPublisher();
        publisher.Publish(NewPayload());
        var delivered = new List<StatusChangedPayload>();
        publisher.StatusChanged += payload =>
        {
            Assert.Same(payload, publisher.Latest);
            delivered.Add(payload);
        };

        var first = publisher.Latest with { ConnectedInventory = NewInventory() };
        PublishInventory(publisher, first, conditional);
        Assert.Same(first, Assert.Single(delivered));
        for (var scan = 1; scan <= 3; scan++)
        {
            // Fresh devices, volumes, nested records and lists; reverse scan order.
            var inventory = NewInventory().Reverse().Select(device => device with
            {
                Volumes = device.Volumes.Reverse().Select(volume => volume with
                {
                    CatalogReasons = volume.CatalogReasons!.Reverse().ToArray(),
                    WriteIncompatibilities = [],
                    WriteUnsupportedFeatures = [],
                }).ToArray(),
            }).ToArray();
            var rescan = first with { ConnectedInventory = inventory, TimestampUtc = first.TimestampUtc.AddSeconds(scan) };
            PublishInventory(publisher, rescan, conditional);
            Assert.Same(rescan, publisher.Latest);
            Assert.Single(delivered);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InventoryChangesAndRemovalNotifySubscribers(bool conditional)
    {
        var publisher = new RuntimeStatusPublisher();
        publisher.Publish(NewPayload() with { ConnectedInventory = NewInventory() });
        var delivered = new List<StatusChangedPayload>();
        publisher.StatusChanged += payload =>
        {
            Assert.Same(payload, publisher.Latest);
            delivered.Add(payload);
        };
        var changes = new Func<VolumeInfo, VolumeInfo>[]
        {
            v => v with { CatalogVolumeId = "replacement-volume" },
            v => v with { CatalogVolumeUuid = "replacement-uuid" },
            v => v with { CatalogReasons = ["special-role:recovery"] },
            v => v with { CatalogDecision = ApfsCapabilityDecision.Locked },
            v => v with { CatalogAutoMountAllowed = true },
            v => v with { SupportsExplorerMount = false },
            v => v with { SupportsNativeWrite = true },
            v => v with { WriteIncompatibilities = ["incompatible"] },
            v => v with { WriteUnsupportedFeatures = ["unsupported"] },
            v => v with { CatalogSpace = v.CatalogSpace! with { CheckpointXid = 43 } },
        };
        foreach (var change in changes)
        {
            var inventory = publisher.Latest.ConnectedInventory!.ToArray();
            inventory[0] = inventory[0] with { Volumes = [change(inventory[0].Volumes[0]), inventory[0].Volumes[1]] };
            ExpectNotification(publisher.Latest with { ConnectedInventory = inventory });
        }

        var disconnected = publisher.Latest.ConnectedInventory!.ToArray();
        disconnected[0] = disconnected[0] with { Device = disconnected[0].Device with { IsConnected = false } };
        ExpectNotification(publisher.Latest with { ConnectedInventory = disconnected });
        var removedVolume = disconnected.ToArray();
        removedVolume[0] = removedVolume[0] with { Volumes = [removedVolume[0].Volumes[0]] };
        ExpectNotification(publisher.Latest with { ConnectedInventory = removedVolume });
        ExpectNotification(publisher.Latest with { ConnectedInventory = [removedVolume[0]] });
        ExpectNotification(publisher.Latest with { ConnectedInventory = null });
        var empty = publisher.Latest with { ConnectedInventory = [] };
        var count = delivered.Count;
        PublishInventory(publisher, empty, conditional);
        Assert.Same(empty, publisher.Latest);
        Assert.Equal(count, delivered.Count);

        void ExpectNotification(StatusChangedPayload next)
        {
            var before = delivered.Count;
            PublishInventory(publisher, next, conditional);
            Assert.Equal(before + 1, delivered.Count);
            Assert.Same(next, delivered[^1]);
            Assert.Same(next, publisher.Latest);
        }
    }

    private static void PublishInventory(RuntimeStatusPublisher publisher, StatusChangedPayload payload, bool conditional)
    {
        if (!conditional) { publisher.Publish(payload); return; }
        Assert.True(publisher.TryPublish(publisher.Latest, payload, out var notification));
        Assert.Same(payload, publisher.Latest);
        notification?.Invoke();
    }

    private static DeviceInventory[] NewInventory()
        => Enumerable.Range(1, 2).Select(device => new DeviceInventory(
            new DeviceInfo($"device-{device}", "APFS USB", true),
            Enumerable.Range(1, 2).Select(volume => new VolumeInfo(
                $"device-{device}|volume-{volume}", $"device-{device}", $"Volume {volume}", false,
                CatalogVolumeId: $"catalog-{device}-{volume}", CatalogVolumeUuid: $"uuid-{device}-{volume}",
                CatalogDecision: ApfsCapabilityDecision.Readable,
                CatalogReasons: ["special-role:system", "special-role:preboot"], CatalogAutoMountAllowed: false,
                DriveLetterPreference: new(null, "T", null, "Saved", "Saved", "ET", true),
                CatalogSpace: new("container", 42, new(100, 409600), new(50, 204800),
                    new("volume", 1, new(10, 40960), null, null, new(0, 0), new(50, 204800), null, null))
            )).ToArray())).ToArray();

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
