using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

internal static class ContainerVerificationFixture
{
    public static StatusChangedPayload Status(int count = 2, bool live = true, bool raw = false)
    {
        var device = WindowsSurfaceFixture.Inventory(2097152);
        var path = raw ? @"\\.\PhysicalDrive99" : device.Device.DeviceId;
        var topology = device.Topology!.Snapshot;
        var volumes = Enumerable.Range(0, count).Select(i => device.Volumes[0] with
        {
            DeviceId = path, VolumeId = ApfsTopology.BuildVolumeId(WindowsSurfaceFixture.Hex, (ulong)(101 + i)),
            CatalogVolumeId = ApfsTopology.BuildVolumeId(WindowsSurfaceFixture.Hex, (ulong)(101 + i)),
            CatalogVolumeUuid = new string((char)('b' + i), 32), CatalogVolumeObjectId = (ulong)(101 + i),
            VolumeName = $"Member {i + 1}", RecoveryIdentity = $"recovery-{i + 1}"
        }).ToArray();
        topology = topology with
        {
            Disks = [topology.Disks[0] with { DeviceIdentifier = path }],
            Containers = [topology.Containers[0] with { VolumeIds = volumes.Select(v => v.CatalogVolumeId!).ToArray() }],
            Volumes = volumes.Select(v => topology.Volumes[0] with { Id = v.CatalogVolumeId!, Uuid = v.CatalogVolumeUuid!,
                ObjectId = v.CatalogVolumeObjectId!.Value.ToString(), Name = v.VolumeName }).ToArray()
        };
        device = device with { Device = device.Device with { DeviceId = path }, Volumes = volumes,
            Topology = device.Topology with { DeviceId = path, Snapshot = topology } };
        var owners = live ? volumes.Select((v, i) => new MountedVolumeDisplay(v.VolumeId, $"{(char)('R' + i)}:\\", v.VolumeName,
            path, "Synthetic", MountAccessMode.ReadWrite, v.RecoveryIdentity, RuntimeState.MountedRw, WriteEnabled: true,
            WriteBackend: "Native", NativeWriteSafetyState: NativeWriteSafetyState.StableReadWrite, MountReady: true,
            HostProcessId: 200 + i, CatalogVolumeId: v.CatalogVolumeId, CatalogContainerUuid: v.CatalogContainerUuid,
            CatalogVolumeObjectId: v.CatalogVolumeObjectId, CatalogVolumeUuid: v.CatalogVolumeUuid, HasRuntimeStatus: true,
            VolumeVerificationSupported: true, VolumeVerificationScope: new("held-source", raw ? "retained-admitted-raw" : "retained-image",
                WindowsSurfaceFixture.Hex, v.CatalogVolumeUuid!, v.CatalogVolumeObjectId!.Value.ToString(), "90", "0", "2097152"),
            HostProcessCreationTimeFileTimeUtc: 134048736000000000 + i)).ToArray() : [];
        return WindowsSurfaceFixture.Status() with { ConnectedInventory = [device], MountedVolumes = owners,
            State = live ? RuntimeState.MountedRw : RuntimeState.Idle, MountPoints = owners.Select(m => m.MountPoint).ToArray() };
    }

    public static DriveDashboardRow[] Rows(StatusChangedPayload status) => TopologyDashboard.Project(status)
        .Where(n => n.Row is not null).Select(n => n.Row!).ToArray();

    public static OperationResultPayload Result(ControlOperationRequestPayload request, bool success = true) => new(
        request.OperationId, request.Command, request.Target, ApfsOperationFingerprint.Compute(request),
        success ? ApfsOperationStates.Succeeded : ApfsOperationStates.Failed, success ? "ok" : "findings", success,
        DateTime.UtcNow, Diagnostic: success ? "Current metadata coverage complete." : "Child reported metadata findings.");

    public static StatusChangedPayload OwnerChange(StatusChangedPayload status, int index,
        Func<MountedVolumeDisplay, MountedVolumeDisplay> change)
        => status with { MountedVolumes = status.MountedVolumes!.Select((m, i) => i == index ? change(m) : m).ToArray() };
}

public sealed class ContainerVolumeVerificationTests
{
    [Fact]
    public void CaptureRejectsCaseChangedSelectedCatalogMemberId()
    {
        var status = ContainerVerificationFixture.Status();
        var rows = ContainerVerificationFixture.Rows(status);
        rows[1] = rows[1] with { CatalogVolumeId = rows[1].CatalogVolumeId!.ToUpperInvariant() };
        Assert.Throws<InvalidOperationException>(() => ContainerVolumeVerification.Capture(status, rows));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ExactMembersDelegateOnlyValidatedVolumeVerifyRequests(bool live, bool raw)
    {
        var status = ContainerVerificationFixture.Status(live: live, raw: raw);
        var rows = ContainerVerificationFixture.Rows(status);
        Assert.True(DriveDashboardPresenter.ContainerVerifyAvailable(rows));
        Assert.Equal(!live, DriveDashboardPresenter.ContainerManageAvailable(rows));
        var batch = ContainerVolumeVerification.Capture(status, rows.Reverse().ToArray());
        var requests = new List<ControlOperationRequestPayload>();
        var report = await batch.RunAsync(() => status, request =>
        {
            requests.Add(request);
            Assert.Equal(ApfsControlCommands.VolumeVerify, request.Command);
            Assert.Null(request.RequestedMode);
            Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,
                request, request.OperationId, PipeSchemaVersions.Schema2)).IsValid);
            Assert.True(SelectedControlTarget.Matches(status.ConnectedInventory!, request.Target!));
            return Task.FromResult(ContainerVerificationFixture.Result(request));
        });
        Assert.True(report.Success);
        Assert.Equal(batch.Rows.Select(r => r.VolumeId), requests.Select(r => r.Target!.VolumeId));
        Assert.Equal(2, requests.Select(r => r.OperationId).Distinct().Count());
        Assert.All(report.Volumes, r => Assert.Equal(ContainerVolumeVerificationState.Verified, r.State));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task SuccessfulServiceNormalizedRepliesCompleteAllMembers(bool live, bool raw)
    {
        var status = ContainerVerificationFixture.Status(live: live, raw: raw);
        var batch = ContainerVolumeVerification.Capture(status, ContainerVerificationFixture.Rows(status));
        var report = await batch.RunAsync(() => status, request => Task.FromResult(
            ContainerVerificationFixture.Result(request) with
            {
                Target = request.Target! with { DeviceId = request.Target.DeviceId.ToLowerInvariant(),
                    VolumeId = request.Target.VolumeId.ToLowerInvariant(),
                    ContainerUuid = request.Target.ContainerUuid?.ToLowerInvariant() }
            }));
        Assert.True(report.Success);
        Assert.Equal(2, report.Volumes.Count);
        Assert.All(report.Volumes, v => Assert.Equal(ContainerVolumeVerificationState.Verified, v.State));
    }

    [Fact]
    public void CaptureRejectsSubsetsDuplicatesMixedDevicesAndMixedContainers()
    {
        var status = ContainerVerificationFixture.Status();
        var rows = ContainerVerificationFixture.Rows(status);
        foreach (var bad in new[] { Array.Empty<DriveDashboardRow>(), new[] { rows[0] }, new[] { rows[0], rows[0] },
            new[] { rows[0], rows[1] with { DeviceId = @"D:\other.apfs" } },
            new[] { rows[0], rows[1] with { CatalogContainerUuid = new string('e', 32) } },
            new[] { rows[0], rows[1] with { RecoveryIdentity = "stale" } },
            new[] { rows[0], rows[1] with { CatalogVolumeUuid = new string('f', 32) } } })
            Assert.Throws<InvalidOperationException>(() => ContainerVolumeVerification.Capture(status, bad));
    }

    [Fact]
    public async Task OtherContainersOnTheSameSourceAreExcluded()
    {
        var status = ContainerVerificationFixture.Status();
        var d = status.ConnectedInventory![0];
        var topology = d.Topology!.Snapshot;
        var uuid = new string('e', 32);
        var cid = ApfsTopology.BuildContainerId(uuid);
        var vid = ApfsTopology.BuildVolumeId(uuid, 201);
        var other = d.Volumes[0] with { VolumeId = vid, CatalogVolumeId = vid, CatalogContainerUuid = uuid,
            CatalogVolumeObjectId = 201, CatalogVolumeUuid = new string('f', 32), RecoveryIdentity = "other-recovery" };
        topology = topology with
        {
            Stores = [..topology.Stores, topology.Stores[0] with { Id = "apfs-store:other", Uuid = uuid, ContainerId = cid }],
            Containers = [..topology.Containers, topology.Containers[0] with {
                Id = cid, Uuid = uuid, StoreIds = ["apfs-store:other"], VolumeIds = [vid] }],
            Volumes = [..topology.Volumes, topology.Volumes[0] with {
                Id = vid, Uuid = other.CatalogVolumeUuid!, ContainerId = cid, ObjectId = "201" }]
        };
        status = status with { ConnectedInventory = [d with { Volumes = [..d.Volumes, other],
            Topology = d.Topology with { Snapshot = topology } }] };
        Assert.True(TopologyAdmission.Validate(status.ConnectedInventory[0]));
        var selected = ContainerVerificationFixture.Rows(status)
            .Where(r => r.CatalogContainerUuid == WindowsSurfaceFixture.Hex).ToArray();
        var batch = ContainerVolumeVerification.Capture(status, selected);
        var targets = new List<string>();
        var report = await batch.RunAsync(() => status, request =>
        {
            targets.Add(request.Target!.VolumeId);
            return Task.FromResult(ContainerVerificationFixture.Result(request));
        });
        Assert.True(report.Success);
        Assert.Equal(selected.Select(r => r.VolumeId), targets);
        Assert.DoesNotContain(vid, targets);
    }

    [Fact]
    public void ValidClonedSourceWithSameContainerIdentityIsAmbiguous()
    {
        var status = ContainerVerificationFixture.Status();
        var rows = ContainerVerificationFixture.Rows(status);
        var d = status.ConnectedInventory![0];
        const string path = @"D:\clone.apfs";
        var clone = d with { Device = d.Device with { DeviceId = path },
            Volumes = d.Volumes.Select(v => v with { DeviceId = path }).ToArray(),
            Topology = d.Topology! with { DeviceId = path, Snapshot = d.Topology.Snapshot with {
                Disks = d.Topology.Snapshot.Disks.Select(disk => disk with { DeviceIdentifier = path }).ToArray() } } };
        Assert.True(TopologyAdmission.Validate(clone));
        Assert.Throws<InvalidOperationException>(() => ContainerVolumeVerification.Capture(
            status with { ConnectedInventory = [d, clone] }, rows));
    }

    [Theory]
    [InlineData("identity")]
    [InlineData("kind")]
    [InlineData("window")]
    [InlineData("malformed")]
    public void ConflictingRetainedSourceEvidenceCannotAuthorizeBatch(string change)
    {
        var status = ContainerVerificationFixture.Status();
        status = ContainerVerificationFixture.OwnerChange(status, 1, m => m with { VolumeVerificationScope = change switch
        {
            "identity" => m.VolumeVerificationScope! with { SourceIdentity = "another-held-object" },
            "kind" => m.VolumeVerificationScope! with { SourceKind = "retained-admitted-raw" },
            "window" => m.VolumeVerificationScope! with { StoreSizeBytes = "1048576" },
            _ => m.VolumeVerificationScope! with { SourceIdentity = "bad\nsource" }
        } });
        // Per-volume support alone cannot establish agreement across the batch.
        var rows = ContainerVerificationFixture.Rows(status);
        Assert.True(DriveDashboardPresenter.ContainerVerifyAvailable(rows));
        Assert.Throws<InvalidOperationException>(() => ContainerVolumeVerification.Capture(status, rows));
    }

    [Theory]
    [InlineData("source")]
    [InlineData("duplicate-device")]
    [InlineData("duplicate-routing")]
    [InlineData("duplicate-owner")]
    [InlineData("stale-owner")]
    [InlineData("capability")]
    [InlineData("missing-catalog-member")]
    [InlineData("missing-inventory-member")]
    public void CaptureRefusesAmbiguousOrIncompleteEvidence(string change)
    {
        var status = ContainerVerificationFixture.Status();
        var rows = ContainerVerificationFixture.Rows(status);
        var d = status.ConnectedInventory![0];
        status = change switch
        {
            "source" => status with { ConnectedInventory = [d, d with { Device = d.Device with { DeviceId = @"D:\clone.apfs" } }] },
            "duplicate-device" => status with { ConnectedInventory = [d, d] },
            "duplicate-routing" => status with { ConnectedInventory = [d with { Volumes = [..d.Volumes, d.Volumes[0]] }] },
            "duplicate-owner" => status with { MountedVolumes = [..status.MountedVolumes!, status.MountedVolumes![0]] },
            "stale-owner" => ContainerVerificationFixture.OwnerChange(status, 1, m => m with { RecoveryIdentity = "stale" }),
            "capability" => ContainerVerificationFixture.OwnerChange(status, 1, m => m with { VolumeVerificationSupported = false }),
            "missing-catalog-member" => status with { ConnectedInventory = [d with { Topology = d.Topology! with {
                Snapshot = d.Topology!.Snapshot with { Volumes = [d.Topology.Snapshot.Volumes[0]] } } }] },
            _ => status with { ConnectedInventory = [d with { Volumes = [d.Volumes[0]] }] }
        };
        Assert.False(ContainerVolumeVerification.TryCapture(status, rows, out var batch, out _));
        Assert.Null(batch);
    }

    [Theory]
    [InlineData("pid", 0)]
    [InlineData("creation", 1)]
    [InlineData("source", 1)]
    [InlineData("checkpoint", 0)]
    [InlineData("capability", 1)]
    [InlineData("recovery", 1)]
    [InlineData("scope", 1)]
    [InlineData("mount", 1)]
    [InlineData("added-member", 1)]
    [InlineData("removed-member", 1)]
    [InlineData("uuid", 1)]
    public async Task WholeMemberSetIsRevalidatedBetweenChildren(string change, int index)
    {
        var current = ContainerVerificationFixture.Status();
        var batch = ContainerVolumeVerification.Capture(current, ContainerVerificationFixture.Rows(current));
        var calls = 0;
        var report = await batch.RunAsync(() => current, request =>
        {
            calls++;
            current = Change(current, change, index);
            return Task.FromResult(ContainerVerificationFixture.Result(request));
        });
        Assert.Equal(1, calls);
        Assert.False(report.Success);
        Assert.Equal(ContainerVolumeVerificationState.Verified, report.Volumes[0].State);
        Assert.Equal(ContainerVolumeVerificationState.NotAttempted, report.Volumes[1].State);
    }

    [Theory]
    [InlineData("pid")]
    [InlineData("added-member")]
    [InlineData("capability")]
    [InlineData("recovery")]
    public async Task SelectionDriftBeforeFirstDispatchSendsNothing(string change)
    {
        var status = ContainerVerificationFixture.Status();
        var batch = ContainerVolumeVerification.Capture(status, ContainerVerificationFixture.Rows(status));
        var report = await batch.RunAsync(() => Change(status, change, 1), _ => throw new Xunit.Sdk.XunitException("Must not dispatch"));
        Assert.All(report.Volumes, r => Assert.Equal(ContainerVolumeVerificationState.NotAttempted, r.State));
        Assert.False(report.Success);
    }

    private static StatusChangedPayload Change(StatusChangedPayload status, string change, int index)
    {
        if (change is "added-member" or "removed-member") return ContainerVerificationFixture.Status(change == "added-member" ? 3 : 1);
        if (change == "uuid")
        {
            var d = status.ConnectedInventory![0];
            return status with { ConnectedInventory = [d with { Volumes = d.Volumes.Select((v, i) => i == index ? v with {
                CatalogVolumeUuid = new string('f', 32) } : v).ToArray() }] };
        }
        return ContainerVerificationFixture.OwnerChange(status, index, m => change switch
        {
            "pid" => m with { HostProcessId = m.HostProcessId + 99 },
            "creation" => m with { HostProcessCreationTimeFileTimeUtc = m.HostProcessCreationTimeFileTimeUtc + 1 },
            "source" => m with { VolumeVerificationScope = m.VolumeVerificationScope! with { SourceIdentity = "replacement" } },
            "checkpoint" => m with { VolumeVerificationScope = m.VolumeVerificationScope! with { CheckpointXid = "91" } },
            "scope" => m with { VolumeVerificationScope = null },
            "recovery" => m with { RecoveryIdentity = "new-recovery" },
            "mount" => m with { MountPoint = "Z:\\" },
            _ => m with { VolumeVerificationSupported = false }
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailureRetainsEarlierSuccessAndReportsRemainingMembersUnattempted(bool transportFailure)
    {
        var status = ContainerVerificationFixture.Status(3);
        var batch = ContainerVolumeVerification.Capture(status, ContainerVerificationFixture.Rows(status));
        var calls = 0;
        var report = await batch.RunAsync(() => status, request =>
        {
            if (++calls == 2 && transportFailure) throw new IOException("Result unknown after disconnect.");
            return Task.FromResult(ContainerVerificationFixture.Result(request, calls != 2));
        });
        Assert.Equal(2, calls);
        Assert.False(report.Success);
        Assert.Equal(new[] { ContainerVolumeVerificationState.Verified, ContainerVolumeVerificationState.Failed,
            ContainerVolumeVerificationState.NotAttempted }, report.Volumes.Select(v => v.State));
        Assert.Contains(transportFailure ? "Result unknown" : "metadata findings", report.Volumes[1].Diagnostic);
        Assert.All(report.Volumes, v => Assert.Contains(v.Volume.VolumeId, report.Details));
    }

    [Fact]
    public async Task SecondChildWaitsForFirstAndUnchangedRefreshIsAllowed()
    {
        var current = ContainerVerificationFixture.Status();
        var batch = ContainerVolumeVerification.Capture(current, ContainerVerificationFixture.Rows(current));
        var first = new TaskCompletionSource<OperationResultPayload>();
        var requests = new List<ControlOperationRequestPayload>();
        var running = batch.RunAsync(() => current, request =>
        {
            requests.Add(request);
            return requests.Count == 1 ? first.Task : Task.FromResult(ContainerVerificationFixture.Result(request));
        });
        Assert.Single(requests);
        Assert.False(running.IsCompleted);
        current = current with { InventoryGeneration = 2, TimestampUtc = current.TimestampUtc.AddSeconds(1) };
        first.SetResult(ContainerVerificationFixture.Result(requests[0]));
        Assert.True((await running).Success);
        Assert.Equal(2, requests.Count);
    }

    [Fact]
    public async Task InProgressOrMismatchedReplyCannotCountAsVerified()
    {
        var status = ContainerVerificationFixture.Status();
        var batch = ContainerVolumeVerification.Capture(status, ContainerVerificationFixture.Rows(status));
        foreach (var kind in new[] { "progress", "target", "recovery", "observation", "volume-uuid", "fingerprint" })
        {
            var report = await batch.RunAsync(() => status, request => Task.FromResult(kind switch
            {
                "progress" => ContainerVerificationFixture.Result(request) with { State = ApfsOperationStates.InProgress },
                "target" => ContainerVerificationFixture.Result(request) with { Target = request.Target! with { VolumeId = "wrong" } },
                "recovery" => ContainerVerificationFixture.Result(request) with { Target = request.Target! with { RecoveryIdentity = request.Target.RecoveryIdentity!.ToUpperInvariant() } },
                "observation" => ContainerVerificationFixture.Result(request) with { Target = request.Target! with { ObservationContract = request.Target.ObservationContract + "-changed" } },
                "volume-uuid" => ContainerVerificationFixture.Result(request) with { Target = request.Target! with { VolumeUuid = new string('f', 32) } },
                _ => ContainerVerificationFixture.Result(request) with { Fingerprint = "wrong" }
            }));
            Assert.Equal(ContainerVolumeVerificationState.Failed, report.Volumes[0].State);
            Assert.DoesNotContain(report.Volumes, v => v.State == ContainerVolumeVerificationState.Verified);
        }
    }
}
