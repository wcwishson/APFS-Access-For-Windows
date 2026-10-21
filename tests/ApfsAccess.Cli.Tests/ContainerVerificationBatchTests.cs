using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

internal static class CliContainerVerificationFixture
{
    public const string Hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    public const string Image = @"D:\SyntheticImage.apfs";

    public static StatusChangedPayload Status(int count = 2, bool live = true, bool raw = false)
    {
        var path = raw ? @"\\.\PhysicalDrive99" : Image;
        var cid = ApfsTopology.BuildContainerId(Hex);
        var volumes = Enumerable.Range(0, count).Select(i => new VolumeInfo($"{path}|Volume-{101 + i}", path, $"Member {i + 1}", true,
            SupportsNativeWrite: true, RecoveryIdentity: $"Recovery-{i + 1}",
            CatalogVolumeId: ApfsTopology.BuildVolumeId(Hex, (ulong)(101 + i)), CatalogContainerUuid: Hex,
            CatalogVolumeObjectId: (ulong)(101 + i), CatalogDecision: ApfsCapabilityDecision.Writable,
            CatalogReasons: [], CatalogAutoMountAllowed: true, CatalogVolumeUuid: new string((char)('b' + i), 32))).ToArray();
        var topology = new ApfsTopologySnapshot([new("apfs-disk:image", path, null, 2097152)], [],
            [new("apfs-store:raw", Hex, "", cid, 0, 2097152, DiskId: "apfs-disk:image")],
            [new(cid, Hex, 4096, ["apfs-store:raw"], volumes.Select(v => v.CatalogVolumeId!).ToArray(), false, "90", [], [], [])],
            volumes.Select(v => new ApfsVolumeRecord(v.CatalogVolumeId!, v.CatalogVolumeUuid!, v.CatalogVolumeObjectId!.Value.ToString(),
                cid, v.VolumeName, true, ["data"], 64, null, "sensitive", "none", false, [], [], [], "7", "90")).ToArray(), []);
        var device = new DeviceInventory(new(path, "Synthetic", true), volumes, new(1, path, ["apfs-disk:image"], topology));
        var mounts = live ? volumes.Select((v, i) => new MountedVolumeDisplay(v.VolumeId, $"{(char)('R' + i)}:\\", v.VolumeName,
            path, "Synthetic", MountAccessMode.ReadWrite, v.RecoveryIdentity, RuntimeState.MountedRw, WriteEnabled: true,
            WriteBackend: "Native", NativeWriteSafetyState: NativeWriteSafetyState.StableReadWrite, MountReady: true,
            HostProcessId: 200 + i, CatalogVolumeId: v.CatalogVolumeId, CatalogContainerUuid: v.CatalogContainerUuid,
            CatalogVolumeObjectId: v.CatalogVolumeObjectId, CatalogVolumeUuid: v.CatalogVolumeUuid, HasRuntimeStatus: true,
            VolumeVerificationSupported: true, VolumeVerificationScope: new("HeldSource", raw ? "retained-admitted-raw" : "retained-image",
                Hex, v.CatalogVolumeUuid!, v.CatalogVolumeObjectId!.Value.ToString(), "90", "0", "2097152"),
            HostProcessCreationTimeFileTimeUtc: 134048736000000000 + i)).ToArray() : [];
        return new(live ? RuntimeState.MountedRw : RuntimeState.Idle, mounts.Select(m => m.MountPoint).ToArray(), null,
            DateTime.UtcNow, [], live, [], MountedVolumes: mounts, ConnectedInventory: [device], InventoryGeneration: 1);
    }

    public static ContainerControlOptions Options(bool dryRun = false) => new("container-verify", Image, Hex, null,
        dryRun, "01234567-89ab-cdef-0123-456789abcdef");

    public static OperationResultPayload Result(ControlOperationRequestPayload request, bool success = true)
    {
        var now = DateTime.UtcNow;
        return new(request.OperationId, request.Command, request.Target, ApfsOperationFingerprint.Compute(request),
            success ? ApfsOperationStates.Succeeded : ApfsOperationStates.Failed,
            success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.OperationFailed, success,
            now, now, now, FinalStatus: success ? "verified-covered-scope" : "not-proven", MountProof: "absent",
            OwnershipProof: "proven", DurabilityProof: "not-applicable", ExpiresAtUtc: request.ExpiresAtUtc,
            Diagnostic: success ? "Current metadata verified." : "Metadata findings.");
    }

    public static StatusChangedPayload Change(StatusChangedPayload s, string kind, int index = 1)
    {
        var d = s.ConnectedInventory![0];
        if (kind == "added") return Status(3);
        if (kind == "removed") return Status(1);
        if (kind == "generation") return s with { InventoryGeneration = 2, TimestampUtc = s.TimestampUtc.AddSeconds(1) };
        if (kind == "duplicate-device") return s with { ConnectedInventory = [d, d] };
        if (kind == "duplicate-owner") return s with { MountedVolumes = [..s.MountedVolumes!, s.MountedVolumes![index]] };
        if (kind == "missing-owner") return s with { MountedVolumes = s.MountedVolumes!.Where((_, i) => i != index).ToArray() };
        if (kind == "no-generation") return s with { InventoryGeneration = null };
        if (kind == "no-inventory") return s with { ConnectedInventory = null };
        if (kind is "uuid" or "catalog" or "observation")
            return s with { ConnectedInventory = [d with { Volumes = d.Volumes.Select((v, i) => i != index ? v : kind switch
            {
                "uuid" => v with { CatalogVolumeUuid = new string('f', 32) },
                "catalog" => v with { CatalogVolumeId = "wrong" },
                _ => v with { SupportsNativeWrite = false }
            }).ToArray() }] };
        return s with { MountedVolumes = s.MountedVolumes!.Select((m, i) => i != index ? m : kind switch
        {
            "pid" => m with { HostProcessId = m.HostProcessId + 1 },
            "creation" => m with { HostProcessCreationTimeFileTimeUtc = m.HostProcessCreationTimeFileTimeUtc + 1 },
            "mount" => m with { MountPoint = "Z:\\" },
            "mode" => m with { AccessMode = MountAccessMode.ReadOnly },
            "recovery" => m with { RecoveryIdentity = m.RecoveryIdentity!.ToLowerInvariant() },
            "source" => m with { VolumeVerificationScope = m.VolumeVerificationScope! with { SourceIdentity = "Replacement" } },
            "kind" => m with { VolumeVerificationScope = m.VolumeVerificationScope! with { SourceKind = "retained-admitted-raw" } },
            "window" => m with { VolumeVerificationScope = m.VolumeVerificationScope! with { StoreSizeBytes = "1048576" } },
            "checkpoint" => m with { VolumeVerificationScope = m.VolumeVerificationScope! with { CheckpointXid = "91" } },
            "scope-target" => m with { VolumeVerificationScope = m.VolumeVerificationScope! with { VolumeUuid = new string('f', 32) } },
            "malformed" => m with { VolumeVerificationScope = m.VolumeVerificationScope! with { SourceIdentity = "bad\nsource" } },
            "scope" => m with { VolumeVerificationScope = null },
            _ => m with { VolumeVerificationSupported = false }
        }).ToArray() };
    }
}

internal sealed class FakeContainerVerificationClient(StatusChangedPayload status) : IContainerVerificationClient
{
    public StatusChangedPayload Status = status;
    public int StatusReads;
    public List<ControlOperationRequestPayload> Requests { get; } = [];
    public List<string> Cancellations { get; } = [];
    public Func<int, StatusChangedPayload>? ReadStatus;
    public Func<ControlOperationRequestPayload, CancellationToken, Task<OperationResultPayload>>? Send;
    public Task<StatusChangedPayload> ReadFreshStatusAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        StatusReads++;
        return Task.FromResult(ReadStatus?.Invoke(StatusReads) ?? Status);
    }
    public Task<OperationResultPayload> VerifyAsync(ControlOperationRequestPayload request, CancellationToken token)
    {
        Requests.Add(request);
        return Send?.Invoke(request, token) ?? Task.FromResult(CliContainerVerificationFixture.Result(request));
    }
    public Task CancelAsync(string operationId, CancellationToken token) { Cancellations.Add(operationId); return Task.CompletedTask; }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

public sealed class ContainerVerificationBatchTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task SequentialExactChildrenUseFreshStatusAndServiceNormalizedReplies(bool live, bool raw)
    {
        var status = CliContainerVerificationFixture.Status(live: live, raw: raw);
        var client = new FakeContainerVerificationClient(status);
        var options = CliContainerVerificationFixture.Options() with { DeviceId = status.ConnectedInventory![0].Device.DeviceId };
        var first = new TaskCompletionSource<OperationResultPayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.Send = (r, _) => client.Requests.Count == 1 ? first.Task : Task.FromResult(Normalized(r));
        var running = ContainerVerificationBatch.RunAsync(options, client);
        Assert.Single(client.Requests);
        Assert.False(running.IsCompleted);
        client.Status = status with { InventoryGeneration = 2, TimestampUtc = status.TimestampUtc.AddSeconds(1) };
        first.SetResult(Normalized(client.Requests[0]));
        var report = await running;
        Assert.True(report.Success);
        Assert.Equal(0, report.ExitCode);
        Assert.Equal(3, client.StatusReads);
        Assert.Equal(2, client.Requests.Select(r => r.OperationId).Distinct().Count());
        Assert.DoesNotContain(options.OperationId, client.Requests.Select(r => r.OperationId));
        Assert.All(client.Requests, r =>
        {
            Assert.Equal(ApfsControlCommands.VolumeVerify, r.Command);
            Assert.Null(r.RequestedMode);
            Assert.True(r.ExpiresAtUtc > DateTime.UtcNow && r.ExpiresAtUtc <= DateTime.UtcNow.AddSeconds(80));
            Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, r, r.OperationId, 2)).IsValid);
            Assert.True(SelectedControlTarget.Matches(status.ConnectedInventory!, r.Target!));
        });
        Assert.All(report.Volumes, v => Assert.Equal("Verified", v.State));
        Assert.Contains("current metadata only", report.Scope);
    }

    private static OperationResultPayload Normalized(ControlOperationRequestPayload r)
        => CliContainerVerificationFixture.Result(r) with { Target = r.Target! with {
            DeviceId = r.Target.DeviceId.ToLowerInvariant(), VolumeId = r.Target.VolumeId.ToLowerInvariant(),
            ContainerUuid = r.Target.ContainerUuid!.ToLowerInvariant() } };

    [Theory]
    [InlineData("pid", 0)]
    [InlineData("creation", 1)]
    [InlineData("mount", 1)]
    [InlineData("mode", 0)]
    [InlineData("recovery", 1)]
    [InlineData("source", 1)]
    [InlineData("kind", 1)]
    [InlineData("window", 0)]
    [InlineData("checkpoint", 0)]
    [InlineData("scope", 1)]
    [InlineData("capability", 1)]
    [InlineData("added", 1)]
    [InlineData("removed", 1)]
    [InlineData("uuid", 1)]
    [InlineData("catalog", 1)]
    [InlineData("observation", 1)]
    [InlineData("duplicate-device", 1)]
    [InlineData("duplicate-owner", 1)]
    [InlineData("missing-owner", 1)]
    public async Task EveryMemberIncludingCompletedMembersIsRevalidated(string kind, int index)
    {
        var client = new FakeContainerVerificationClient(CliContainerVerificationFixture.Status());
        client.Send = (r, _) =>
        {
            client.Status = CliContainerVerificationFixture.Change(client.Status, kind, index);
            return Task.FromResult(CliContainerVerificationFixture.Result(r));
        };
        var report = await ContainerVerificationBatch.RunAsync(CliContainerVerificationFixture.Options(), client);
        Assert.Single(client.Requests);
        Assert.Equal(new[] { "Verified", "NotAttempted" }, report.Volumes.Select(v => v.State));
        Assert.Null(report.Volumes[1].OperationId);
        Assert.False(report.Success);
        Assert.Equal(5, report.ExitCode);
    }

    [Theory]
    [InlineData("pid")]
    [InlineData("added")]
    [InlineData("recovery")]
    [InlineData("capability")]
    [InlineData("scope-target")]
    public async Task StaleBeforeFirstDispatchLeavesAllNotAttempted(string kind)
    {
        var status = CliContainerVerificationFixture.Status();
        var client = new FakeContainerVerificationClient(status) { ReadStatus = n => n == 1 ? status : CliContainerVerificationFixture.Change(status, kind) };
        var report = await ContainerVerificationBatch.RunAsync(CliContainerVerificationFixture.Options(), client);
        Assert.Empty(client.Requests);
        Assert.Equal(2, report.Volumes.Count);
        Assert.All(report.Volumes, v => Assert.Equal("NotAttempted", v.State));
        Assert.False(report.OperationIssued);
    }

    [Theory]
    [InlineData("duplicate-device")]
    [InlineData("duplicate-owner")]
    [InlineData("missing-owner")]
    [InlineData("recovery")]
    [InlineData("source")]
    [InlineData("kind")]
    [InlineData("window")]
    [InlineData("scope-target")]
    [InlineData("malformed")]
    [InlineData("capability")]
    [InlineData("no-generation")]
    [InlineData("no-inventory")]
    [InlineData("uuid")]
    [InlineData("catalog")]
    public async Task IncompleteOrConflictingEvidenceCannotAuthorizeBatch(string kind)
    {
        var client = new FakeContainerVerificationClient(CliContainerVerificationFixture.Change(CliContainerVerificationFixture.Status(), kind));
        var report = await ContainerVerificationBatch.RunAsync(CliContainerVerificationFixture.Options(), client);
        Assert.False(report.Success);
        Assert.False(report.OperationIssued);
        Assert.Empty(client.Requests);
        Assert.NotNull(report.Diagnostic);
    }

    [Fact]
    public void SharedProofRefusesSubsetsDuplicatesAndClonedContainerSources()
    {
        var status = CliContainerVerificationFixture.Status();
        var proof = ContainerVerificationProof.CaptureForContainer(status, CliContainerVerificationFixture.Image, CliContainerVerificationFixture.Hex);
        Assert.Throws<InvalidOperationException>(() => ContainerVerificationProof.Capture(status, [proof.Targets[0]]));
        Assert.Throws<InvalidOperationException>(() => ContainerVerificationProof.Capture(status, [proof.Targets[0], proof.Targets[0]]));
        var d = status.ConnectedInventory![0];
        const string path = @"D:\Clone.apfs";
        var clone = d with { Device = d.Device with { DeviceId = path }, Volumes = d.Volumes.Select(v => v with { DeviceId = path }).ToArray(),
            Topology = d.Topology! with { DeviceId = path, Snapshot = d.Topology.Snapshot with {
                Disks = d.Topology.Snapshot.Disks.Select(disk => disk with { DeviceIdentifier = path }).ToArray() } } };
        Assert.True(TopologyAdmission.Validate(clone));
        Assert.Throws<InvalidOperationException>(() => proof.Revalidate(status with { ConnectedInventory = [d, clone] }));
    }

    [Theory]
    [InlineData("failure")]
    [InlineData("disconnect")]
    [InlineData("accepted")]
    [InlineData("progress")]
    [InlineData("success-false")]
    [InlineData("operation-id")]
    [InlineData("command")]
    [InlineData("target")]
    [InlineData("recovery")]
    [InlineData("observation")]
    [InlineData("volume-uuid")]
    [InlineData("fingerprint")]
    public async Task LateFailureOrUnconfirmedReplyPreservesOnlyProvenEarlierResults(string kind)
    {
        var client = new FakeContainerVerificationClient(CliContainerVerificationFixture.Status(3));
        client.Send = (r, _) =>
        {
            var ok = CliContainerVerificationFixture.Result(r);
            if (client.Requests.Count == 1) return Task.FromResult(ok);
            if (kind == "disconnect") throw new IOException("Disconnected after dispatch.");
            return Task.FromResult(kind switch
            {
                "failure" => CliContainerVerificationFixture.Result(r, false),
                "accepted" => ok with { State = ApfsOperationStates.Accepted },
                "progress" => ok with { State = ApfsOperationStates.InProgress },
                "success-false" => ok with { Success = false },
                "operation-id" => ok with { OperationId = Guid.NewGuid().ToString("D") },
                "command" => ok with { Command = ApfsControlCommands.Fix },
                "target" => ok with { Target = r.Target! with { VolumeId = "wrong" } },
                "recovery" => ok with { Target = r.Target! with { RecoveryIdentity = r.Target.RecoveryIdentity!.ToLowerInvariant() } },
                "observation" => ok with { Target = r.Target! with { ObservationContract = r.Target.ObservationContract!.ToUpperInvariant() } },
                "volume-uuid" => ok with { Target = r.Target! with { VolumeUuid = new string('f', 32) } },
                _ => ok with { Fingerprint = "wrong" }
            });
        };
        var report = await ContainerVerificationBatch.RunAsync(CliContainerVerificationFixture.Options(), client);
        Assert.Equal(2, client.Requests.Count);
        Assert.Equal(new[] { "Verified", "Failed", "NotAttempted" }, report.Volumes.Select(v => v.State));
        Assert.Equal(client.Requests[1].OperationId, report.Volumes[1].OperationId);
        Assert.Null(report.Volumes[2].OperationId);
        Assert.False(report.Success);
        Assert.Equal(5, report.ExitCode);
    }

    [Fact]
    public async Task CancellationAfterDispatchCancelsOnlyChildAndRejectsLateSuccess()
    {
        using var cancel = new CancellationTokenSource();
        var client = new FakeContainerVerificationClient(CliContainerVerificationFixture.Status());
        client.Send = (r, _) => { cancel.Cancel(); return Task.FromResult(CliContainerVerificationFixture.Result(r)); };
        var report = await ContainerVerificationBatch.RunAsync(CliContainerVerificationFixture.Options(), client, cancel.Token);
        Assert.Equal(new[] { "Failed", "NotAttempted" }, report.Volumes.Select(v => v.State));
        Assert.Equal(client.Requests.Single().OperationId, client.Cancellations.Single());
        Assert.NotEqual(report.BatchId, client.Cancellations.Single());
        Assert.Equal(4, report.ExitCode);
    }

    [Fact]
    public async Task AbsoluteDeadlineBoundsUncooperativeTransportAndCancelDoesNotPromoteOutcome()
    {
        var client = new FakeContainerVerificationClient(CliContainerVerificationFixture.Status());
        var pending = new TaskCompletionSource<OperationResultPayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.Send = (_, _) => pending.Task;
        var report = await ContainerVerificationBatch.RunAsync(CliContainerVerificationFixture.Options(), client,
            operationDeadlineUtc: DateTimeOffset.UtcNow.AddMilliseconds(250));
        Assert.Equal(4, report.ExitCode);
        Assert.Single(client.Requests);
        Assert.Single(client.Cancellations);
        Assert.Equal(new[] { "Failed", "NotAttempted" }, report.Volumes.Select(v => v.State));
        pending.SetResult(CliContainerVerificationFixture.Result(client.Requests[0]));
        Assert.False(report.Success);
    }

    [Fact]
    public async Task ExpiredDeadlineBeforeCaptureDoesNotReadStatusOrIssueOperations()
    {
        var client = new FakeContainerVerificationClient(CliContainerVerificationFixture.Status());
        var report = await ContainerVerificationBatch.RunAsync(CliContainerVerificationFixture.Options(), client,
            operationDeadlineUtc: DateTimeOffset.UtcNow.AddSeconds(-1));
        Assert.Equal(4, report.ExitCode);
        Assert.Equal(0, client.StatusReads);
        Assert.Empty(client.Requests);
    }

    [Fact]
    public async Task DryRunListsEligibleTargetsWithoutChildOperations()
    {
        var client = new FakeContainerVerificationClient(CliContainerVerificationFixture.Status());
        var report = await ContainerVerificationBatch.RunAsync(CliContainerVerificationFixture.Options(true), client);
        Assert.True(report.Success);
        Assert.Equal(0, report.ExitCode);
        Assert.Equal(2, report.Volumes.Count);
        Assert.All(report.Volumes, v => { Assert.Equal("NotAttempted", v.State); Assert.Null(v.OperationId); });
        Assert.Empty(client.Requests);
        Assert.Empty(client.Cancellations);
        Assert.Equal(1, client.StatusReads);
        Assert.False(report.OperationIssued);
    }

    [Theory]
    [InlineData(ApfsOperationStates.Succeeded, true)]
    [InlineData(ApfsOperationStates.Failed, false)]
    [InlineData(ApfsOperationStates.Cancelled, false)]
    public async Task PipeRoutingWaitsThroughPendingAndUnrelatedRepliesForExactTerminal(string state, bool success)
    {
        var request = Request();
        var terminal = Normalized(request) with { State = state, Success = success,
            Code = state == ApfsOperationStates.Cancelled ? ApfsOperationCodes.OperationCancelled :
                success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.OperationFailed };
        var accepted = Pending(request, ApfsOperationStates.Accepted);
        var progress = Pending(request, ApfsOperationStates.InProgress);
        var other = terminal with { OperationId = Guid.NewGuid().ToString("D") };
        var responses = new[] { Envelope(other), Envelope(accepted), Envelope(progress), Envelope(terminal) };
        Assert.All(responses, r => Assert.True(PipeMessageCodec.Validate(r).IsValid, PipeMessageCodec.Validate(r).ToString()));
        var stream = new ScriptedVerificationStream(responses);
        await using var peer = new PipePeer(stream);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var actual = await PipeContainerVerificationClient.ReadTerminalAsync(peer, request, deadline.Token);
        Assert.Equal(state, actual.State);
        Assert.Equal(success, actual.Success);
        var queries = Encoding.UTF8.GetString(stream.Output.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, queries.Length);
        foreach (var query in queries)
        {
            Assert.True(PipeMessageCodec.TryDeserialize(query, out var envelope));
            Assert.Equal(ApfsMessageTypes.OperationResultQuery, envelope!.Type);
            Assert.Equal(request.OperationId, envelope.RequestId);
        }
    }

    [Fact]
    public async Task CancellationDrainsLargeServiceGreetingBeforeSendingRequest()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var pipeName = "ApfsAccess.CancelGreeting." + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096);
        var greeting = PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged,
            CliContainerVerificationFixture.Status() with
            { Warnings = Enumerable.Repeat(new string('w', 2048), 64).ToArray() });
        Assert.True(PipeMessageCodec.Validate(greeting).IsValid);
        Assert.True(Encoding.UTF8.GetByteCount(PipeMessageCodec.Serialize(greeting)) > 128 * 1024);
        var received = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync(deadline.Token);
            await using var peer = new PipePeer(server);
            await peer.SendAsync(greeting, deadline.Token);
            return await peer.ReadMessageAsync(deadline.Token);
        });
        await using var client = new PipeContainerVerificationClient(async token =>
        {
            var stream = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            try { await stream.ConnectAsync(token); return new PipePeer(stream); }
            catch { await stream.DisposeAsync(); throw; }
        });
        var id = Guid.NewGuid().ToString("D");
        await client.CancelAsync(id, deadline.Token);
        var request = await received.WaitAsync(deadline.Token);
        Assert.NotNull(request);
        Assert.Equal(ApfsMessageTypes.CancellationRequest, request.Type);
        Assert.Equal(id, request.RequestId);
        Assert.True(PipeMessageCodec.Validate(request).IsValid);
    }

    private static ControlOperationRequestPayload Request()
        => new(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeVerify,
            ContainerVerificationProof.CaptureForContainer(CliContainerVerificationFixture.Status(live: false),
                CliContainerVerificationFixture.Image, CliContainerVerificationFixture.Hex).Targets[0],
            ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80));

    private static PipeEnvelope Envelope(OperationResultPayload result)
        => PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, result.OperationId, 2);

    private static OperationResultPayload Pending(ControlOperationRequestPayload request, string state)
        => CliContainerVerificationFixture.Result(request) with { State = state, Success = false,
            Code = ApfsOperationCodes.OperationInProgress, StartedAtUtc = state == ApfsOperationStates.Accepted ? null : DateTime.UtcNow,
            CompletedAtUtc = null, FinalStatus = "not-proven", PendingDurability = true,
            MountProof = "not-proven", OwnershipProof = "not-proven", DurabilityProof = "not-proven" };

    [Theory]
    [InlineData("operation-id")]
    [InlineData("command")]
    [InlineData("fingerprint")]
    [InlineData("target")]
    [InlineData("recovery")]
    [InlineData("observation")]
    [InlineData("volume-uuid")]
    [InlineData("malformed")]
    public async Task PipeRoutingRejectsMismatchedOrMalformedCorrelatedResults(string kind)
    {
        var request = Request();
        var result = CliContainerVerificationFixture.Result(request);
        result = kind switch
        {
            "operation-id" => result with { OperationId = Guid.NewGuid().ToString("D") },
            "command" => result with { Command = ApfsControlCommands.SnapshotList },
            "fingerprint" => result with { Fingerprint = new string('0', 64) },
            "target" => result with { Target = request.Target! with { VolumeId = "wrong" } },
            "recovery" => result with { Target = request.Target! with { RecoveryIdentity = request.Target.RecoveryIdentity!.ToLowerInvariant() } },
            "observation" => result with { Target = request.Target! with { ObservationContract = request.Target.ObservationContract!.ToUpperInvariant() } },
            "volume-uuid" => result with { Target = request.Target! with { VolumeUuid = new string('f', 32) } },
            _ => result with { CompletedAtUtc = null }
        };
        var response = PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, request.OperationId, 2);
        await using var peer = new PipePeer(new ScriptedVerificationStream([response]));
        var ex = await Record.ExceptionAsync(() => PipeContainerVerificationClient.ReadTerminalAsync(peer, request, CancellationToken.None));
        Assert.True(ex is IOException or InvalidOperationException, ex?.ToString());
    }

    [Fact]
    public async Task PipeClientReadsFreshGreetingEachTimeAndDispatchesOnlyVolumeVerify()
    {
        var request = Request();
        var status = CliContainerVerificationFixture.Status(live: false);
        var initial = new ScriptedVerificationStream([PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status)]);
        var fresh = new ScriptedVerificationStream([PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status), Envelope(Normalized(request))]);
        var streams = new Queue<ScriptedVerificationStream>([initial, fresh]);
        await using var client = new PipeContainerVerificationClient(_ => Task.FromResult(new PipePeer(streams.Dequeue())));
        _ = await client.ReadFreshStatusAsync(CancellationToken.None);
        _ = await client.ReadFreshStatusAsync(CancellationToken.None);
        var result = await client.VerifyAsync(request, CancellationToken.None);
        ContainerVerificationProof.RequireVerifiedReply(request, result);
        Assert.Empty(streams);
        Assert.Empty(initial.Output.ToArray());
        var lines = Encoding.UTF8.GetString(fresh.Output.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Single(lines);
        Assert.True(PipeMessageCodec.TryDeserialize(lines[0], out var sent));
        Assert.Equal(ApfsMessageTypes.ControlOperationRequest, sent!.Type);
        Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(sent, out var child));
        Assert.Equal(ApfsControlCommands.VolumeVerify, child!.Command);
        Assert.Equal(request.OperationId, child.OperationId);
    }

    [Theory]
    [InlineData(ApfsOperationStates.Succeeded, 0)]
    [InlineData(ApfsOperationStates.Failed, 5)]
    [InlineData(ApfsOperationStates.Cancelled, 5)]
    public async Task AggregateUsesOnlyCorrelatedTerminalOutcomeAfterProgress(string state, int expectedExit)
    {
        var client = new FakeContainerVerificationClient(CliContainerVerificationFixture.Status(3));
        client.Send = async (request, token) =>
        {
            var success = client.Requests.Count != 2 || state == ApfsOperationStates.Succeeded;
            var result = Normalized(request) with { State = success ? ApfsOperationStates.Succeeded : state, Success = success,
                Code = success ? ApfsOperationCodes.OperationSucceeded : state == ApfsOperationStates.Cancelled ?
                    ApfsOperationCodes.OperationCancelled : ApfsOperationCodes.OperationFailed };
            await using var peer = new PipePeer(new ScriptedVerificationStream([
                Envelope(Pending(request, ApfsOperationStates.Accepted)),
                Envelope(Pending(request, ApfsOperationStates.InProgress)), Envelope(result)]));
            return await PipeContainerVerificationClient.ReadTerminalAsync(peer, request, token);
        };
        var report = await ContainerVerificationBatch.RunAsync(CliContainerVerificationFixture.Options(), client);
        Assert.Equal(expectedExit, report.ExitCode);
        Assert.Equal(expectedExit == 0, report.Success);
        Assert.Equal(expectedExit == 0 ? ["Verified", "Verified", "Verified"] :
            new[] { "Verified", "Failed", "NotAttempted" }, report.Volumes.Select(v => v.State));
        Assert.Equal(expectedExit == 0 ? 3 : 2, client.Requests.Count);
    }
}

internal sealed class ScriptedVerificationStream(IEnumerable<PipeEnvelope> input) : Stream
{
    private readonly MemoryStream _input = new(Encoding.UTF8.GetBytes(string.Join("\n", input.Select(PipeMessageCodec.Serialize)) + "\n"));
    public MemoryStream Output { get; } = new();
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => _input.Length;
    public override long Position { get => _input.Position; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) => _input.Read(buffer, offset, count);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => _input.ReadAsync(buffer, cancellationToken);
    public override void Write(byte[] buffer, int offset, int count) => Output.Write(buffer, offset, count);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => Output.WriteAsync(buffer, cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
