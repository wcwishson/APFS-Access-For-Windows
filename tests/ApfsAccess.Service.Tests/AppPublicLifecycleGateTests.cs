using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace ApfsAccess.Service.Tests;

// Private offline gate: synthetic inventory/status, real Service handlers and
// frozen Backend stop/proof methods, dedicated children, ordinary D: directories.
public sealed class AppPublicLifecycleGateTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(12);
    private const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static;

    [Fact]
    public async Task LegacyQuitGracefulOriginal()
    {
        await using var f = new Fixture();
        await using var route = await Route.Open(f);
        var id = Guid.NewGuid().ToString("D");
        await route.Send(PipeMessageCodec.Create(ApfsMessageTypes.QuitRequested,
            new QuitRequestedPayload("offline-gate", DateTime.UtcNow), id));
        var ack = await route.Read<AckPayload>();
        Assert.True(ack.Success, ack.Message);
        var stopping = await route.Read<ServiceStoppingPayload>();
        Assert.True(stopping.CleanupCompleted);
        Assert.True(stopping.HostOwnershipReleased && stopping.PendingDurabilityCleared);
        await f.Lifetime.Stopped.Task.WaitAsync(Bound);
        var result = f.Operations.Query(id)!;
        AssertReceipt(result);
        Assert.True(f.Lifetime.EvidenceExistedAtStop);
        f.Backend.Owner.AssertStop(clean: true, forced: false);
        Assert.False(File.Exists(f.Backend.Owner.StatusPath));
    }

    [Fact]
    public async Task Schema2QuitUnknownThenFreshRetry()
    {
        await using var f = new Fixture(unknown: true);
        var provenSibling = f.Backend.AddOwner("sibling", unknown: false);
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Backend.Hold = hold.Task;
        var first = Request(ApfsControlCommands.Quit);
        await using var route = await Route.Open(f);
        await route.Send(Envelope(first));
        await f.Backend.StopStarted.Task.WaitAsync(Bound);
        await using (var competing = await Route.Open(f))
        {
            var denied = await competing.Execute(Request(ApfsControlCommands.Quit));
            Assert.Equal(ApfsOperationCodes.ServiceUnavailable, denied.Code);
            var mutation = await competing.Execute(Request(ApfsControlCommands.Fix, f.Backend.Owner.Row));
            Assert.Equal(ApfsOperationCodes.ServiceUnavailable, mutation.Code);
        }
        var cancelledWait = f.Worker.PrepareForShutdownAsync(new CancellationToken(true));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelledWait);
        var sameAttempt = f.Worker.PrepareForShutdownAsync(CancellationToken.None);
        hold.SetResult();
        var failed = await route.Read<OperationResultPayload>();
        AssertReceipt(failed);
        Assert.False(failed.Success);
        Assert.False(f.Lifetime.Stopped.Task.IsCompleted);
        var originalPreparation = await sameAttempt.WaitAsync(Bound);
        Assert.False(originalPreparation.CleanupCompleted);
        Assert.True(originalPreparation.UnmountResultsOrEmpty[provenSibling.Row.VolumeId].HostOwnershipReleased);
        var immutable = File.ReadAllBytes(failed.EvidencePath!);
        var calls = f.Backend.Owner.Calls;
        Assert.Equal(failed, await route.Execute(first));
        Assert.Equal(calls, f.Backend.Owner.Calls);
        f.Backend.Owner.AssertRetained();

        // The row disappears while its original proof is still UNKNOWN.
        // A new operation must reconcile the retained cohort, never All(empty).
        f.Backend.HideRows = true;
        var unknownRetry = await route.Execute(Request(ApfsControlCommands.Quit));
        Assert.NotEqual(ApfsOperationCodes.ServiceUnavailable, unknownRetry.Code);
        Assert.False(unknownRetry.Success);
        Assert.Equal("not-proven", unknownRetry.OwnershipProof);
        Assert.Equal("not-proven", unknownRetry.DurabilityProof);
        Assert.Equal(calls, f.Backend.Owner.Calls);
        Assert.True(f.Backend.Owner.TerminalReads > 0);
        Assert.Equal(1, provenSibling.Calls);
        f.Backend.Owner.AssertRetained();

        // A different observed incarnation at the original point cannot be stopped.
        calls = f.Backend.Owner.Calls;
        f.Backend.Replacement = f.Backend.Owner.Row with { HostProcessCreationTimeFileTimeUtc = f.Backend.Owner.Start + 1 };
        var replaced = await route.Execute(Request(ApfsControlCommands.Quit));
        Assert.False(replaced.Success);
        Assert.Equal(calls, f.Backend.Owner.Calls);
        f.Backend.Replacement = null;
        f.Backend.Owner.Unknown = false;
        Assert.True(f.Backend.Owner.TryCleanup());
        Assert.False((await f.Backend.GetUnmountTerminalStateAsync(
            f.Backend.Owner.Row with { HostProcessId = f.Backend.Owner.Row.HostProcessId + 1 }, CancellationToken.None)).Success);
        Assert.False((await f.Backend.GetUnmountTerminalStateAsync(
            f.Backend.Owner.Row with { HostProcessCreationTimeFileTimeUtc = f.Backend.Owner.Start + 1 }, CancellationToken.None)).Success);
        Assert.False((await f.Backend.GetUnmountTerminalStateAsync(
            f.Backend.Owner.Row with { HostProcessCreationTimeFileTimeUtc = 0 }, CancellationToken.None)).Success);
        var completed = await route.Execute(Request(ApfsControlCommands.Quit));
        Assert.True(completed.Success, completed.Diagnostic);
        Assert.Equal(calls, f.Backend.Owner.Calls);
        AssertReceipt(completed);
        var stopping = await route.Read<ServiceStoppingPayload>();
        Assert.True(stopping.CleanupCompleted);
        await f.Lifetime.Stopped.Task.WaitAsync(Bound);
        Assert.Equal(1, provenSibling.Calls);
        Assert.Equal(immutable, File.ReadAllBytes(failed.EvidencePath!));
        Assert.Equal(failed, await f.Operations.ExecuteOrReplayAsync(first));
        await f.Operations.StopAsync(CancellationToken.None);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable,
            (await f.Operations.ExecuteOrReplayAsync(Request(ApfsControlCommands.Quit))).Code);
        await AdmittedQuitExpiryAndExplicitCancellationKeepSameAttempt();
    }

    private static async Task AdmittedQuitExpiryAndExplicitCancellationKeepSameAttempt()
    {
        await using var f = new Fixture(unknown: true);
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Backend.Hold = hold.Task;
        await using var route = await Route.Open(f);
        var request = Request(ApfsControlCommands.Quit) with { ExpiresAtUtc = DateTime.UtcNow.AddSeconds(3) };
        await route.Send(Envelope(request));
        try { await f.Backend.StopStarted.Task.WaitAsync(Bound); }
        catch (TimeoutException error)
        {
            throw new TimeoutException("Quit did not reach the dedicated owner: " +
                JsonSerializer.Serialize(f.Operations.Query(request.OperationId)), error);
        }
        var response = route.Read<OperationResultPayload>();
        await Task.Delay(TimeSpan.FromMilliseconds(3200));
        Assert.False(response.IsCompleted, "An admitted Quit must not expire while the original drain is retained.");
        Assert.Equal(ApfsOperationStates.InProgress, f.Operations.Query(request.OperationId)!.State);
        Assert.False(f.Lifetime.Stopped.Task.IsCompleted);
        await using (var competing = await Route.Open(f))
            Assert.Equal(ApfsOperationCodes.ServiceUnavailable,
                (await competing.Execute(Request(ApfsControlCommands.Quit))).Code);
        await using (var cancellation = await Route.Open(f))
        {
            await cancellation.Send(PipeMessageCodec.Create(ApfsMessageTypes.CancellationRequest,
                new OperationCancellationRequestPayload(request.OperationId), request.OperationId, PipeSchemaVersions.Schema2));
            var cancellationResponse = await cancellation.Read<OperationResultPayload>();
            Assert.Equal(ApfsOperationStates.InProgress, cancellationResponse.State);
            Assert.Contains("cannot be explicitly cancelled", cancellationResponse.Diagnostic);
        }
        Assert.False(response.IsCompleted);
        Assert.Equal(1, f.Backend.Owner.Calls);
        hold.SetResult();
        var failed = await response;
        Assert.Equal(ApfsOperationStates.Failed, failed.State);
        Assert.False(failed.Success);
        AssertReceipt(failed);
        await f.Worker.PrepareForShutdownAsync(CancellationToken.None).WaitAsync(Bound);
        f.Backend.Owner.Unknown = false;
        Assert.True(f.Backend.Owner.TryCleanup());
        var fresh = await route.Execute(Request(ApfsControlCommands.Quit));
        Assert.True(fresh.Success, fresh.Diagnostic);
        Assert.True((await route.Read<ServiceStoppingPayload>()).CleanupCompleted);
        await f.Lifetime.Stopped.Task.WaitAsync(Bound);
        Assert.Equal(failed, await f.Operations.ExecuteOrReplayAsync(request));
    }

    [Fact]
    public async Task LegacyQuitRetainsDelayedDescendantUntilCleanRetry()
    {
        await using var f = new Fixture(descendant: true);
        await using var route = await Route.Open(f);
        var id = Guid.NewGuid().ToString("D");
        var watch = Stopwatch.StartNew();
        await route.Send(PipeMessageCodec.Create(ApfsMessageTypes.QuitRequested,
            new QuitRequestedPayload("offline-gate", DateTime.UtcNow), id));
        await f.Backend.StopStarted.Task.WaitAsync(Bound);
        await Eventually(() => f.Backend.Owner.Process.HasExited);
        Assert.True(f.Backend.Owner.ActiveChildren() > 0, "The descendant must remain in the original guardian job after parent exit.");
        Assert.False(f.Backend.Owner.Released.IsCompleted);
        var ack = await route.Read<AckPayload>();
        Assert.False(ack.Success);
        Assert.True(watch.Elapsed >= TimeSpan.FromMilliseconds(800), $"The pending guardian was not observed through its stop window: {watch.Elapsed}.");
        var failed = f.Operations.Query(id)!;
        AssertReceipt(failed);
        Assert.Equal(ApfsOperationStates.Failed, failed.State);
        Assert.Equal(ApfsOperationCodes.UnsafeOwnership, failed.Code);
        Assert.Equal("not-proven", failed.OwnershipProof);
        Assert.Equal("not-proven", failed.DurabilityProof);
        Assert.Equal("shutdown-incomplete", failed.FinalStatus);
        await Task.Delay(100);
        Assert.False(f.Lifetime.Stopped.Task.IsCompleted);
        f.Backend.Owner.AssertDescendantRetainedWithoutForce();
        var original = File.ReadAllBytes(failed.EvidencePath!);
        f.Backend.Owner.ReleaseDescendant();
        await Eventually(() => f.Backend.Owner.ActiveChildren() == 0);
        Assert.True(f.Backend.Owner.TryCleanup(), "Cleanup must succeed after the original descendant drains.");
        f.Backend.Owner.AssertStop(clean: true, forced: false);
        await route.Send(PipeMessageCodec.Create(ApfsMessageTypes.QuitRequested,
            new QuitRequestedPayload("offline-gate-clean-retry", DateTime.UtcNow), Guid.NewGuid().ToString("D")));
        var retryAck = await route.Read<AckPayload>();
        Assert.True(retryAck.Success, retryAck.Message);
        Assert.True((await route.Read<ServiceStoppingPayload>()).CleanupCompleted);
        await f.Lifetime.Stopped.Task.WaitAsync(Bound);
        Assert.Equal(original, File.ReadAllBytes(failed.EvidencePath!));
        Assert.Equal(1, f.Backend.Owner.Calls);
        Assert.True(f.Lifetime.EvidenceExistedAtStop);
    }

    [Fact]
    public async Task SelectedEjectUnknownThenProof()
    {
        await using var f = new Fixture(unknown: true);
        await using var route = await Route.Open(f);
        var first = Request(ApfsControlCommands.Eject, f.Backend.Owner.Row);
        var failed = await route.Execute(first);
        Assert.False(failed.Success);
        AssertReceipt(failed);
        f.Backend.Owner.AssertRetained();
        var bytes = File.ReadAllBytes(failed.EvidencePath!);
        Assert.Equal(failed, await route.Execute(first));
        f.Backend.Owner.Unknown = false;
        // Wrong owner terminal bytes still retain the exact original resources.
        f.Backend.Owner.WriteTerminal(wrongOwner: true);
        Assert.False(f.Backend.Owner.TryCleanup());
        f.Backend.Owner.AssertRetained();
        f.Backend.Owner.WriteTerminal();
        var success = await route.Execute(Request(ApfsControlCommands.Eject, f.Backend.Owner.Row));
        Assert.True(success.Success, success.Diagnostic);
        Assert.Equal("proven", success.OwnershipProof);
        Assert.Equal("proven", success.DurabilityProof);
        AssertReceipt(success);
        Assert.Equal(bytes, File.ReadAllBytes(failed.EvidencePath!));
        Assert.False(f.Lifetime.Stopped.Task.IsCompleted);
    }

    [Fact]
    public async Task SelectedEjectCancellationDelayedDescendant()
    {
        await using var f = new Fixture(descendant: true);
        await using var operationRoute = await Route.Open(f);
        var request = Request(ApfsControlCommands.Eject, f.Backend.Owner.Row);
        var watch = Stopwatch.StartNew();
        await operationRoute.Send(Envelope(request));
        await f.Backend.StopStarted.Task.WaitAsync(Bound);
        await using var cancellationRoute = await Route.Open(f);
        await cancellationRoute.Send(PipeMessageCodec.Create(ApfsMessageTypes.CancellationRequest,
            new OperationCancellationRequestPayload(request.OperationId), request.OperationId, PipeSchemaVersions.Schema2));
        var cancelled = await cancellationRoute.Read<OperationResultPayload>();
        var result = await operationRoute.Read<OperationResultPayload>();
        Assert.Equal(ApfsOperationStates.Cancelled, result.State);
        Assert.Equal(result, cancelled);
        Assert.False(result.Success);
        Assert.Equal("not-proven", result.DurabilityProof);
        Assert.True(watch.Elapsed >= TimeSpan.FromMilliseconds(800));
        f.Backend.Owner.AssertDescendantRetainedWithoutForce();
        AssertReceipt(result);
        Assert.Equal(result, await operationRoute.Execute(request));
        var original = File.ReadAllBytes(result.EvidencePath!);
        f.Backend.Owner.ReleaseDescendant();
        await Eventually(() => f.Backend.Owner.ActiveChildren() == 0);
        Assert.True(f.Backend.Owner.TryCleanup());
        f.Backend.Owner.AssertStop(clean: true, forced: false);
        Assert.Equal(original, File.ReadAllBytes(result.EvidencePath!));
    }

    [Theory]
    [InlineData(true, "clean")] [InlineData(false, "clean")]
    [InlineData(true, "status")] [InlineData(false, "status")]
    [InlineData(true, "pending")] [InlineData(false, "pending")]
    [InlineData(true, "ownership")] [InlineData(false, "ownership")]
    [InlineData(true, "durability")] [InlineData(false, "durability")]
    public async Task QuitRequiresConsistentCleanTerminalProof(bool legacy, string vector)
    {
        await using var f = new Fixture(resultMutator: result =>
        {
            Assert.True(result.Success, result.Diagnostic);
            return vector switch
            {
                "status" => result with { FinalStatus = "shutdown-incomplete" },
                "pending" => result with { PendingDurability = true },
                "ownership" => result with { OwnershipProof = "not-proven" },
                "durability" => result with { DurabilityProof = "not-proven" },
                _ => result,
            };
        });
        await using var route = await Route.Open(f);
        var id = Guid.NewGuid().ToString("D");
        if (legacy)
        {
            await route.Send(PipeMessageCodec.Create(ApfsMessageTypes.QuitRequested,
                new QuitRequestedPayload("terminal-proof-gate", DateTime.UtcNow), id));
            _ = await route.Read<AckPayload>();
        }
        else
        {
            var request = Request(ApfsControlCommands.Quit) with { OperationId = id };
            await route.Send(Envelope(request));
            var response = await route.ReadEnvelope();
            Assert.Equal(ApfsMessageTypes.OperationResult, response.Type);
            Assert.Equal(id, response.RequestId);
            Assert.Equal(vector == "clean", PipeMessageCodec.Validate(response).IsValid);
        }
        var observed = f.Operations.Query(id)!;
        Assert.True(observed.Success);
        Assert.NotNull(observed.CompletedAtUtc);
        Assert.True(File.Exists(observed.EvidencePath), observed.Diagnostic);
        Assert.Equal(vector == "clean", PipeMessageCodec.Validate(PipeMessageCodec.Create(
            ApfsMessageTypes.OperationResult, observed, observed.OperationId, PipeSchemaVersions.Schema2)).IsValid);
        f.Backend.Owner.AssertStop(clean: true, forced: false);
        if (vector == "clean")
        {
            Assert.True((await route.Read<ServiceStoppingPayload>()).CleanupCompleted);
            await f.Lifetime.Stopped.Task.WaitAsync(Bound);
        }
        else
        {
            await Task.Delay(100);
            Assert.False(f.Lifetime.Stopped.Task.IsCompleted);
            Assert.False((bool)typeof(TrayPipeHostService).GetMethod("HasTerminalQuitEvidence", All)!.Invoke(null, [observed])!);
            Assert.False((bool)typeof(TrayPipeHostService).GetMethod("HasSuccessfulTerminalEvidence", All)!.Invoke(null, [observed])!);
        }
    }

    [Theory]
    [InlineData("clean")]
    [InlineData("accepted-debt")]
    [InlineData("cleanup-debt")]
    [InlineData("deferred")]
    [InlineData("unknown")]
    public async Task GenericFixModernWatermarks(string vector)
    {
        await using var f = new Fixture();
        var row = f.Backend.Owner.ProjectStatus(vector);
        Assert.Equal(0, row.DirtyTransactionCount);
        Assert.Equal(0, row.InFlightMutationCallbacks);
        Assert.False(row.ShutdownDrainActive);
        Assert.Equal(vector == "clean", !row.RuntimeMutationPending);
        f.Backend.Owner.Row = row;
        await using var route = await Route.Open(f);
        var result = await route.Execute(Request(ApfsControlCommands.Fix, row));
        AssertReceipt(result);
        if (vector == "clean")
        {
            Assert.True(result.Success, result.Diagnostic);
            Assert.Equal("healthy-rw", result.FinalStatus);
            Assert.False(result.PendingDurability);
            // Legacy optional-null compatibility remains explicitly supported.
            f.Backend.Owner.Row = row with { RuntimeWatermarksKnown = null, MountReady = false };
            Assert.True((await route.Execute(Request(ApfsControlCommands.Fix, row))).Success);
        }
        else
        {
            Assert.False(result.Success);
            Assert.NotEqual("healthy-rw", result.FinalStatus);
            Assert.True(result.PendingDurability);
        }
        Assert.Equal(0, f.Backend.Owner.Calls);
        Assert.Equal(0, f.Backend.ForbiddenCalls);
        Assert.False(f.Backend.Owner.Process.HasExited);
    }

    private static ControlOperationRequestPayload Request(string command, MountedVolumeState? row = null)
        => new(Guid.NewGuid().ToString("D"), command, row is null ? null : new(row.DeviceId!, row.VolumeId, row.RecoveryIdentity),
            ExpiresAtUtc: DateTime.UtcNow.AddSeconds(30));

    private static PipeEnvelope Envelope(ControlOperationRequestPayload request)
        => PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, PipeSchemaVersions.Schema2);

    private static void AssertReceipt(OperationResultPayload result)
    {
        Assert.NotNull(result.CompletedAtUtc);
        Assert.True(File.Exists(result.EvidencePath), result.Diagnostic);
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult,
            result, result.OperationId, PipeSchemaVersions.Schema2)).IsValid);
    }

    private static async Task Eventually(Func<bool> probe)
    {
        var deadline = Stopwatch.StartNew();
        while (!probe() && deadline.Elapsed < Bound) await Task.Delay(10);
        Assert.True(probe());
    }

    private sealed class Fixture : IAsyncDisposable
    {
        internal readonly StopBackend Backend;
        internal readonly ApfsMountWorker Worker;
        internal readonly AgentControlOperationService Operations;
        internal readonly TrayPipeHostService Handler;
        internal readonly RecordingLifetime Lifetime;
        internal Fixture(bool unknown = false, bool descendant = false,
            Func<OperationResultPayload, OperationResultPayload>? resultMutator = null)
        {
            var root = Environment.GetEnvironmentVariable("APFSACCESS_PUBLIC_ROUTE_TEST_ROOT")
                ?? throw new InvalidOperationException("Explicit private D: gate root required.");
            Assert.StartsWith("D:\\", Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase);
            root = Path.Combine(root, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            Backend = new StopBackend(root, unknown, descendant);
            var publisher = new RuntimeStatusPublisher();
            Worker = new(NullLogger<ApfsMountWorker>.Instance, Backend, new Policy(), publisher,
                new Options(new ServiceHostOptions { EnableNativeWrite = true, WriteRolloutChannel = "Enabled",
                    WriteBackendMode = "Native", NativeWritePromotionPolicy = "PilotHardware", ReadWriteMode = "RwWithRoFallback",
                    NativeHostStopTimeoutSeconds = 4 }));
            var executor = new AgentControlCommandExecutor(Worker,
                timestamp => QuitRequestMarker.WriteMarker(timestamp, Path.Combine(root, "quit-requested")));
            Operations = new(async (request, token) =>
            {
                var result = await executor.ExecuteAsync(request, token);
                return resultMutator is null ? result : resultMutator(result);
            }, Path.Combine(root, "operations"));
            Lifetime = new RecordingLifetime(Backend);
            Handler = new(NullLogger<TrayPipeHostService>.Instance, publisher, Worker, Lifetime, Operations);
        }
        public async ValueTask DisposeAsync()
        {
            Backend.Closing.TrySetResult();
            try { await Operations.StopAsync(CancellationToken.None).WaitAsync(Bound); }
            finally
            {
                Worker.Dispose();
                Handler.Dispose();
                await Backend.DisposeAsync();
            }
        }
    }

    private sealed class RecordingLifetime(StopBackend backend) : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        internal TaskCompletionSource Stopped { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool EvidenceExistedAtStop;
        public void StopApplication()
        {
            EvidenceExistedAtStop = Directory.GetFiles(Path.Combine(backend.Root, "operations"), "*.json").Any(File.Exists);
            Stopped.TrySetResult();
        }
    }

    private sealed class Route : IAsyncDisposable
    {
        private readonly NamedPipeServerStream _server;
        private readonly PipePeer _client;
        private readonly PipePeer _peer;
        private readonly Task _handler;
        private readonly CancellationTokenSource _bound = new(Bound);
        private Route(Fixture fixture, NamedPipeServerStream server, NamedPipeClientStream client)
        {
            _server = server;
            _client = new(client);
            _peer = new(server);
            _handler = (Task)typeof(TrayPipeHostService).GetMethod("HandleClientAsync", All)!
                .Invoke(fixture.Handler, [_peer, _bound.Token])!;
        }
        internal static async Task<Route> Open(Fixture fixture)
        {
            var name = "apfs-offline-owned-" + Guid.NewGuid().ToString("N");
            var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            var connect = client.ConnectAsync(2000);
            await server.WaitForConnectionAsync();
            await connect;
            var route = new Route(fixture, server, client);
            var initial = await route._client.ReadMessageAsync(route._bound.Token);
            Assert.Equal(ApfsMessageTypes.StatusChanged, initial!.Type);
            return route;
        }
        internal Task Send(PipeEnvelope envelope)
        {
            var validation = PipeMessageCodec.Validate(envelope);
            Assert.True(validation.IsValid, validation.Diagnostic);
            return _client.SendAsync(envelope, _bound.Token);
        }
        internal async Task<T> Read<T>()
        {
            var envelope = await ReadEnvelope();
            Assert.True(PipeMessageCodec.TryGetPayload<T>(envelope!, out var payload));
            return payload!;
        }
        internal async Task<PipeEnvelope> ReadEnvelope()
        {
            var envelope = await _client.ReadMessageAsync(_bound.Token);
            Assert.NotNull(envelope);
            return envelope;
        }
        internal async Task<OperationResultPayload> Execute(ControlOperationRequestPayload request)
        {
            await Send(Envelope(request));
            return await Read<OperationResultPayload>();
        }
        public async ValueTask DisposeAsync()
        {
            await _client.DisposeAsync();
            await _handler.WaitAsync(Bound);
            await _peer.DisposeAsync();
            await _server.DisposeAsync();
            _bound.Dispose();
        }
    }

    private sealed class StopBackend : IApfsBackend, IUnmountTerminalStateBackend, IAsyncDisposable
    {
        internal readonly string Root;
        internal readonly Owner Owner;
        private readonly List<Owner> _owners = [];
        internal Task Hold = Task.CompletedTask;
        internal TaskCompletionSource Closing = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource StopStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool HideRows;
        internal MountedVolumeState? Replacement;
        internal int ForbiddenCalls;
        internal StopBackend(string root, bool unknown, bool descendant)
        {
            Root = root;
            Owner = AddOwner("main", unknown, descendant);
        }
        internal Owner AddOwner(string name, bool unknown, bool descendant = false)
        {
            var owner = new Owner(Path.Combine(Root, name), unknown, descendant);
            _owners.Add(owner);
            return owner;
        }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token)
            => Task.FromResult<IReadOnlyList<DeviceInfo>>([new("offline-owned-device", "Dedicated offline fixture", true)]);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token)
            => Task.FromResult<IReadOnlyList<VolumeInfo>>(_owners.Select(owner => new VolumeInfo(owner.Row.VolumeId,
                owner.Row.DeviceId!, owner.Row.VolumeName!, SupportsReadWrite: true, SupportsNativeWrite: true,
                NativeWriteReadiness: NativeWriteReadiness.CommitReady, RecoveryIdentity: owner.Row.RecoveryIdentity)).ToArray());
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            ForbiddenCalls++;
            throw new InvalidOperationException("Mount/native/driver invocation is outside this offline gate.");
        }
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<MountedVolumeState>>(Replacement is not null ? [Replacement] :
                HideRows ? [] : _owners.Where(owner => !owner.Cleaned).Select(owner => owner.Row).ToArray());
        }
        public async Task<UnmountResult> UnmountAsync(string point, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var owner = _owners.Single(o => o.Row.MountPoint == point);
            owner.Calls++;
            // Mirrors the frozen public cancellation handoff without entering its
            // drive normalization/Shell path. All result facts are real private proofs.
            var stop = owner.Stop();
            StopStarted.TrySetResult();
            await stop;
            await Task.WhenAny(Hold, Closing.Task);
            owner.TryCleanup();
            return owner.Result();
        }
        public Task<UnmountResult> GetUnmountTerminalStateAsync(MountedVolumeState selected, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var owner = _owners.FirstOrDefault(o =>
                selected.HostProcessId > 0 && selected.HostProcessCreationTimeFileTimeUtc > 0 &&
                o.Row.HostProcessId == selected.HostProcessId && o.Start == selected.HostProcessCreationTimeFileTimeUtc &&
                string.Equals(o.Row.MountPoint, selected.MountPoint, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(o.Row.DeviceId, selected.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(o.Row.VolumeId, selected.VolumeId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(o.Row.RecoveryIdentity, selected.RecoveryIdentity, StringComparison.Ordinal) &&
                string.Equals(o.Row.CatalogContainerUuid, selected.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase) &&
                o.Row.CatalogVolumeObjectId == selected.CatalogVolumeObjectId &&
                string.Equals(o.Row.CatalogVolumeUuid, selected.CatalogVolumeUuid, StringComparison.OrdinalIgnoreCase));
            if (owner is null) return Task.FromResult(new UnmountResult(false, selected.MountPoint, "Original owner identity does not match."));
            owner.TerminalReads++;
            return Task.FromResult(owner.TerminalResult());
        }
        public async ValueTask DisposeAsync()
        {
            foreach (var owner in _owners) await owner.DisposeAsync();
            Assert.Equal(0, ForbiddenCalls);
        }
    }

    private sealed class Owner : IAsyncDisposable
    {
        private static readonly Assembly Native = typeof(NativeApfsBackend).Assembly;
        private readonly object _guardian;
        private readonly object _lifetime;
        private readonly object _gate;
        private readonly object _state;
        private readonly NativeApfsBackend _backend;
        private readonly SafeHandle _original;
        private readonly IDisposable? _stderr;
        private readonly string _root;
        internal readonly string StatusPath;
        internal readonly Process Process;
        internal readonly long Start;
        internal bool Unknown;
        internal bool Cleaned;
        internal int Calls;
        internal int TerminalReads;
        private readonly string? _descendantRelease;
        internal MountedVolumeState Row;
        internal Task Released => (Task)Property(_guardian, "OwnershipReleased")!;
        internal Owner(string root, bool unknown, bool descendant)
        {
            _root = root;
            Unknown = unknown;
            Directory.CreateDirectory(root);
            var point = Path.Combine(root, "namespace");
            Directory.CreateDirectory(point);
            Assert.False((File.GetAttributes(point) & FileAttributes.ReparsePoint) != 0);
            var lifetimePath = Path.Combine(root, "host.alive");
            _lifetime = Native.GetType("ApfsAccess.Backend.Native.HostLifetimeSentinel")!
                .GetMethod("Create", All)!.Invoke(null, [lifetimePath])!;
            _gate = Native.GetType("ApfsAccess.Backend.Native.HostStartupGate")!.GetMethod("Create", All)!.Invoke(null, [root])!;
            var helper = Environment.GetEnvironmentVariable("APFSACCESS_GUARDIAN_TEST_CHILD")
                ?? throw new InvalidOperationException("Pinned dedicated helper required.");
            Assert.StartsWith("D:\\", helper, StringComparison.OrdinalIgnoreCase);
            var start = new ProcessStartInfo(helper) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = root };
            if (descendant)
            {
                _descendantRelease = Path.Combine(root, "descendant-drain.alive");
                File.WriteAllText(_descendantRelease, "owned drain");
                var script = Path.Combine(root, "owned-drain-tree.ps1");
                File.WriteAllText(script, """
                    param([string]$Root, [switch]$Child)
                    $ErrorActionPreference = 'Stop'
                    if ($Child) {
                        [IO.File]::WriteAllText((Join-Path $Root 'descendant.ready'), [string]$PID)
                        while ([IO.File]::Exists((Join-Path $Root 'descendant-drain.alive'))) { Start-Sleep -Milliseconds 10 }
                        exit 0
                    }
                    $start = New-Object Diagnostics.ProcessStartInfo
                    $start.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
                    $start.Arguments = '-NoLogo -NoProfile -File "' + $PSCommandPath + '" -Root "' + $Root + '" -Child'
                    $start.UseShellExecute = $false
                    $start.CreateNoWindow = $true
                    $childProcess = [Diagnostics.Process]::Start($start)
                    while (![IO.File]::Exists((Join-Path $Root 'descendant.ready'))) { Start-Sleep -Milliseconds 10 }
                    [IO.File]::WriteAllText((Join-Path $Root 'ready.txt'), [string]$PID)
                    while ([IO.File]::Exists((Join-Path $Root 'host.alive'))) { Start-Sleep -Milliseconds 10 }
                    exit 0
                    """);
                start.FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
                foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-File", script, "-Root", root }) start.ArgumentList.Add(argument);
            }
            else
            {
                start.ArgumentList.Add("--ready"); start.ArgumentList.Add(Path.Combine(root, "ready.txt"));
                start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = lifetimePath;
            }
            var guardianType = Native.GetType("ApfsAccess.Backend.Native.HostProcessGuardian")!;
            var launch = guardianType.GetMethods(All).Single(m => m.Name == "Start" && m.GetParameters().Length == 2)
                .Invoke(null, [start, _gate])!;
            Process = (Process)Property(launch, "Process")!;
            _guardian = Property(launch, "Guardian")!;
            _stderr = (IDisposable?)Property(launch, "StartupStderr");
            _original = (SafeHandle)guardianType.GetField("_processHandle", All)!.GetValue(_guardian)!;
            Start = (long)Property(_guardian, "CreationTimeFileTimeUtc")!;
            StatusPath = Path.Combine(root, "host.status.json");
            _state = typeof(NativeApfsBackend).GetNestedType("HostProcessState", All)!.GetConstructors(All)
                .Single(c => c.GetParameters().Length == 8).Invoke([Process, _guardian, _lifetime, lifetimePath,
                    Property(_gate, "FilePath"), StatusPath, MountAccessMode.ReadWrite, "Native"]);
            _state.GetType().GetProperty("OriginalMountPoints", All)!.SetValue(_state, new[] { point });
            var hooks = Activator.CreateInstance(Native.GetType("ApfsAccess.Backend.Native.HostProcessLifecycleTestHooks")!)!;
            hooks.GetType().GetProperty("QueryMountAttributes")!.SetValue(hooks, (Func<string, (uint, int)>)(path =>
            {
                Assert.Equal(point, path);
                return Unknown ? (uint.MaxValue, 5) : ((uint)File.GetAttributes(path), 0);
            }));
            _backend = (NativeApfsBackend)typeof(NativeApfsBackend).GetConstructors(All)
                .Single(c => c.GetParameters().Length == 3).Invoke([new ServiceHostOptions {
                    NativeHostStopTimeoutSeconds = 1, NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json") }, hooks, null]);
            Assert.True(SpinWait.SpinUntil(() => File.Exists(Path.Combine(root, "ready.txt")), Bound));
            Row = new("offline-owned-device|" + Path.GetFileName(root), point, MountAccessMode.ReadWrite,
                Path.GetFileName(root), "offline-owned-device", WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.CommitReady, NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
                RecoveryIdentity: "owned-" + Path.GetFileName(root), MountReady: true, HostProcessId: Process.Id,
                HostProcessCreationTimeFileTimeUtc: Start);
            WriteTerminal();
        }
        internal Task Stop() => (Task)Invoke("StopHostProcessAsync", _state, CancellationToken.None)!;
        internal bool TryCleanup() => Cleaned = (bool)Invoke("CleanupHostResources", _state)!;
        internal UnmountResult Result()
            => (UnmountResult)typeof(NativeApfsBackend).GetMethod("BuildCompletedUnmountResult", All)!
                .Invoke(null, [Row.MountPoint, Invoke("CaptureHostStopResult", _state)])!;
        internal UnmountResult TerminalResult()
            => Property(_state, "CompletedStopResult") is { } completed
                ? (UnmountResult)typeof(NativeApfsBackend).GetMethod("BuildCompletedUnmountResult", All)!
                    .Invoke(null, [Row.MountPoint, completed])!
                : new(false, Row.MountPoint, "The original terminal cleanup proof is unknown.");
        internal uint ActiveChildren()
        {
            object?[] args = [0u];
            Assert.True((bool)_guardian.GetType().GetMethod("TryGetActiveProcessCount", All)!.Invoke(_guardian, args)!);
            return (uint)args[0]!;
        }
        internal void AssertRetained()
        {
            Assert.False(Cleaned);
            Assert.False(_original.IsClosed);
            Assert.False(Released.IsCompleted);
            Assert.True(File.Exists(StatusPath));
            Assert.True(File.Exists((string)Property(_gate, "FilePath")!));
        }
        internal void AssertDescendantRetainedWithoutForce()
        {
            Assert.True(Process.HasExited);
            Assert.True(ActiveChildren() > 0);
            AssertRetained();
            var proof = Invoke("CaptureHostStopResult", _state)!;
            Assert.False((bool)Property(proof, "ForcedKill")!);
            Assert.False((bool)Property(proof, "GuardianSettled")!);
            Assert.False((bool)Property(proof, "PendingDurabilityCleared")!);
        }
        internal void ReleaseDescendant()
        {
            Assert.NotNull(_descendantRelease);
            File.Delete(_descendantRelease);
        }
        internal void AssertStop(bool clean, bool forced)
        {
            var proof = Invoke("CaptureHostStopResult", _state)!;
            Assert.True((bool)Property(proof, "ProcessExited")!);
            Assert.True((bool)Property(proof, "GuardianSettled")!);
            Assert.True((bool)Property(proof, "MountAbsent")!);
            Assert.True((bool)Property(proof, "NativeTerminalProven")!);
            Assert.Equal(forced, Property(proof, "ForcedKill"));
            Assert.Equal(0, Property(proof, "ExitCode"));
            Assert.Equal(clean, Result().PendingDurabilityCleared);
            Assert.True(Released.IsCompletedSuccessfully);
            Assert.True(_original.IsClosed);
        }
        internal void WriteTerminal(bool wrongOwner = false)
        {
            var values = Drain("clean");
            values["hostPid"] = wrongOwner ? Process.Id + 1 : Process.Id;
            values["mountReady"] = false;
            File.WriteAllText(StatusPath, JsonSerializer.Serialize(values));
        }
        internal MountedVolumeState ProjectStatus(string vector)
        {
            const string container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            var child = vector == "unknown" ? new Dictionary<string, object>() : Drain(vector);
            child["objectId"] = 101; child["canonicalId"] = $"apfs-vol:{container}:101";
            child["mounted"] = true; child["ready"] = true; child["writable"] = true;
            child["recoveryIdentity"] = Row.RecoveryIdentity!; child["recoveryActive"] = false;
            child["writeDegraded"] = false; child["recoveryReason"] = "";
            var path = Path.Combine(_root, "synthetic-container-status.json");
            File.WriteAllText(path, JsonSerializer.Serialize(new { containerUuid = container, ownerPid = Process.Id,
                ownerStartFileTimeUtc = Start, leaseHeld = true, checkpointXid = 15153,
                recoveryRequired = false, recoveryVolumeObjectId = (ulong?)null, recoveryReason = "", volumes = new[] { child } }));
            var parsed = ContainerStatusReader.TryRead(path, container);
            Assert.True(parsed.IsKnown, parsed.UnknownReason);
            Assert.Equal(Start, parsed.OwnerStartFileTimeUtc);
            return (MountedVolumeState)Native.GetType("ApfsAccess.Backend.Native.ContainerRuntimeDiagnostics")!
                .GetMethod("ApplyWatermarks", All)!.Invoke(null, [Row, parsed.IsKnown, parsed.Volumes.Single()])!;
        }
        private static Dictionary<string, object> Drain(string vector) => new()
        {
            ["dirtyTransactionCount"] = 0, ["inFlightMutationCallbacks"] = 0,
            ["closeCommitDeferred"] = vector == "deferred", ["deferredCommitRequested"] = false,
            ["deferredCommitInFlight"] = false, ["shutdownDrainActive"] = false, ["walRecoveryStateValid"] = true,
            ["walAcceptedSequence"] = 3, ["walApfsDurableSequence"] = vector == "accepted-debt" ? 2 : 3,
            ["walCleanupSequence"] = vector is "accepted-debt" or "cleanup-debt" ? 2 : 3,
            ["payloadSpoolDirtyRangeCount"] = 0, ["payloadSpoolIndexDirty"] = false, ["payloadSpoolRecoveryRequired"] = false,
        };
        private object? Invoke(string method, params object?[] args)
            => typeof(NativeApfsBackend).GetMethod(method, All)!.Invoke(_backend, args);
        private static object? Property(object value, string name) => value.GetType().GetProperty(name, All)!.GetValue(value);
        public async ValueTask DisposeAsync()
        {
            Unknown = false;
            if (_descendantRelease is not null) File.Delete(_descendantRelease);
            ((IDisposable)_guardian).Dispose();
            await Released.WaitAsync(Bound);
            _stderr?.Dispose();
            ((IDisposable)_lifetime).Dispose();
            ((IDisposable)_gate).Dispose();
            Process.Dispose();
            _backend.Dispose();
            Assert.True(_original.IsClosed);
        }
    }

    private sealed class Policy : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters) => throw new InvalidOperationException("No mount allowed.");
        public bool ShouldAutoMount(VolumeInfo volume) => false;
    }
    private sealed class Options(ServiceHostOptions value) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => value;
        public ServiceHostOptions Get(string? name) => value;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
}
