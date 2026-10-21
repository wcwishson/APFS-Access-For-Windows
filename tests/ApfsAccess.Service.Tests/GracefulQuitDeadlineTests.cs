using System.IO.Pipes;
using System.Reflection;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class GracefulQuitDeadlineTests
{
    [Theory]
    [InlineData(ApfsControlCommands.Quit)]
    [InlineData(ApfsControlCommands.Mount)]
    public async Task ExpiredAdmission_RemainsRejectedWithoutDispatch(string command)
    {
        var root = Path.Combine(Path.GetTempPath(), "expired-shutdown-" + Guid.NewGuid().ToString("N"));
        var calls = 0;
        var operations = new AgentControlOperationService((_, _) =>
        {
            calls++;
            throw new InvalidOperationException("Expired work must not be dispatched.");
        }, root);
        try
        {
            var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), command,
                command == ApfsControlCommands.Quit ? null : new ApfsControlTarget("device-1", "device-1|Main"),
                ExpiresAtUtc: DateTime.UtcNow.AddSeconds(-1));
            var result = await operations.ExecuteOrReplayAsync(request).WaitAsync(TimeSpan.FromSeconds(3));
            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.Timeout, result.Code);
            Assert.Equal(0, calls);
        }
        finally { await operations.StopAsync(CancellationToken.None); Directory.Delete(root, true); }
    }

    [Fact]
    public async Task NonQuitExecution_StillCancelsAndReconcilesAtItsDeadline()
    {
        var root = Path.Combine(Path.GetTempPath(), "bounded-nonquit-" + Guid.NewGuid().ToString("N"));
        var calls = 0;
        var observedCancellation = false;
        var operations = new AgentControlOperationService(async (_, token) =>
        {
            calls++;
            try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            catch (OperationCanceledException) { observedCancellation = token.IsCancellationRequested; throw; }
            throw new InvalidOperationException("A non-Quit execution must remain deadline bounded.");
        }, root);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.Mount,
                new ApfsControlTarget("device-1", "device-1|Main"), ExpiresAtUtc: DateTime.UtcNow.AddSeconds(1));
            await operations.ExecuteOrReplayAsync(request).WaitAsync(timeout.Token);
            while (operations.Query(request.OperationId)!.State != ApfsOperationStates.Failed)
                await Task.Delay(10, timeout.Token);
            var result = operations.Query(request.OperationId)!;
            Assert.Equal(ApfsOperationCodes.Timeout, result.Code);
            Assert.False(result.Success);
            Assert.True(observedCancellation);
            Assert.Equal(1, calls);
        }
        finally { await operations.StopAsync(timeout.Token); Directory.Delete(root, true); }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AdmittedQuit_RetainsOriginalRequestPastExpiryAndStopsOnlyOnGenuineSuccess(bool clean)
    {
        var root = Path.Combine(Path.GetTempPath(), "graceful-quit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var executionToken = CancellationToken.None;
        var clock = new AdjustableTimeProvider(DateTimeOffset.UtcNow);
        var operations = new AgentControlOperationService(async (request, token) =>
        {
            calls++;
            executionToken = token;
            entered.SetResult();
            await release.Task.WaitAsync(token);
            var now = clock.GetUtcNow().UtcDateTime;
            return new OperationResultPayload(request.OperationId, request.Command, null, null,
                clean ? ApfsOperationStates.Succeeded : ApfsOperationStates.Failed,
                clean ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.UnsafeOwnership,
                clean, now, StartedAtUtc: now, CompletedAtUtc: now,
                FinalStatus: clean ? "shutdown-complete" : "shutdown-incomplete",
                OwnershipProof: clean ? "proven" : "not-proven", DurabilityProof: clean ? "proven" : "not-proven",
                PendingDurability: !clean);
        }, root, clock);
        var lifetime = new Lifetime();
        using var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, new NoBackend(), new Policy(),
            new RuntimeStatusPublisher(), new Options());
        var host = new TrayPipeHostService(NullLogger<TrayPipeHostService>.Instance, new RuntimeStatusPublisher(), worker, lifetime, operations);
        var name = "ApfsAccess.PrivateShutdownTest." + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var connected = server.WaitForConnectionAsync(timeout.Token);
        await client.ConnectAsync(timeout.Token);
        await connected;
        await using var serverPeer = new PipePeer(server);
        await using var clientPeer = new PipePeer(client);
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.Quit,
            Target: null, ExpiresAtUtc: clock.GetUtcNow().UtcDateTime.AddMilliseconds(300));
        var message = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, PipeSchemaVersions.Schema2);
        var method = typeof(TrayPipeHostService).GetMethod("HandleAgentControlMessageAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var response = clientPeer.ReadMessageAsync(timeout.Token);
        var handling = (Task<bool>)method.Invoke(host, [serverPeer, message, timeout.Token])!;
        try
        {
            Assert.Same(entered.Task, await Task.WhenAny(entered.Task, handling).WaitAsync(timeout.Token));
            // Keep admission independent of evidence I/O; the production deadline still uses a real timer.
            clock.Advance(TimeSpan.FromSeconds(1));
            await Task.Delay(700, timeout.Token);
            Assert.False(executionToken.IsCancellationRequested);
            Assert.False(handling.IsCompleted, "The original request must retain the eventual shutdown continuation.");
            Assert.Equal(ApfsOperationStates.InProgress, operations.Query(request.OperationId)!.State);
            Assert.False(lifetime.Stopped);

            release.SetResult();
            Assert.Equal(clean, await handling.WaitAsync(timeout.Token));
            Assert.NotNull(await response);
            var terminal = operations.Query(request.OperationId)!;
            Assert.Equal(clean, terminal.Success);
            Assert.Contains("after the service deadline", terminal.Diagnostic);
            Assert.Equal(clean, lifetime.Stopped);
            Assert.Equal(1, calls);
            Assert.True(File.Exists(terminal.EvidencePath));
            Assert.Equal(terminal, await operations.ExecuteOrReplayAsync(request));
        }
        finally
        {
            release.TrySetResult();
            await operations.StopAsync(timeout.Token);
            await handling.WaitAsync(timeout.Token);
            host.Dispose();
            Directory.Delete(root, true);
        }
    }

    private sealed class AdjustableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private readonly object _gate = new();
        private DateTimeOffset _utcNow = utcNow;
        public override DateTimeOffset GetUtcNow() { lock (_gate) return _utcNow; }
        public void Advance(TimeSpan elapsed) { lock (_gate) _utcNow += elapsed; }
    }

    private sealed class Lifetime : IHostApplicationLifetime
    {
        public bool Stopped { get; private set; }
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() => Stopped = true;
    }
    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new();
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
    private sealed class Policy : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters) => throw new NotSupportedException();
        public bool ShouldAutoMount(VolumeInfo volume) => false;
    }
    private sealed class NoBackend : IApfsBackend
    {
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string id, CancellationToken token) => throw new NotSupportedException();
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token) => throw new NotSupportedException();
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token) => throw new NotSupportedException();
    }
}
