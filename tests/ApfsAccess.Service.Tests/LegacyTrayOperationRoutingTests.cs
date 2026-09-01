using System.IO.Pipes;
using System.Reflection;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class LegacyTrayOperationRoutingTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(10);
    private static readonly string EvidenceBase = Path.Combine(
        Path.GetTempPath(),
        "ApfsAccessTests",
        "LegacyTrayOperationRouting");
    private const string DeviceId = @"\\.\PhysicalDrive2";
    private const string VolumeId = @"\\.\PhysicalDrive2|Main";
    private const string OtherVolumeId = @"\\.\PhysicalDrive2|Other";
    private const string RecoveryIdentity = "apfs-recovery-v1|main";

    public static TheoryData<string> LegacyMutations => new()
    {
        ApfsMessageTypes.MountRequested,
        ApfsMessageTypes.FixRequested,
        ApfsMessageTypes.EjectRequested,
        ApfsMessageTypes.QuitRequested,
    };

    [Theory]
    [MemberData(nameof(LegacyMutations))]
    public async Task LegacyMutation_UsesDurableOperationServiceWithoutDirectWorkerMutation(
        string messageType)
    {
        var backend = new RecordingBackend(startMounted: messageType is
            ApfsMessageTypes.EjectRequested or ApfsMessageTypes.QuitRequested);
        await using var fixture = CreateFixture(backend);
        var timestamp = DateTime.UtcNow;
        var requestId = Guid.NewGuid().ToString("N");
        ControlOperationRequestPayload? captured = null;
        fixture.SetExecutor((request, _) =>
        {
            captured = request;
            return Task.FromResult(Success(request));
        });

        var response = await ExchangeAsync(
            fixture.Service,
            LegacyRequest(messageType, requestId, timestamp, VolumeId),
            TestTimeout);

        var ack = ReadAck(response);
        Assert.True(ack.Success, ack.Message);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, ack.Code);
        Assert.NotNull(captured);
        Assert.Equal(Guid.Parse(requestId).ToString("D").ToLowerInvariant(), captured!.OperationId);
        Assert.Equal(ExpectedCommand(messageType), captured.Command);
        Assert.Equal(
            messageType == ApfsMessageTypes.MountRequested
                ? ApfsControlModes.ReadWrite
                : null,
            captured.RequestedMode);
        Assert.Equal(timestamp.AddMinutes(2), captured.ExpiresAtUtc);
        Assert.Equal(
            messageType == ApfsMessageTypes.QuitRequested
                ? null
                : new ApfsControlTarget(
                    DeviceId.ToLowerInvariant(),
                    VolumeId.ToLowerInvariant(),
                    RecoveryIdentity),
            captured.Target);
        Assert.Equal(1, fixture.ExecutorCalls);
        Assert.Equal(0, backend.MountCalls);
        Assert.Equal(0, backend.UnmountCalls);
        Assert.Single(Directory.GetFiles(fixture.EvidenceRoot, "*.json"));
    }

    [Fact]
    public async Task LegacyMount_DurableResultIsValidForSchema2QueryAndReplay()
    {
        var backend = new RecordingBackend();
        await using var fixture = CreateFixtureWithRealExecutor(backend);
        var requestId = Guid.NewGuid().ToString("N");
        var operationId = Guid.Parse(requestId).ToString("D").ToLowerInvariant();

        var response = await ExchangeAsync(
            fixture.Service,
            LegacyRequest(
                ApfsMessageTypes.MountRequested,
                requestId,
                DateTime.UtcNow,
                VolumeId),
            TestTimeout);

        var ack = ReadAck(response);
        Assert.True(ack.Success, ack.Message);
        var evidencePath = Assert.Single(Directory.GetFiles(fixture.EvidenceRoot, "*.json"));
        var evidence = JsonSerializer.Deserialize<OperationResultPayload>(
            await File.ReadAllTextAsync(evidencePath),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.NotNull(evidence);
        Assert.Equal(operationId, evidence!.OperationId);
        Assert.Equal(ApfsControlModes.ReadWrite, evidence.RequestedMode);

        var schema2Result = PipeMessageCodec.Create(
            ApfsMessageTypes.OperationResult,
            evidence,
            evidence.OperationId,
            PipeSchemaVersions.Schema2);
        var validation = PipeMessageCodec.Validate(schema2Result);
        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    [Fact]
    public async Task LegacyMount_ReadOnlyVolumeRequestsCanonicalReadOnlyMode()
    {
        var readOnlyVolume = TestVolume(VolumeId, RecoveryIdentity) with
        {
            SupportsReadWrite = false,
            SupportsNativeWrite = false,
            NativeWriteReadiness = NativeWriteReadiness.Unavailable,
        };
        var backend = new RecordingBackend(volumes: [readOnlyVolume]);
        await using var fixture = CreateFixture(backend);
        ControlOperationRequestPayload? captured = null;
        fixture.SetExecutor((request, _) =>
        {
            captured = request;
            return Task.FromResult(Success(request));
        });

        var response = await ExchangeAsync(
            fixture.Service,
            LegacyRequest(
                ApfsMessageTypes.MountRequested,
                Guid.NewGuid().ToString("N"),
                DateTime.UtcNow,
                VolumeId),
            TestTimeout);

        Assert.True(ReadAck(response).Success);
        Assert.NotNull(captured);
        Assert.Equal(ApfsControlModes.ReadOnly, captured!.RequestedMode);
    }

    [Fact]
    public async Task LegacyRequestIdentity_ReplaysSamePayloadAndRejectsChangedPayload()
    {
        var backend = new RecordingBackend(volumes:
        [
            TestVolume(VolumeId, RecoveryIdentity),
            TestVolume(OtherVolumeId, "apfs-recovery-v1|other"),
        ]);
        await using var fixture = CreateFixture(backend);
        fixture.SetExecutor((request, _) => Task.FromResult(Success(request)));
        var timestamp = DateTime.UtcNow;
        var requestId = Guid.NewGuid().ToString("N");
        var original = LegacyRequest(
            ApfsMessageTypes.MountRequested,
            requestId,
            timestamp,
            VolumeId);
        var changed = LegacyRequest(
            ApfsMessageTypes.MountRequested,
            requestId,
            timestamp,
            OtherVolumeId);

        var first = ReadAck(await ExchangeAsync(fixture.Service, original, TestTimeout));
        var replay = ReadAck(await ExchangeAsync(fixture.Service, original, TestTimeout));
        var conflict = ReadAck(await ExchangeAsync(fixture.Service, changed, TestTimeout));

        Assert.True(first.Success);
        Assert.Equal(first.Success, replay.Success);
        Assert.Equal(first.Code, replay.Code);
        Assert.Equal(first.Message, replay.Message);
        Assert.False(conflict.Success);
        Assert.Equal(ApfsOperationCodes.OperationConflict, conflict.Code);
        Assert.Contains("fingerprint", conflict.Message!, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, fixture.ExecutorCalls);
        Assert.Equal(0, backend.MountCalls);
        Assert.Single(Directory.GetFiles(fixture.EvidenceRoot, "*.json"));
    }

    [Fact]
    public async Task LegacyMutation_StaleDeterministicExpiryReturnsDurableTimeout()
    {
        var backend = new RecordingBackend();
        await using var fixture = CreateFixture(backend);
        fixture.SetExecutor((request, _) => Task.FromResult(Success(request)));
        var requestId = Guid.NewGuid().ToString("N");
        var staleTimestamp = DateTime.UtcNow.AddMinutes(-3);

        var response = await ExchangeAsync(
            fixture.Service,
            LegacyRequest(
                ApfsMessageTypes.MountRequested,
                requestId,
                staleTimestamp,
                VolumeId),
            TestTimeout);

        var ack = ReadAck(response);
        Assert.False(ack.Success);
        Assert.Equal(ApfsOperationCodes.Timeout, ack.Code);
        Assert.Contains("expired", ack.Message!, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, fixture.ExecutorCalls);
        Assert.Equal(0, backend.MountCalls);
        var evidencePath = Path.Combine(
            fixture.EvidenceRoot,
            $"{Guid.Parse(requestId):D}.json".ToLowerInvariant());
        Assert.True(File.Exists(evidencePath));
    }

    [Fact]
    public async Task LegacyMutation_MissingTargetReturnsDurableMissingVolumeWithoutMutation()
    {
        var backend = new RecordingBackend();
        await using var fixture = CreateFixtureWithRealExecutor(backend);
        var missingVolume = $@"{DeviceId}|Missing";

        var response = await ExchangeAsync(
            fixture.Service,
            LegacyRequest(
                ApfsMessageTypes.MountRequested,
                Guid.NewGuid().ToString("N"),
                DateTime.UtcNow,
                missingVolume),
            TestTimeout);

        var ack = ReadAck(response);
        Assert.False(ack.Success);
        Assert.Equal(ApfsOperationCodes.MissingVolume, ack.Code);
        Assert.Equal(0, backend.MountCalls);
        Assert.Equal(0, backend.UnmountCalls);
        Assert.Single(Directory.GetFiles(fixture.EvidenceRoot, "*.json"));
    }

    [Fact]
    public async Task LegacyMutation_DuplicateInventoryRowsUseDurableAmbiguousRejectionTarget()
    {
        foreach (var volumeId in new string?[] { VolumeId, null })
        {
            var backend = new RecordingBackend(duplicateDevice: true);
            await using var fixture = CreateFixtureWithRealExecutor(backend);

            var response = await ExchangeAsync(
                fixture.Service,
                LegacyRequest(
                    ApfsMessageTypes.EjectRequested,
                    Guid.NewGuid().ToString("N"),
                    DateTime.UtcNow,
                    volumeId),
                TestTimeout);

            var ack = ReadAck(response);
            Assert.False(ack.Success);
            Assert.Equal(ApfsOperationCodes.AmbiguousTarget, ack.Code);
            Assert.Equal(0, backend.MountCalls);
            Assert.Equal(0, backend.UnmountCalls);
            var evidencePath = Assert.Single(Directory.GetFiles(fixture.EvidenceRoot, "*.json"));
            var evidence = JsonSerializer.Deserialize<OperationResultPayload>(
                await File.ReadAllTextAsync(evidencePath),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            Assert.NotNull(evidence?.Target);
            Assert.Equal("legacy-ambiguous-target", evidence!.Target!.RecoveryIdentity);
            Assert.NotEqual(RecoveryIdentity, evidence.Target.RecoveryIdentity);
        }
    }

    [Fact]
    public async Task LegacyMutation_NullTargetWithMultipleVolumesFailsWithoutMutation()
    {
        var backend = new RecordingBackend(
            startMounted: true,
            volumes:
            [
                TestVolume(VolumeId, RecoveryIdentity),
                TestVolume(OtherVolumeId, "apfs-recovery-v1|other"),
            ]);
        await using var fixture = CreateFixtureWithRealExecutor(backend);

        var response = await ExchangeAsync(
            fixture.Service,
            LegacyRequest(
                ApfsMessageTypes.EjectRequested,
                Guid.NewGuid().ToString("N"),
                DateTime.UtcNow,
                volumeId: null),
            TestTimeout);

        var ack = ReadAck(response);
        Assert.False(ack.Success);
        Assert.Equal(ApfsOperationCodes.AmbiguousTarget, ack.Code);
        Assert.Equal(0, backend.UnmountCalls);
        Assert.Single(Directory.GetFiles(fixture.EvidenceRoot, "*.json"));
    }

    [Fact]
    public async Task LegacyAck_UsesDurableResultSuccessCodeAndDiagnostic()
    {
        var backend = new RecordingBackend();
        await using var fixture = CreateFixture(backend);
        fixture.SetExecutor((request, _) => Task.FromResult(Failure(
            request,
            ApfsOperationCodes.BlockedRecovery,
            "Durable executor rejected the recovery state.")));

        var response = await ExchangeAsync(
            fixture.Service,
            LegacyRequest(
                ApfsMessageTypes.FixRequested,
                Guid.NewGuid().ToString("N"),
                DateTime.UtcNow,
                VolumeId),
            TestTimeout);

        var ack = ReadAck(response);
        Assert.False(ack.Success);
        Assert.Equal(ApfsOperationCodes.BlockedRecovery, ack.Code);
        Assert.Equal("Durable executor rejected the recovery state.", ack.Message);
        Assert.Equal(0, backend.MountCalls);
    }

    [Fact]
    public async Task LegacyRefreshWithoutClear_IsReadOnlyAndDoesNotEnterOperationService()
    {
        var backend = new RecordingBackend();
        await using var fixture = CreateFixture(backend);
        fixture.SetExecutor((request, _) => Task.FromResult(Success(request)));
        var request = PipeMessageCodec.Create(
            ApfsMessageTypes.RefreshRequested,
            new RefreshRequestedPayload(
                "legacy-tray",
                DateTime.UtcNow,
                ClearUserEjectedVolumes: false,
                VolumeId),
            Guid.NewGuid().ToString("N"));

        var ack = ReadAck(await ExchangeAsync(fixture.Service, request, TestTimeout));

        Assert.True(ack.Success, ack.Message);
        Assert.Contains("inventory", ack.Message!, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, fixture.ExecutorCalls);
        Assert.Equal(0, backend.MountCalls);
        Assert.Equal(0, backend.UnmountCalls);
        Assert.True(backend.ProbeDeviceCalls > 0);
    }

    [Fact]
    public async Task LegacyRefreshWithClear_UsesDurableExactMountOperation()
    {
        var backend = new RecordingBackend();
        await using var fixture = CreateFixture(backend);
        ControlOperationRequestPayload? captured = null;
        fixture.SetExecutor((request, _) =>
        {
            captured = request;
            return Task.FromResult(Success(request));
        });
        var timestamp = DateTime.UtcNow;
        var request = PipeMessageCodec.Create(
            ApfsMessageTypes.RefreshRequested,
            new RefreshRequestedPayload(
                "legacy-tray",
                timestamp,
                ClearUserEjectedVolumes: true,
                VolumeId),
            Guid.NewGuid().ToString("N"));

        var ack = ReadAck(await ExchangeAsync(fixture.Service, request, TestTimeout));

        Assert.True(ack.Success, ack.Message);
        Assert.Equal(ApfsControlCommands.Mount, captured!.Command);
        Assert.Equal(ApfsControlModes.ReadWrite, captured.RequestedMode);
        Assert.Equal(
            new ApfsControlTarget(
                DeviceId.ToLowerInvariant(),
                VolumeId.ToLowerInvariant(),
                RecoveryIdentity),
            captured.Target);
        Assert.Equal(timestamp.AddMinutes(2), captured.ExpiresAtUtc);
        Assert.Equal(1, fixture.ExecutorCalls);
        Assert.Equal(0, backend.MountCalls);
    }

    [Fact]
    public async Task LegacyQuit_StopsOnlyAfterSuccessfulTerminalEvidenceAndNotification()
    {
        var backend = new RecordingBackend(startMounted: true);
        var requestId = Guid.NewGuid().ToString("N");
        var operationId = Guid.Parse(requestId).ToString("D").ToLowerInvariant();
        string? evidencePath = null;
        await using var fixture = CreateFixture(
            backend,
            stopProbe: () => evidencePath is not null && File.Exists(evidencePath));
        fixture.SetExecutor((request, _) => Task.FromResult(Success(request)));
        evidencePath = Path.Combine(fixture.EvidenceRoot, $"{operationId}.json");
        var request = LegacyRequest(
            ApfsMessageTypes.QuitRequested,
            requestId,
            DateTime.UtcNow,
            volumeId: null);

        var responses = await ExchangeUntilStopAsync(
            fixture.Service,
            request,
            TestTimeout);

        Assert.Equal(ApfsMessageTypes.Ack, responses[0].Type);
        Assert.Equal(ApfsMessageTypes.ServiceStopping, responses[1].Type);
        Assert.True(ReadAck(responses[0]).Success);
        Assert.True(fixture.Lifetime.WasStopped);
        Assert.True(fixture.Lifetime.StopProbePassed);
        Assert.Equal(0, backend.UnmountCalls);
    }

    [Fact]
    public async Task LegacyQuit_FailedTerminalShutdownEvidenceStillStopsAfterFailureAck()
    {
        var backend = new RecordingBackend(startMounted: true);
        await using var fixture = CreateFixture(backend);
        fixture.SetExecutor((request, _) => Task.FromResult(Failure(
            request,
            ApfsOperationCodes.UnsafeOwnership,
            "Shutdown proof was incomplete.")));

        var response = await ExchangeAsync(
            fixture.Service,
            LegacyRequest(
                ApfsMessageTypes.QuitRequested,
                Guid.NewGuid().ToString("N"),
                DateTime.UtcNow,
                volumeId: null),
            TestTimeout);

        var ack = ReadAck(response);
        Assert.False(ack.Success);
        Assert.Equal(ApfsOperationCodes.UnsafeOwnership, ack.Code);
        Assert.True(fixture.Lifetime.WasStopped);
        Assert.Equal(0, backend.UnmountCalls);
    }

    private static LegacyFixture CreateFixture(
        RecordingBackend backend,
        Func<bool>? stopProbe = null)
        => new(backend, useRealExecutor: false, stopProbe);

    private static LegacyFixture CreateFixtureWithRealExecutor(RecordingBackend backend)
        => new(backend, useRealExecutor: true, stopProbe: null);

    private static PipeEnvelope LegacyRequest(
        string messageType,
        string requestId,
        DateTime timestampUtc,
        string? volumeId)
    {
        object payload = messageType switch
        {
            ApfsMessageTypes.MountRequested => new MountRequestedPayload("legacy-tray", timestampUtc, volumeId),
            ApfsMessageTypes.FixRequested => new FixRequestedPayload("legacy-tray", timestampUtc, volumeId),
            ApfsMessageTypes.EjectRequested => new EjectRequestedPayload("legacy-tray", timestampUtc, volumeId),
            ApfsMessageTypes.QuitRequested => new QuitRequestedPayload("legacy-tray", timestampUtc),
            _ => throw new ArgumentOutOfRangeException(nameof(messageType)),
        };
        return PipeMessageCodec.Create(messageType, payload, requestId);
    }

    private static string ExpectedCommand(string messageType)
        => messageType switch
        {
            ApfsMessageTypes.MountRequested => ApfsControlCommands.Mount,
            ApfsMessageTypes.FixRequested => ApfsControlCommands.Fix,
            ApfsMessageTypes.EjectRequested => ApfsControlCommands.Eject,
            ApfsMessageTypes.QuitRequested => ApfsControlCommands.Quit,
            _ => throw new ArgumentOutOfRangeException(nameof(messageType)),
        };

    private static AckPayload ReadAck(PipeEnvelope response)
    {
        Assert.Equal(ApfsMessageTypes.Ack, response.Type);
        Assert.Equal(PipeSchemaVersions.Schema1, response.SchemaVersion);
        Assert.True(PipeMessageCodec.TryGetPayload<AckPayload>(response, out var ack));
        return Assert.IsType<AckPayload>(ack);
    }

    private static OperationResultPayload Success(ControlOperationRequestPayload request)
        => TerminalResult(
            request,
            success: true,
            ApfsOperationCodes.OperationSucceeded,
            "Durable operation completed.");

    private static OperationResultPayload Failure(
        ControlOperationRequestPayload request,
        string code,
        string diagnostic)
        => TerminalResult(request, success: false, code, diagnostic);

    private static OperationResultPayload TerminalResult(
        ControlOperationRequestPayload request,
        bool success,
        string code,
        string diagnostic)
    {
        var now = DateTime.UtcNow;
        var quit = request.Command == ApfsControlCommands.Quit;
        return new OperationResultPayload(
            request.OperationId,
            request.Command,
            request.Target,
            Fingerprint: null,
            State: success ? ApfsOperationStates.Succeeded : ApfsOperationStates.Failed,
            Code: code,
            Success: success,
            RequestedAtUtc: now,
            StartedAtUtc: now,
            CompletedAtUtc: now,
            FinalStatus: quit
                ? success ? "shutdown-complete" : "shutdown-incomplete"
                : success ? "mounted" : "failed",
            PendingDurability: quit && !success,
            MountProof: quit ? success ? "no-mounts" : "present" : "present",
            OwnershipProof: quit ? success ? "proven" : "not-proven" : "not-applicable",
            DurabilityProof: quit ? success ? "proven" : "not-proven" : "not-applicable",
            Diagnostic: diagnostic,
            QuitMarkerWritten: quit,
            ExpiresAtUtc: request.ExpiresAtUtc);
    }

    private static VolumeInfo TestVolume(string volumeId, string recoveryIdentity)
        => new(
            volumeId,
            DeviceId,
            Path.GetFileName(volumeId),
            SupportsReadWrite: true,
            SupportsNativeWrite: true,
            NativeWriteReadiness: NativeWriteReadiness.CommitReady,
            RecoveryIdentity: recoveryIdentity);

    private static async Task<PipeEnvelope> ExchangeAsync(
        TrayPipeHostService service,
        PipeEnvelope request,
        TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        await using var pair = await ConnectedPipePair.CreateAsync(cancellation.Token);
        var serverPeer = new PipePeer(pair.Server);
        var clientPeer = new PipePeer(pair.Client);
        var handler = InvokeHandleClient(service, serverPeer, cancellation.Token);
        try
        {
            var initial = await clientPeer.ReadMessageAsync(cancellation.Token);
            Assert.Equal(ApfsMessageTypes.StatusChanged, initial!.Type);
            await clientPeer.SendAsync(request, cancellation.Token);
            return (await clientPeer.ReadMessageAsync(cancellation.Token))!;
        }
        finally
        {
            await clientPeer.DisposeAsync();
            await handler.WaitAsync(cancellation.Token);
            await serverPeer.DisposeAsync();
        }
    }

    private static async Task<IReadOnlyList<PipeEnvelope>> ExchangeUntilStopAsync(
        TrayPipeHostService service,
        PipeEnvelope request,
        TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        await using var pair = await ConnectedPipePair.CreateAsync(cancellation.Token);
        var serverPeer = new PipePeer(pair.Server);
        var clientPeer = new PipePeer(pair.Client);
        var handler = InvokeHandleClient(service, serverPeer, cancellation.Token);
        try
        {
            _ = await clientPeer.ReadMessageAsync(cancellation.Token);
            await clientPeer.SendAsync(request, cancellation.Token);
            var first = (await clientPeer.ReadMessageAsync(cancellation.Token))!;
            var second = (await clientPeer.ReadMessageAsync(cancellation.Token))!;
            await handler.WaitAsync(cancellation.Token);
            return [first, second];
        }
        finally
        {
            await clientPeer.DisposeAsync();
            await serverPeer.DisposeAsync();
        }
    }

    private static Task InvokeHandleClient(
        TrayPipeHostService service,
        PipePeer peer,
        CancellationToken cancellationToken)
    {
        var method = typeof(TrayPipeHostService).GetMethod(
            "HandleClientAsync",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(method);
        return Assert.IsAssignableFrom<Task>(method!.Invoke(service, [peer, cancellationToken]));
    }

    private sealed class LegacyFixture : IAsyncDisposable
    {
        private readonly ApfsMountWorker _worker;
        private AgentControlOperationService _operationService;
        private Func<ControlOperationRequestPayload, CancellationToken, Task<OperationResultPayload>> _executor;
        private readonly string? _previousRuntimeRoot;
        private int _executorCalls;

        public LegacyFixture(
            RecordingBackend backend,
            bool useRealExecutor,
            Func<bool>? stopProbe)
        {
            Directory.CreateDirectory(EvidenceBase);
            EvidenceRoot = Path.Combine(EvidenceBase, Guid.NewGuid().ToString("N"));
            _previousRuntimeRoot = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT");
            Environment.SetEnvironmentVariable(
                "APFSACCESS_RUNTIME_ROOT",
                Path.Combine(EvidenceRoot, "runtime"));
            _worker = new ApfsMountWorker(
                NullLogger<ApfsMountWorker>.Instance,
                backend,
                new AlwaysMountPolicy(),
                new RuntimeStatusPublisher(),
                new FixedOptionsMonitor(new ServiceHostOptions
                {
                    EnableNativeWrite = true,
                    WriteRolloutChannel = "Enabled",
                    WriteBackendMode = "Native",
                    NativeWriteAllowRawPhysicalDevices = true,
                    NativeWritePromotionPolicy = "PilotHardware",
                    ReadWriteMode = "RwWithRoFallback",
                }));
            var realExecutor = new AgentControlCommandExecutor(
                _worker,
                quitMarkerWriter: _ => true);
            _executor = useRealExecutor
                ? realExecutor.ExecuteAsync
                : (_, _) => throw new InvalidOperationException("The test executor was not configured.");
            _operationService = CreateOperationService();
            Lifetime = new RecordingApplicationLifetime(stopProbe);
            Service = new TrayPipeHostService(
                NullLogger<TrayPipeHostService>.Instance,
                new RuntimeStatusPublisher(),
                _worker,
                Lifetime,
                _operationService);
        }

        public string EvidenceRoot { get; }
        public TrayPipeHostService Service { get; private set; }
        public RecordingApplicationLifetime Lifetime { get; }
        public int ExecutorCalls => Volatile.Read(ref _executorCalls);

        public void SetExecutor(
            Func<ControlOperationRequestPayload, CancellationToken, Task<OperationResultPayload>> executor)
        {
            _operationService.StopAsync(CancellationToken.None).GetAwaiter().GetResult();
            TryDelete(EvidenceRoot);
            _executor = executor;
            _operationService = CreateOperationService();
            Service = new TrayPipeHostService(
                NullLogger<TrayPipeHostService>.Instance,
                new RuntimeStatusPublisher(),
                _worker,
                Lifetime,
                _operationService);
        }

        public async ValueTask DisposeAsync()
        {
            await _operationService.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
            _worker.Dispose();
            Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", _previousRuntimeRoot);
            TryDelete(EvidenceRoot);
        }

        private AgentControlOperationService CreateOperationService()
            => new(
                async (request, cancellationToken) =>
                {
                    Interlocked.Increment(ref _executorCalls);
                    return await _executor(request, cancellationToken);
                },
                EvidenceRoot);
    }

    private sealed class RecordingBackend : IApfsBackend
    {
        private readonly IReadOnlyList<VolumeInfo> _volumes;
        private readonly bool _duplicateDevice;
        private readonly List<MountedVolumeState> _mounts = [];

        public RecordingBackend(
            bool startMounted = false,
            IReadOnlyList<VolumeInfo>? volumes = null,
            bool duplicateDevice = false)
        {
            _volumes = volumes ?? [TestVolume(VolumeId, RecoveryIdentity)];
            _duplicateDevice = duplicateDevice;
            if (startMounted)
            {
                _mounts.Add(Mounted(_volumes[0]));
            }
        }

        public int ProbeDeviceCalls { get; private set; }
        public int MountCalls { get; private set; }
        public int UnmountCalls { get; private set; }

        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
        {
            ProbeDeviceCalls++;
            IReadOnlyList<DeviceInfo> devices = _duplicateDevice
                ?
                [
                    new DeviceInfo(DeviceId, "Test APFS device A", true),
                    new DeviceInfo(DeviceId, "Test APFS device B", true),
                ]
                : [new DeviceInfo(DeviceId, "Test APFS device", true)];
            return Task.FromResult(devices);
        }

        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(
            string deviceId,
            CancellationToken cancellationToken)
            => Task.FromResult(_volumes);

        public Task<MountResult> MountAsync(
            MountRequest request,
            CancellationToken cancellationToken)
        {
            MountCalls++;
            var volume = _volumes.Single(item => item.VolumeId == request.VolumeId);
            var mounted = Mounted(volume, request.AccessMode);
            _mounts.RemoveAll(item => item.VolumeId == request.VolumeId);
            _mounts.Add(mounted);
            return Task.FromResult(new MountResult(
                true,
                mounted.MountPoint,
                null,
                request.AccessMode,
                IsReadOnly: request.AccessMode == MountAccessMode.ReadOnly,
                WriteEnabled: request.AccessMode == MountAccessMode.ReadWrite,
                NativeWriteSafetyState: request.AccessMode == MountAccessMode.ReadWrite
                    ? NativeWriteSafetyState.StableReadWrite
                    : NativeWriteSafetyState.ReadOnlyFallback,
                MountReady: true));
        }

        public Task<UnmountResult> UnmountAsync(
            string mountPoint,
            CancellationToken cancellationToken)
        {
            UnmountCalls++;
            _mounts.RemoveAll(item => string.Equals(item.MountPoint, mountPoint, StringComparison.OrdinalIgnoreCase));
            return Task.FromResult(new UnmountResult(
                true,
                mountPoint,
                null,
                MountRemoved: true,
                HostOwnershipReleased: true,
                PendingDurabilityCleared: true));
        }

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(
            CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<MountedVolumeState>>(_mounts.ToArray());

        private static MountedVolumeState Mounted(
            VolumeInfo volume,
            MountAccessMode mode = MountAccessMode.ReadWrite)
            => new(
                volume.VolumeId,
                "E:\\",
                mode,
                volume.VolumeName,
                volume.DeviceId,
                "Test APFS device",
                RecoveryIdentity: volume.RecoveryIdentity,
                NativeWriteSafetyState: mode == MountAccessMode.ReadWrite
                    ? NativeWriteSafetyState.StableReadWrite
                    : NativeWriteSafetyState.ReadOnlyFallback,
                MountReady: true);
    }

    private sealed class AlwaysMountPolicy : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters) => 'E';
        public bool ShouldAutoMount(VolumeInfo volume) => true;
    }

    private sealed class FixedOptionsMonitor(ServiceHostOptions options) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => options;
        public ServiceHostOptions Get(string? name) => options;
        public IDisposable OnChange(Action<ServiceHostOptions, string> listener) => NoopDisposable.Instance;

        private sealed class NoopDisposable : IDisposable
        {
            public static readonly NoopDisposable Instance = new();
            public void Dispose()
            {
            }
        }
    }

    private sealed class RecordingApplicationLifetime(Func<bool>? stopProbe) : IHostApplicationLifetime
    {
        public bool WasStopped { get; private set; }
        public bool StopProbePassed { get; private set; }
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;

        public void StopApplication()
        {
            StopProbePassed = stopProbe?.Invoke() ?? true;
            WasStopped = true;
        }
    }

    private sealed class ConnectedPipePair : IAsyncDisposable
    {
        private ConnectedPipePair(NamedPipeServerStream server, NamedPipeClientStream client)
        {
            Server = server;
            Client = client;
        }

        public NamedPipeServerStream Server { get; }
        public NamedPipeClientStream Client { get; }

        public static async Task<ConnectedPipePair> CreateAsync(CancellationToken cancellationToken)
        {
            var pipeName = $"ApfsAccess.LegacyRouting.{Guid.NewGuid():N}";
            var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
            var client = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);
            var waitForConnection = server.WaitForConnectionAsync(cancellationToken);
            await client.ConnectAsync(cancellationToken);
            await waitForConnection;
            return new ConnectedPipePair(server, client);
        }

        public async ValueTask DisposeAsync()
        {
            await Client.DisposeAsync();
            await Server.DisposeAsync();
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
    }
}
