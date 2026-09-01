using System.Globalization;
using System.IO.Pipes;
using System.Text.Json;
using ApfsAccess.Cli;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class PerVolumeStatusTruthTests
{
    [Fact]
    public async Task StatusExactSelector_UsesSelectedMountInsteadOfServiceAggregate()
    {
        var pipeName = $"ApfsAccess.Cli.PerVolumeStatus.{Guid.NewGuid():N}";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunStatusServerAsync(pipeName, CreateStatus(), serverCancellation.Token);

        var result = await InvokeAsync(
            "status",
            "--device-id", "device-a",
            "--volume-id", "device-a|rw",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var status = json.RootElement.GetProperty("status");
        Assert.Equal("MountedRw", status.GetProperty("state").GetString());
        Assert.True(status.GetProperty("writeEnabled").GetBoolean());
        Assert.Equal("Native", status.GetProperty("writeBackend").GetString());
        Assert.Equal("CanonicalApfsCheckpoint", status.GetProperty("commitModel").GetString());
        Assert.Equal("CommitReady", status.GetProperty("nativeWriteReadiness").GetString());
        Assert.Equal("Transactional", status.GetProperty("nativeWriteEngineState").GetString());
        Assert.Equal("HardwarePilotValidated", status.GetProperty("nativeWriteValidationState").GetString());
        Assert.Equal("StableReadWrite", status.GetProperty("nativeWriteSafetyState").GetString());
        Assert.Equal(1, status.GetProperty("dirtyTransactionCount").GetInt32());
        Assert.True(status.GetProperty("recoveryActive").GetBoolean());
        Assert.Equal("rw-recovery", status.GetProperty("recoveryReason").GetString());
        Assert.Equal("rw-action", status.GetProperty("lastRecoveryAction").GetString());
        Assert.Equal(123UL, status.GetProperty("lastCommitXid").GetUInt64());
        Assert.True(status.GetProperty("shutdownDrainActive").GetBoolean());
        Assert.Equal(2, status.GetProperty("inFlightMutationCallbacks").GetInt32());
        Assert.Equal("rw-incompatibility", status.GetProperty("writeIncompatibilities")[0].GetString());
        Assert.Equal("rw-unsupported", status.GetProperty("writeUnsupportedFeatures")[0].GetString());
        Assert.Equal(7, status.GetProperty("nativeWriteValidationEvidence").GetProperty("crashFaultPasses").GetInt32());
        Assert.Equal("rw-validation", status.GetProperty("nativeWriteDiagnostics")[0].GetProperty("code").GetString());
        Assert.Equal("device-a|rw", status.GetProperty("mountedVolumes")[0].GetProperty("volumeId").GetString());
        Assert.Equal("rw-identity", status.GetProperty("mountedVolumes")[0].GetProperty("recoveryIdentity").GetString());
    }

    [Fact]
    public async Task StatusExactSelector_RejectsMissingMountedMatch()
    {
        var pipeName = $"ApfsAccess.Cli.PerVolumeStatusMissing.{Guid.NewGuid():N}";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunStatusServerAsync(
            pipeName,
            CreateStatus() with { MountedVolumes = Array.Empty<MountedVolumeDisplay>() },
            serverCancellation.Token);

        var result = await InvokeAsync(
            "status",
            "--device-id", "device-a",
            "--volume-id", "device-a|rw",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(7, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.MissingVolume, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task StatusExactSelector_RejectsMultipleMountedMatches()
    {
        var pipeName = $"ApfsAccess.Cli.PerVolumeStatusMultiple.{Guid.NewGuid():N}";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var selected = CreateStatus().MountedVolumes![0];
        var serverTask = RunStatusServerAsync(
            pipeName,
            CreateStatus() with { MountedVolumes = [selected, selected with { MountPoint = "T:\\" }] },
            serverCancellation.Token);

        var result = await InvokeAsync(
            "status",
            "--device-id", "device-a",
            "--volume-id", "device-a|rw",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(5, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.OperationFailed, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task DryRunExactSelector_UsesSelectedInventoryAndMountFacts()
    {
        var pipeName = $"ApfsAccess.Cli.PerVolumeDryRun.{Guid.NewGuid():N}";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunDryRunServerAsync(pipeName, serverCancellation.Token);

        var result = await InvokeAsync(
            "fix",
            "--device-id", "device-a",
            "--volume-id", "device-a|rw",
            "--dry-run",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var facts = json.RootElement.GetProperty("knownFacts");
        Assert.Equal("rw-identity", facts.GetProperty("recoveryIdentity").GetString());
        Assert.True(facts.GetProperty("supportsReadWrite").GetBoolean());
        Assert.True(facts.GetProperty("supportsNativeWrite").GetBoolean());
        Assert.Equal("MountedRw", facts.GetProperty("state").GetString());
        Assert.True(facts.GetProperty("writeEnabled").GetBoolean());
        Assert.Equal("Native", facts.GetProperty("writeBackend").GetString());
        Assert.Equal("CanonicalApfsCheckpoint", facts.GetProperty("commitModel").GetString());
        Assert.Equal("CommitReady", facts.GetProperty("nativeWriteReadiness").GetString());
        Assert.Equal("Transactional", facts.GetProperty("nativeWriteEngineState").GetString());
        Assert.Equal("HardwarePilotValidated", facts.GetProperty("nativeWriteValidationState").GetString());
        Assert.Equal("StableReadWrite", facts.GetProperty("nativeWriteSafetyState").GetString());
        Assert.True(facts.GetProperty("recoveryActive").GetBoolean());
        Assert.Equal("rw-recovery", facts.GetProperty("recoveryReason").GetString());
        Assert.Equal("rw-action", facts.GetProperty("lastRecoveryAction").GetString());
        Assert.Equal(123UL, facts.GetProperty("lastCommitXid").GetUInt64());
        Assert.Equal("rw-incompatibility", facts.GetProperty("writeIncompatibilities")[0].GetString());
        Assert.Equal("rw-unsupported", facts.GetProperty("writeUnsupportedFeatures")[0].GetString());
        Assert.Equal(1, facts.GetProperty("dirtyTransactionCount").GetInt32());
        Assert.True(facts.GetProperty("shutdownDrainActive").GetBoolean());
        Assert.Equal(2, facts.GetProperty("inFlightMutationCallbacks").GetInt32());
        Assert.Equal(7, facts.GetProperty("nativeWriteValidationEvidence").GetProperty("crashFaultPasses").GetInt32());
        Assert.Equal("rw-validation", facts.GetProperty("nativeWriteDiagnostics")[0].GetProperty("code").GetString());
        Assert.True(facts.GetProperty("mountReady").GetBoolean());
        Assert.Equal(4242, facts.GetProperty("hostProcessId").GetInt32());
        Assert.Equal("owned", facts.GetProperty("hostOwnershipState").GetString());
        Assert.Equal(12UL, facts.GetProperty("walAcceptedSequence").GetUInt64());
        Assert.Equal(10UL, facts.GetProperty("walApfsDurableSequence").GetUInt64());
        Assert.Equal(8UL, facts.GetProperty("walCleanupSequence").GetUInt64());
        Assert.True(facts.GetProperty("pendingDurability").GetBoolean());
        Assert.False(facts.TryGetProperty("serviceState", out _));
    }

    private static async Task RunStatusServerAsync(
        string pipeName,
        StatusChangedPayload status,
        CancellationToken cancellationToken)
    {
        await using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        await server.WaitForConnectionAsync(cancellationToken);
        await using var peer = new PipePeer(server);

        await peer.SendAsync(
            PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status),
            cancellationToken);
    }

    private static async Task RunDryRunServerAsync(string pipeName, CancellationToken cancellationToken)
    {
        await using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        await server.WaitForConnectionAsync(cancellationToken);
        await using var peer = new PipePeer(server);

        await peer.SendAsync(
            PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, CreateStatus()),
            cancellationToken);
        var request = await peer.ReadMessageAsync(cancellationToken);
        Assert.NotNull(request);
        Assert.Equal(ApfsMessageTypes.InventoryRequested, request!.Type);
        var inventory = new InventoryPayload(
            [
                new DeviceInventory(
                    new DeviceInfo("device-a", "APFS device", true),
                    [
                        new VolumeInfo(
                            "device-a|rw", "device-a", "Writable", true,
                            SupportsNativeWrite: true,
                            RecoveryIdentity: "rw-identity"),
                        new VolumeInfo(
                            "device-a|ro", "device-a", "Read only", false,
                            SupportsNativeWrite: false,
                            RecoveryIdentity: "ro-identity"),
                    ]),
            ],
            DateTime.UtcNow);
        await peer.SendAsync(
            PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory, request.RequestId),
            cancellationToken);
    }

    private static StatusChangedPayload CreateStatus()
    {
        return new StatusChangedPayload(
            State: RuntimeState.MountedRo,
            MountPoints: ["S:\\", "R:\\"],
            LastError: "aggregate-error",
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["aggregate-warning"],
            WriteEnabled: false,
            CompatibilityWarnings: ["aggregate-compatibility"],
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    "device-a|rw", "R:\\", "Writable", "device-a", "APFS device", MountAccessMode.ReadWrite,
                    RecoveryIdentity: "rw-identity", State: RuntimeState.MountedRw, WriteEnabled: true,
                    WriteBackend: "Native", CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
                    NativeWriteReadiness: NativeWriteReadiness.CommitReady,
                    NativeWriteEngineState: NativeWriteEngineState.Transactional,
                    NativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
                    NativeWriteSafetyState: NativeWriteSafetyState.StableReadWrite,
                    RecoveryActive: true, RecoveryReason: "rw-recovery", LastRecoveryAction: "rw-action",
                    LastCommitXid: 123,
                    WriteIncompatibilities: ["rw-incompatibility"],
                    WriteUnsupportedFeatures: ["rw-unsupported"],
                    DirtyTransactionCount: 1, ShutdownDrainActive: true,
                    InFlightMutationCallbacks: 2, MountReady: true, HostProcessId: 4242,
                    NativeWriteValidationEvidence: new NativeWriteValidationEvidence(CrashFaultPasses: 7),
                    NativeWriteDiagnostics: [new NativeWriteDiagnostic("rw-validation", "rw diagnostic")],
                    WalAcceptedSequence: 12, WalApfsDurableSequence: 10, WalCleanupSequence: 8,
                    PendingDurability: true, HostOwnershipState: "owned"),
                new MountedVolumeDisplay(
                    "device-a|ro", "S:\\", "Read only", "device-a", "APFS device", MountAccessMode.ReadOnly,
                    RecoveryIdentity: "ro-identity", State: RuntimeState.MountedRo, WriteEnabled: false,
                    WriteBackend: "Disabled", CommitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
                    NativeWriteReadiness: NativeWriteReadiness.Unavailable,
                    NativeWriteEngineState: NativeWriteEngineState.Scaffold,
                    NativeWriteValidationState: NativeWriteValidationState.Scaffold,
                    NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
                    RecoveryActive: false, RecoveryReason: "ro-recovery", LastRecoveryAction: "ro-action",
                    LastCommitXid: 456,
                    WriteIncompatibilities: ["ro-incompatibility"],
                    WriteUnsupportedFeatures: ["ro-unsupported"],
                    DirtyTransactionCount: 4, ShutdownDrainActive: false, InFlightMutationCallbacks: 5,
                    NativeWriteValidationEvidence: new NativeWriteValidationEvidence(CrashFaultPasses: 2),
                    NativeWriteDiagnostics: [new NativeWriteDiagnostic("ro-validation", "ro diagnostic")],
                    MountReady: false, HostProcessId: 0,
                    WalAcceptedSequence: 5, WalApfsDurableSequence: 5, WalCleanupSequence: 5,
                    PendingDurability: false, HostOwnershipState: "unknown"),
            ],
            WriteBackend: "Disabled",
            CommitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
            NativeWriteReadiness: NativeWriteReadiness.Unavailable,
            NativeWriteEngineState: NativeWriteEngineState.Scaffold,
            NativeWriteValidationState: NativeWriteValidationState.Scaffold,
            RecoveryActive: false,
            RecoveryReason: "aggregate-recovery",
            LastCommitXid: 999,
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
            WriteIncompatibilities: ["aggregate-incompatibility"],
            WriteUnsupportedFeatures: ["aggregate-unsupported"],
            LastRecoveryAction: "aggregate-action",
            DirtyTransactionCount: 99,
            ShutdownDrainActive: false,
            InFlightMutationCallbacks: 98,
            NativeWriteValidationEvidence: new NativeWriteValidationEvidence(CrashFaultPasses: 99),
            NativeWriteDiagnostics: [new NativeWriteDiagnostic("aggregate-validation", "aggregate diagnostic")]);
    }

    private static async Task<(int ExitCode, string Output)> InvokeAsync(params string[] args)
    {
        var original = Console.Out;
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        Console.SetOut(writer);
        try
        {
            return (await Program.RunForTestAsync(args), writer.ToString());
        }
        finally
        {
            Console.SetOut(original);
        }
    }
}
