using System.Globalization;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using ApfsAccess.Cli;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class CliSchema2ContractTests
{
    private const string DeviceId = @"\\.\PhysicalDrive2";
    private const string FirstVolumeId = DeviceId + "|Main";
    private const string SecondVolumeId = DeviceId + "|Data";

    [Fact]
    public async Task MutationUsesSchema2ExactTargetAndCanonicalOperationId()
    {
        var pipeName = NewPipeName("Mutation");
        var suppliedId = "{01234567-89AB-CDEF-0123-456789ABCDEF}";
        var canonicalId = "01234567-89ab-cdef-0123-456789abcdef";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(pipeName, async (peer, cancellationToken) =>
        {
            var request = await ReadMessageAsync(peer, cancellationToken);
            Assert.Equal(PipeSchemaVersions.Schema2, request.SchemaVersion);
            Assert.Equal(ApfsMessageTypes.ControlOperationRequest, request.Type);
            Assert.Equal(canonicalId, request.RequestId);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var payload));
            Assert.NotNull(payload);
            Assert.Equal(canonicalId, payload!.OperationId);
            Assert.Equal(ApfsControlCommands.Mount, payload.Command);
            Assert.Equal(DeviceId, payload.Target!.DeviceId);
            Assert.Equal(FirstVolumeId, payload.Target.VolumeId);
            Assert.Equal("Opaque-MixedCase", payload.Target.RecoveryIdentity);
            Assert.Equal(ApfsControlModes.ReadWrite, payload.RequestedMode);
            Assert.NotNull(payload.ExpiresAtUtc);
            Assert.Equal(DateTimeKind.Utc, payload.ExpiresAtUtc!.Value.Kind);
            Assert.InRange(payload.ExpiresAtUtc.Value, DateTime.UtcNow, DateTime.UtcNow.AddSeconds(3));

            await SendResultAsync(peer, payload.OperationId, payload.Command, payload.Target, ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true, cancellationToken, expiresAtUtc: payload.ExpiresAtUtc);
        }, serverCancellation.Token);

        var result = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", FirstVolumeId,
            "--recovery-identity", "Opaque-MixedCase",
            "--operation-id", suppliedId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(canonicalId, json.RootElement.GetProperty("operationId").GetString());
        Assert.Equal(2, json.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.True(json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("succeeded", json.RootElement.GetProperty("operationState").GetString());
        Assert.Equal(DateTimeKind.Utc, json.RootElement.GetProperty("expiresAtUtc").GetDateTime().Kind);
    }

    [Theory]
    [InlineData(ApfsControlCommands.Fix, "healthy-rw", "present", "not-applicable", "not-applicable")]
    [InlineData(ApfsControlCommands.Eject, "absent", "absent", "proven", "proven")]
    public async Task PublicFixAndEjectRequireCommandSpecificTerminalSuccess(
        string command,
        string finalStatus,
        string mountProof,
        string ownershipProof,
        string durabilityProof)
    {
        var pipeName = NewPipeName(command);
        var operationId = "01234567-89ab-cdef-0123-456789abcdef";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(pipeName, async (peer, cancellationToken) =>
        {
            var request = await ReadMessageAsync(peer, cancellationToken);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var payload));
            Assert.NotNull(payload);
            Assert.Equal(command, payload!.Command);
            Assert.Equal(DeviceId, payload.Target!.DeviceId);
            Assert.Equal(FirstVolumeId, payload.Target.VolumeId);
            await SendResultAsync(
                peer,
                payload.OperationId,
                payload.Command,
                payload.Target,
                ApfsOperationStates.Succeeded,
                ApfsOperationCodes.OperationSucceeded,
                success: true,
                cancellationToken,
                expiresAtUtc: payload.ExpiresAtUtc);
        }, serverCancellation.Token);

        var result = await InvokeAsync(
            command,
            "--device-id", DeviceId,
            "--volume-id", FirstVolumeId,
            "--operation-id", operationId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var root = json.RootElement;
        Assert.True(root.GetProperty("success").GetBoolean());
        Assert.Equal(command, root.GetProperty("command").GetString());
        Assert.Equal(ApfsOperationStates.Succeeded, root.GetProperty("operationState").GetString());
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, root.GetProperty("resultCode").GetString());
        Assert.Equal(finalStatus, root.GetProperty("finalStatus").GetString());
        Assert.Equal(mountProof, root.GetProperty("mountProof").GetString());
        Assert.Equal(ownershipProof, root.GetProperty("ownershipProof").GetString());
        Assert.Equal(durabilityProof, root.GetProperty("durabilityProof").GetString());
        Assert.False(root.GetProperty("pendingDurability").GetBoolean());
        if (command == ApfsControlCommands.Fix)
        {
            Assert.Equal(ApfsControlModes.ReadWrite, root.GetProperty("effectiveMode").GetString());
            Assert.False(root.GetProperty("recoveryActive").GetBoolean());
            Assert.Equal(0, root.GetProperty("dirtyTransactionCount").GetInt32());
        }
    }

    [Theory]
    [InlineData("01234567-89AB-CDEF-0123-456789ABCDEF")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("{01234567-89AB-CDEF-0123-456789ABCDEF}")]
    public async Task EquivalentGuidFormsProduceTheSameCanonicalOperationId(string operationId)
    {
        var pipeName = NewPipeName("CanonicalDryRun");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunDryRunInspectionServerAsync(pipeName, serverCancellation.Token);
        var result = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", FirstVolumeId,
            "--operation-id", operationId,
            "--dry-run",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal("01234567-89ab-cdef-0123-456789abcdef", json.RootElement.GetProperty("operationId").GetString());
        Assert.True(json.RootElement.GetProperty("dryRun").GetBoolean());
        Assert.True(json.RootElement.GetProperty("inspectionOnly").GetBoolean());
    }

    [Fact]
    public async Task OmittedMutationOperationIdIsGeneratedAsLowercaseDFormat()
    {
        var pipeName = NewPipeName("GeneratedDryRun");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunDryRunInspectionServerAsync(pipeName, serverCancellation.Token);
        var result = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", FirstVolumeId,
            "--dry-run",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var operationId = json.RootElement.GetProperty("operationId").GetString();
        Assert.NotNull(operationId);
        Assert.True(Guid.TryParseExact(operationId, "D", out _));
        Assert.Equal(operationId, operationId!.ToLowerInvariant());
    }

    [Theory]
    [InlineData("mount", "--volume-id", FirstVolumeId)]
    [InlineData("mount", "--device-id", DeviceId)]
    [InlineData("mount", "--device-id", DeviceId, "--volume-id", "E:")]
    [InlineData("mount", "--device-id", "E:", "--volume-id", FirstVolumeId)]
    [InlineData("mount", "--device-id", DeviceId, "--volume-id", @"\\.\PhysicalDrive3|Data")]
    public async Task MutationsRejectMissingOrAmbiguousExactTargets(params string[] args)
    {
        var result = await InvokeAsync(args);

        Assert.Equal(2, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(ApfsOperationCodes.InvalidArguments, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Theory]
    [InlineData("--mode", "sideways")]
    [InlineData("--requested-mode", "unknown")]
    public async Task UnknownRequestedModesAreRejectedBeforeConnecting(string option, string value)
    {
        var result = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", FirstVolumeId,
            option, value,
            "--pipe-name", NewPipeName("NoConnect"),
            "--no-start-service");

        Assert.Equal(2, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task QueryAndCancelUseSchema2AndRequireCallerOperationId()
    {
        var operationId = "01234567-89ab-cdef-0123-456789abcdef";
        foreach (var command in new[] { "query", "cancel" })
        {
            var pipeName = NewPipeName(command);
            using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var serverTask = RunSingleServerAsync(pipeName, async (peer, cancellationToken) =>
            {
                var request = await ReadMessageAsync(peer, cancellationToken);
                Assert.Equal(PipeSchemaVersions.Schema2, request.SchemaVersion);
                Assert.Equal(
                    command == "query" ? ApfsMessageTypes.OperationResultQuery : ApfsMessageTypes.CancellationRequest,
                    request.Type);
                Assert.Equal(operationId, request.RequestId);
                OperationResultQueryPayload? queryPayload = null;
                OperationCancellationRequestPayload? cancellationPayload = null;
                if (command == "query")
                {
                    Assert.True(PipeMessageCodec.TryGetPayload(request, out queryPayload));
                }
                else
                {
                    Assert.True(PipeMessageCodec.TryGetPayload(request, out cancellationPayload));
                }

                Assert.Equal(operationId, queryPayload?.OperationId ?? cancellationPayload!.OperationId);

                var state = ApfsOperationStates.InProgress;
                var code = ApfsOperationCodes.OperationInProgress;
                await SendResultAsync(peer, operationId, "mount", new ApfsControlTarget(DeviceId, FirstVolumeId), state, code, false, cancellationToken);
            }, serverCancellation.Token);

            var result = await InvokeAsync(
                command,
                "--operation-id", operationId,
                "--pipe-name", pipeName,
                "--no-start-service",
                "--timeout-ms", "2000");
            await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.NotEqual(0, result.ExitCode);
            using var json = JsonDocument.Parse(result.Output);
            Assert.Equal(operationId, json.RootElement.GetProperty("operationId").GetString());
            Assert.Equal(2, json.RootElement.GetProperty("schemaVersion").GetInt32());
            Assert.True(json.RootElement.GetProperty("pendingDurability").GetBoolean());
            Assert.Equal("not-proven", json.RootElement.GetProperty("finalStatus").GetString());
            Assert.Equal("not-proven", json.RootElement.GetProperty("mountProof").GetString());
            Assert.Equal("not-proven", json.RootElement.GetProperty("ownershipProof").GetString());
            Assert.Equal("not-proven", json.RootElement.GetProperty("durabilityProof").GetString());
            Assert.StartsWith("sha256:", json.RootElement.GetProperty("fingerprint").GetString());
        }

        var missingId = await InvokeAsync("query", "--pipe-name", NewPipeName("MissingId"));
        Assert.Equal(2, missingId.ExitCode);

        var malformedId = await InvokeAsync("cancel", "--operation-id", "not-a-guid");
        Assert.Equal(2, malformedId.ExitCode);
    }

    [Fact]
    public async Task InProgressResultIsReconciledByBoundedReconnectQueryWithoutReissue()
    {
        var pipeName = NewPipeName("Reconnect");
        var operationId = "01234567-89ab-cdef-0123-456789abcdef";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var serverTask = RunReconnectServerAsync(pipeName, operationId, serverCancellation.Token);

        var result = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", FirstVolumeId,
            "--operation-id", operationId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "1000");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(8));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.True(json.RootElement.GetProperty("reconciledByQuery").GetBoolean());
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, json.RootElement.GetProperty("resultCode").GetString());
    }

    [Fact]
    public async Task PartialOrInProgressOperationCannotExitSuccessWhenQueryIsUnavailable()
    {
        var pipeName = NewPipeName("Partial");
        var operationId = "01234567-89ab-cdef-0123-456789abcdef";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(pipeName, async (peer, cancellationToken) =>
        {
            var request = await ReadMessageAsync(peer, cancellationToken);
            Assert.Equal(ApfsMessageTypes.ControlOperationRequest, request.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var payload));
            await SendResultAsync(peer, operationId, payload!.Command, payload.Target, ApfsOperationStates.InProgress, ApfsOperationCodes.OperationInProgress, false, cancellationToken, expiresAtUtc: payload.ExpiresAtUtc);
        }, serverCancellation.Token, keepConnectionOpen: false);

        var result = await InvokeAsync(
            "fix",
            "--device-id", DeviceId,
            "--volume-id", FirstVolumeId,
            "--operation-id", operationId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "500");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.NotEqual(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
        Assert.NotEqual(0, json.RootElement.GetProperty("exitCode").GetInt32());
        Assert.True(json.RootElement.GetProperty("pendingDurability").GetBoolean());
        Assert.Equal("not-proven", json.RootElement.GetProperty("finalStatus").GetString());
        Assert.Equal("not-proven", json.RootElement.GetProperty("mountProof").GetString());
        Assert.Equal("not-proven", json.RootElement.GetProperty("ownershipProof").GetString());
        Assert.Equal("not-proven", json.RootElement.GetProperty("durabilityProof").GetString());
        Assert.StartsWith("sha256:", json.RootElement.GetProperty("fingerprint").GetString());
    }

    [Fact]
    public async Task ReadOnlyFallbackResultReportsEffectiveModeWithoutClaimingReadWrite()
    {
        var pipeName = NewPipeName("ReadOnlyFallback");
        var operationId = "01234567-89ab-cdef-0123-456789abcdef";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(pipeName, async (peer, cancellationToken) =>
        {
            var request = await ReadMessageAsync(peer, cancellationToken);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var payload));
            Assert.Equal(ApfsControlModes.ReadWrite, payload!.RequestedMode);
            await SendResultAsync(
                peer,
                operationId,
                payload.Command,
                payload.Target,
                ApfsOperationStates.Succeeded,
                ApfsOperationCodes.OperationSucceeded,
                true,
                cancellationToken,
                effectiveMode: ApfsControlModes.ReadOnly,
                expiresAtUtc: payload.ExpiresAtUtc);
        }, serverCancellation.Token);

        var result = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", FirstVolumeId,
            "--operation-id", operationId,
            "--mode", ApfsControlModes.ReadWrite,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(5, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(ApfsControlModes.ReadWrite, json.RootElement.GetProperty("requestedMode").GetString());
        Assert.Equal(ApfsControlModes.ReadOnly, json.RootElement.GetProperty("effectiveMode").GetString());
    }

    [Theory]
    [InlineData(ApfsOperationCodes.MissingVolume, 7)]
    [InlineData(ApfsOperationCodes.AlreadyAchieved, 8)]
    [InlineData(ApfsOperationCodes.BlockedRecovery, 9)]
    [InlineData(ApfsOperationCodes.UnsafeOwnership, 10)]
    [InlineData(ApfsOperationCodes.OperationConflict, 11)]
    [InlineData(ApfsOperationCodes.OperationCancelled, 12)]
    [InlineData(ApfsOperationCodes.Timeout, 4)]
    [InlineData(ApfsOperationCodes.OperationFailed, 5)]
    public async Task StableOperationCodesMapToDeterministicExitCodes(string code, int expectedExitCode)
    {
        var pipeName = NewPipeName("Map");
        var operationId = "01234567-89ab-cdef-0123-456789abcdef";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(pipeName, async (peer, cancellationToken) =>
        {
            var request = await ReadMessageAsync(peer, cancellationToken);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var payload));
            var state = code switch
            {
                ApfsOperationCodes.AlreadyAchieved => ApfsOperationStates.Succeeded,
                ApfsOperationCodes.OperationCancelled => ApfsOperationStates.Cancelled,
                _ => ApfsOperationStates.Failed,
            };
            await SendResultAsync(
                peer,
                operationId,
                payload!.Command,
                payload.Target,
                state,
                code,
                code == ApfsOperationCodes.AlreadyAchieved,
                cancellationToken,
                expiresAtUtc: payload.ExpiresAtUtc);
        }, serverCancellation.Token);

        var result = await InvokeAsync(
            "eject",
            "--device-id", DeviceId,
            "--volume-id", FirstVolumeId,
            "--operation-id", operationId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(expectedExitCode, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(code, json.RootElement.GetProperty("resultCode").GetString());
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task ListFiltersByDeviceAndPreservesMultiplePartitions()
    {
        var pipeName = NewPipeName("List");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(pipeName, async (peer, cancellationToken) =>
        {
            var request = await ReadMessageAsync(peer, cancellationToken);
            Assert.Equal(ApfsMessageTypes.InventoryRequested, request.Type);
            var inventory = new InventoryPayload(
                new[]
                {
                    new DeviceInventory(
                        new DeviceInfo(DeviceId, "USB APFS", true),
                        new[]
                        {
                            new VolumeInfo(FirstVolumeId, DeviceId, "Main", true),
                            new VolumeInfo(SecondVolumeId, DeviceId, "Data", true),
                        }),
                    new DeviceInventory(
                        new DeviceInfo(@"\\.\PhysicalDrive3", "Other", true),
                        new[] { new VolumeInfo(@"\\.\PhysicalDrive3|Other", @"\\.\PhysicalDrive3", "Other", true) }),
                },
                DateTime.UtcNow);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory, request.RequestId), cancellationToken);
        }, serverCancellation.Token);

        var result = await InvokeAsync(
            "list",
            "--device-id", DeviceId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var devices = json.RootElement.GetProperty("devices").EnumerateArray().ToArray();
        Assert.Single(devices);
        Assert.Equal(2, devices[0].GetProperty("volumes").GetArrayLength());
    }

    [Fact]
    public async Task ListFiltersByBothExactDeviceAndVolumeIds()
    {
        var pipeName = NewPipeName("ListBoth");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(pipeName, async (peer, cancellationToken) =>
        {
            var request = await ReadMessageAsync(peer, cancellationToken);
            var inventory = new InventoryPayload(
                new[]
                {
                    new DeviceInventory(
                        new DeviceInfo(DeviceId, "USB APFS", true),
                        new[]
                        {
                            new VolumeInfo(FirstVolumeId, DeviceId, "Main", true),
                            new VolumeInfo(SecondVolumeId, DeviceId, "Data", true),
                        }),
                },
                DateTime.UtcNow);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory, request.RequestId), cancellationToken);
        }, serverCancellation.Token);

        var result = await InvokeAsync(
            "list",
            "--device-id", DeviceId,
            "--volume-id", SecondVolumeId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var devices = json.RootElement.GetProperty("devices").EnumerateArray().ToArray();
        Assert.Single(devices);
        var volumes = devices[0].GetProperty("volumes").EnumerateArray().ToArray();
        Assert.Single(volumes);
        Assert.Equal(SecondVolumeId, volumes[0].GetProperty("volumeId").GetString());
    }

    [Fact]
    public async Task StatusFiltersByExactVolumeId()
    {
        var pipeName = NewPipeName("Status");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(pipeName, (_, _) => Task.CompletedTask, serverCancellation.Token,
            mountedVolumes: new[]
            {
                new MountedVolumeDisplay(FirstVolumeId, @"E:\", "Main", DeviceId, "USB APFS", MountAccessMode.ReadWrite),
                new MountedVolumeDisplay(SecondVolumeId, @"F:\", "Data", DeviceId, "USB APFS", MountAccessMode.ReadOnly),
            });

        var result = await InvokeAsync(
            "status",
            "--volume-id", SecondVolumeId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Single(json.RootElement.GetProperty("status").GetProperty("mountedVolumes").EnumerateArray());
        Assert.Equal(SecondVolumeId, json.RootElement.GetProperty("status").GetProperty("mountedVolumes")[0].GetProperty("volumeId").GetString());
    }

    [Fact]
    public async Task MissingExactListTargetUsesMissingVolumeExitCode()
    {
        var pipeName = NewPipeName("MissingTarget");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(pipeName, async (peer, cancellationToken) =>
        {
            var request = await ReadMessageAsync(peer, cancellationToken);
            var inventory = new InventoryPayload(Array.Empty<DeviceInventory>(), DateTime.UtcNow);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory, request.RequestId), cancellationToken);
        }, serverCancellation.Token);

        var result = await InvokeAsync(
            "list",
            "--device-id", DeviceId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(7, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.MissingVolume, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task ServiceUnavailableIsBoundedAndDoesNotAttemptImplicitElevation()
    {
        var pipeName = NewPipeName("Unavailable");
        var result = await InvokeAsync(
            "status",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "250");

        Assert.Equal(3, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, json.RootElement.GetProperty("errorCode").GetString());
        var source = FindRepositoryFile("src", "ApfsAccess.Cli", "Program.cs");
        Assert.DoesNotContain("Verb = \"runas\"", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("UseShellExecute = true", source, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("UseShellExecute = false", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task HelpAndCapabilitiesReportSchema2SurfaceAsJsonByDefault()
    {
        var help = await InvokeAsync("--help");
        Assert.Equal(0, help.ExitCode);
        using var helpJson = JsonDocument.Parse(help.Output);
        Assert.Equal(2, helpJson.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("help", helpJson.RootElement.GetProperty("command").GetString());

        var capabilities = await InvokeAsync("capabilities");
        Assert.Equal(0, capabilities.ExitCode);
        using var json = JsonDocument.Parse(capabilities.Output);
        var commands = json.RootElement.GetProperty("commands").EnumerateArray().Select(static item => item.GetString()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains("query", commands);
        Assert.Contains("cancel", commands);
        Assert.Equal(2, json.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.False(json.RootElement.GetProperty("supportsImplicitElevation").GetBoolean());
    }

    [Fact]
    public async Task HumanOutputIsOptIn()
    {
        var jsonResult = await InvokeAsync("version");
        Assert.StartsWith("{", jsonResult.Output.TrimStart());
        Assert.DoesNotContain("version:", jsonResult.Output, StringComparison.OrdinalIgnoreCase);

        var humanResult = await InvokeAsync("version", "--human");
        Assert.Contains("version:", humanResult.Output, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task RunReconnectServerAsync(string pipeName, string operationId, CancellationToken cancellationToken)
    {
        DateTime? expiresAtUtc;
        await using (var firstServer = CreateServer(pipeName))
        {
            await firstServer.WaitForConnectionAsync(cancellationToken);
            await using var peer = new PipePeer(firstServer);
            await SendInitialStatusAsync(peer, cancellationToken);
            var request = await ReadMessageAsync(peer, cancellationToken);
            Assert.Equal(ApfsMessageTypes.ControlOperationRequest, request.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var payload));
            expiresAtUtc = payload!.ExpiresAtUtc;
            await SendResultAsync(peer, operationId, payload.Command, payload.Target, ApfsOperationStates.InProgress, ApfsOperationCodes.OperationInProgress, false, cancellationToken, expiresAtUtc: expiresAtUtc);
        }

        await using var secondServer = CreateServer(pipeName);
        await secondServer.WaitForConnectionAsync(cancellationToken);
        await using var queryPeer = new PipePeer(secondServer);
        await SendInitialStatusAsync(queryPeer, cancellationToken);
        var query = await ReadMessageAsync(queryPeer, cancellationToken);
        Assert.Equal(ApfsMessageTypes.OperationResultQuery, query.Type);
        Assert.Equal(PipeSchemaVersions.Schema2, query.SchemaVersion);
        Assert.True(PipeMessageCodec.TryGetPayload<OperationResultQueryPayload>(query, out var queryPayload));
        Assert.Equal(operationId, queryPayload!.OperationId);
        await SendResultAsync(queryPeer, operationId, ApfsControlCommands.Mount, new ApfsControlTarget(DeviceId, FirstVolumeId), ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true, cancellationToken, expiresAtUtc: expiresAtUtc);
    }

    private static async Task RunSingleServerAsync(
        string pipeName,
        Func<PipePeer, CancellationToken, Task> handler,
        CancellationToken cancellationToken,
        bool keepConnectionOpen = false,
        IReadOnlyList<MountedVolumeDisplay>? mountedVolumes = null)
    {
        await using var server = CreateServer(pipeName);
        await server.WaitForConnectionAsync(cancellationToken);
        await using var peer = new PipePeer(server);
        await SendInitialStatusAsync(peer, cancellationToken, mountedVolumes);
        await handler(peer, cancellationToken);
        if (keepConnectionOpen)
        {
            await peer.ReadMessageAsync(cancellationToken);
        }
    }

    private static async Task RunDryRunInspectionServerAsync(
        string pipeName,
        CancellationToken cancellationToken)
    {
        await using var server = CreateServer(pipeName);
        await server.WaitForConnectionAsync(cancellationToken);
        await using var peer = new PipePeer(server);
        await SendInitialStatusAsync(peer, cancellationToken);
        var request = await ReadMessageAsync(peer, cancellationToken);
        Assert.Equal(ApfsMessageTypes.InventoryRequested, request.Type);
        var inventory = new InventoryPayload(
            new[]
            {
                new DeviceInventory(
                    new DeviceInfo(DeviceId, "USB APFS", true),
                    new[] { new VolumeInfo(FirstVolumeId, DeviceId, "Main", true) }),
            },
            DateTime.UtcNow);
        await peer.SendAsync(
            PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory, request.RequestId),
            cancellationToken);
        Assert.Null(await peer.ReadMessageAsync(cancellationToken));
    }

    private static NamedPipeServerStream CreateServer(string pipeName)
        => new(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);

    private static async Task SendInitialStatusAsync(
        PipePeer peer,
        CancellationToken cancellationToken,
        IReadOnlyList<MountedVolumeDisplay>? mountedVolumes = null)
    {
        var status = new StatusChangedPayload(
            RuntimeState.MountedRw,
            new[] { @"E:\" },
            null,
            DateTime.UtcNow,
            Array.Empty<string>(),
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes: mountedVolumes,
            WriteBackend: "Native");
        await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status), cancellationToken);
    }

    private static async Task<PipeEnvelope> ReadMessageAsync(PipePeer peer, CancellationToken cancellationToken)
        => (await peer.ReadMessageAsync(cancellationToken)) ?? throw new Xunit.Sdk.XunitException("The fake service received EOF unexpectedly.");

    private static async Task SendResultAsync(
        PipePeer peer,
        string operationId,
        string command,
        ApfsControlTarget? target,
        string state,
        string code,
        bool success,
        CancellationToken cancellationToken,
        string? effectiveMode = null,
        DateTime? expiresAtUtc = null)
    {
        var requestedAt = DateTime.UtcNow;
        var isTerminal = state is ApfsOperationStates.Succeeded or ApfsOperationStates.Failed or ApfsOperationStates.Cancelled;
        var requiresConservativeProof = !isTerminal || code == ApfsOperationCodes.Timeout;
        var requestedMode = command == ApfsControlCommands.Mount ? ApfsControlModes.ReadWrite : null;
        var actualEffectiveMode = effectiveMode ?? (command is ApfsControlCommands.Mount or ApfsControlCommands.Fix
            ? ApfsControlModes.ReadWrite
            : null);
        var finalStatus = success
            ? code == ApfsOperationCodes.AlreadyAchieved ? "absent" : command switch
            {
                ApfsControlCommands.Mount or ApfsControlCommands.Fix => "healthy-rw",
                ApfsControlCommands.Eject => "absent",
                ApfsControlCommands.Quit => "shutdown-complete",
                _ => null,
            }
            : null;
        var mountProof = success
            ? command switch
            {
                ApfsControlCommands.Mount or ApfsControlCommands.Fix => "present",
                ApfsControlCommands.Eject => "absent",
                ApfsControlCommands.Quit => "no-mounts",
                _ => null,
            }
            : null;
        var requiresTerminalReleaseProof =
            (command is ApfsControlCommands.Eject or ApfsControlCommands.Quit) &&
            code != ApfsOperationCodes.AlreadyAchieved;
        var ownershipProof = success
            ? requiresTerminalReleaseProof
                ? "proven"
                : command is ApfsControlCommands.Mount or ApfsControlCommands.Fix ? "not-applicable" : "not-proven"
            : null;
        var durabilityProof = ownershipProof;
        var actualExpiry = expiresAtUtc ?? DateTime.UtcNow.AddMinutes(1);
        var payload = new OperationResultPayload(
            operationId,
            command,
            target,
            Fingerprint: ApfsOperationFingerprint.Compute(command, target, requestedMode, actualExpiry),
            state,
            code,
            success,
            RequestedAtUtc: requestedAt,
            StartedAtUtc: state == ApfsOperationStates.Accepted ? null : requestedAt.AddMilliseconds(1),
            CompletedAtUtc: isTerminal ? requestedAt.AddMilliseconds(2) : null,
            FinalStatus: requiresConservativeProof ? "not-proven" : finalStatus,
            RequestedMode: requestedMode,
            EffectiveMode: actualEffectiveMode,
            RecoveryState: success ? "clean" : requiresConservativeProof ? "not-proven" : null,
            RecoveryActive: false,
            DirtyTransactionCount: 0,
            PendingDurability: requiresConservativeProof,
            MountProof: requiresConservativeProof ? "not-proven" : mountProof,
            OwnershipProof: requiresConservativeProof ? "not-proven" : ownershipProof,
            DurabilityProof: requiresConservativeProof ? "not-proven" : durabilityProof,
            QuitMarkerWritten: success && command == ApfsControlCommands.Quit,
            ExpiresAtUtc: actualExpiry);
        await peer.SendAsync(
            PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, payload, operationId, PipeSchemaVersions.Schema2),
            cancellationToken);
    }

    private static string NewPipeName(string suffix)
        => $"ApfsAccess.Cli.Tests.{suffix}.{Guid.NewGuid():N}";

    private static string FindRepositoryFile(params string[] segments)
    {
        var roots = new[]
        {
            Environment.GetEnvironmentVariable("APFS_ACCESS_REPO_ROOT"),
            Directory.GetCurrentDirectory(),
            AppContext.BaseDirectory
        }
        .Where(static root => !string.IsNullOrWhiteSpace(root))
        .Select(static root => new DirectoryInfo(root!));

        foreach (var root in roots)
        {
            var directory = root;
            while (directory is not null)
            {
                var candidate = Path.Combine(new[] { directory.FullName }.Concat(segments).ToArray());
                if (File.Exists(candidate)) return File.ReadAllText(candidate);
                directory = directory.Parent;
            }
        }

        throw new Xunit.Sdk.XunitException($"Could not locate repository file: {Path.Combine(segments)}");
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
