using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class CliSchema2AdversarialTests
{
    private const string DeviceId = @"\\.\PhysicalDrive2";
    private const string VolumeId = DeviceId + "|Main";
    private const string OtherVolumeId = DeviceId + "|Data";
    private const string OperationId = "01234567-89ab-cdef-0123-456789abcdef";
    private const string OtherOperationId = "11234567-89ab-cdef-0123-456789abcdef";

    [Theory]
    [InlineData("operation-id")]
    [InlineData("command")]
    [InlineData("target")]
    [InlineData("recovery-case")]
    [InlineData("requested-mode")]
    [InlineData("expiry")]
    [InlineData("fingerprint")]
    [InlineData("missing-fingerprint")]
    public async Task MutationRejectsTerminalResultThatDoesNotCorrelateToIssuedRequest(string mismatch)
    {
        var pipeName = NewPipeName("Correlation");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunMutationServerAsync(pipeName, async (peer, request, cancellationToken) =>
        {
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var issued));
            var issuedRequest = issued ?? throw new Xunit.Sdk.XunitException("The control request payload was null.");
            var result = ValidSuccessResult(issuedRequest);
            result = mismatch switch
            {
                "operation-id" => result with { OperationId = OtherOperationId },
                "command" => ValidSuccessResult(issuedRequest with { Command = ApfsControlCommands.Fix, RequestedMode = null }),
                "target" => result with { Target = new ApfsControlTarget(DeviceId, OtherVolumeId, "Opaque-Identity") },
                "recovery-case" => result with { Target = issuedRequest.Target! with { RecoveryIdentity = "opaque-identity" } },
                "requested-mode" => result with
                {
                    RequestedMode = ApfsControlModes.ReadOnly,
                    EffectiveMode = ApfsControlModes.ReadOnly,
                    FinalStatus = "mounted-ro",
                },
                "expiry" => result with
                {
                    ExpiresAtUtc = (issuedRequest.ExpiresAtUtc ?? DateTime.UtcNow).AddSeconds(1),
                },
                "fingerprint" => result with
                {
                    Fingerprint = "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                },
                "missing-fingerprint" => result with { Fingerprint = null },
                _ => throw new ArgumentOutOfRangeException(nameof(mismatch)),
            };
            if (mismatch is not "fingerprint" and not "missing-fingerprint")
            {
                result = result with
                {
                    Fingerprint = ApfsOperationFingerprint.Compute(
                        result.Command,
                        result.Target,
                        result.RequestedMode,
                        result.ExpiresAtUtc!.Value),
                };
            }
            await SendResultAsync(peer, result, result.OperationId, cancellationToken);
        }, serverCancellation.Token);

        var cli = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", VolumeId,
            "--recovery-identity", "Opaque-Identity",
            "--operation-id", OperationId,
            "--mode", ApfsControlModes.ReadWrite,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(5, cli.ExitCode);
        using var json = JsonDocument.Parse(cli.Output);
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
    }

    [Theory]
    [InlineData("failed-ok")]
    [InlineData("succeeded-false")]
    [InlineData("read-only-fallback")]
    [InlineData("pending-durability")]
    [InlineData("missing-mount-proof")]
    public async Task MutationNeverSucceedsForContradictoryOrUnprovenTerminalResult(string contradiction)
    {
        var pipeName = NewPipeName("Contradiction");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunMutationServerAsync(pipeName, async (peer, request, cancellationToken) =>
        {
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var issued));
            var result = ValidSuccessResult(issued!);
            result = contradiction switch
            {
                "failed-ok" => result with { State = ApfsOperationStates.Failed },
                "succeeded-false" => result with { Success = false },
                "read-only-fallback" => result with { EffectiveMode = ApfsControlModes.ReadOnly, FinalStatus = "mounted-ro" },
                "pending-durability" => result with { PendingDurability = true },
                "missing-mount-proof" => result with { MountProof = null },
                _ => throw new ArgumentOutOfRangeException(nameof(contradiction)),
            };
            await SendResultAsync(peer, result, OperationId, cancellationToken);
        }, serverCancellation.Token);

        var cli = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", VolumeId,
            "--operation-id", OperationId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(5, cli.ExitCode);
        using var json = JsonDocument.Parse(cli.Output);
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
    }

    [Theory]
    [InlineData(ApfsControlCommands.Fix, "recovery-active")]
    [InlineData(ApfsControlCommands.Eject, "ownership-not-proven")]
    public async Task FixAndEjectRejectMissingCommandSpecificProof(string command, string contradiction)
    {
        var pipeName = NewPipeName("CommandProof");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunMutationServerAsync(pipeName, async (peer, request, cancellationToken) =>
        {
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var issued));
            var result = ValidSuccessResult(issued!);
            result = contradiction switch
            {
                "recovery-active" => result with { RecoveryActive = true },
                "ownership-not-proven" => result with { OwnershipProof = "not-proven" },
                _ => throw new ArgumentOutOfRangeException(nameof(contradiction)),
            };
            await SendResultAsync(peer, result, OperationId, cancellationToken);
        }, serverCancellation.Token);

        var cli = await InvokeAsync(
            command,
            "--device-id", DeviceId,
            "--volume-id", VolumeId,
            "--operation-id", OperationId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(5, cli.ExitCode);
        using var json = JsonDocument.Parse(cli.Output);
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task RejectedResultRetainsTheCompleteCommandContextShape()
    {
        var pipeName = NewPipeName("RejectedShape");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunMutationServerAsync(pipeName, async (peer, request, cancellationToken) =>
        {
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var issued));
            var rejected = ValidSuccessResult(issued!) with { State = ApfsOperationStates.Failed };
            await SendResultAsync(peer, rejected, OperationId, cancellationToken);
        }, serverCancellation.Token);

        var cli = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", VolumeId,
            "--operation-id", OperationId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(5, cli.ExitCode);
        using var json = JsonDocument.Parse(cli.Output);
        var root = json.RootElement;
        Assert.Equal(JsonValueKind.Object, root.GetProperty("result").ValueKind);
        Assert.Equal(JsonValueKind.Object, root.GetProperty("rejectedResult").ValueKind);
        Assert.Equal(JsonValueKind.Object, root.GetProperty("target").ValueKind);
        Assert.Equal(ApfsOperationStates.Failed, root.GetProperty("operationState").GetString());
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, root.GetProperty("resultCode").GetString());
        Assert.Equal(JsonValueKind.String, root.GetProperty("requestedAtUtc").ValueKind);
        Assert.Equal(JsonValueKind.String, root.GetProperty("startedAtUtc").ValueKind);
        Assert.Equal(JsonValueKind.String, root.GetProperty("completedAtUtc").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("evidencePath").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("diagnostic").ValueKind);
    }

    [Fact]
    public async Task DryRunInspectsExactTargetWithoutIssuingMutationOrClaimingFeasibility()
    {
        var pipeName = NewPipeName("DryRun");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunDryRunServerAsync(pipeName, TargetInventory(), serverCancellation.Token);

        var cli = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", VolumeId,
            "--mode", ApfsControlModes.ReadWrite,
            "--operation-id", OperationId,
            "--dry-run",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, cli.ExitCode);
        using var json = JsonDocument.Parse(cli.Output);
        var root = json.RootElement;
        Assert.True(root.GetProperty("success").GetBoolean());
        Assert.True(root.GetProperty("dryRun").GetBoolean());
        Assert.True(root.GetProperty("inspectionOnly").GetBoolean());
        Assert.False(root.GetProperty("operationIssued").GetBoolean());
        Assert.False(root.GetProperty("operationSucceeded").GetBoolean());
        Assert.Equal("not-evaluated", root.GetProperty("feasibility").GetString());
        Assert.Equal(ApfsControlCommands.Mount, root.GetProperty("wouldIssue").GetProperty("command").GetString());
        Assert.Equal(VolumeId, root.GetProperty("wouldIssue").GetProperty("target").GetProperty("volumeId").GetString());
        Assert.True(root.GetProperty("knownFacts").GetProperty("targetExists").GetBoolean());
        Assert.Equal(ApfsControlModes.ReadOnly, root.GetProperty("knownFacts").GetProperty("effectiveMode").GetString());
    }

    [Fact]
    public async Task DryRunMissingExactTargetReturnsStableMissingVolumeExit()
    {
        var pipeName = NewPipeName("DryRunMissing");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunDryRunServerAsync(
            pipeName,
            new InventoryPayload(Array.Empty<DeviceInventory>(), DateTime.UtcNow),
            serverCancellation.Token);

        var cli = await InvokeAsync(
            "fix",
            "--device-id", DeviceId,
            "--volume-id", VolumeId,
            "--dry-run",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(7, cli.ExitCode);
        using var json = JsonDocument.Parse(cli.Output);
        Assert.Equal(ApfsOperationCodes.MissingVolume, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task DryRunUnavailableServiceReturnsStableServiceUnavailableExit()
    {
        var cli = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", VolumeId,
            "--dry-run",
            "--pipe-name", NewPipeName("Unavailable"),
            "--no-start-service",
            "--timeout-ms", "250");

        Assert.Equal(3, cli.ExitCode);
        using var json = JsonDocument.Parse(cli.Output);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task QuitDryRunInspectsInitialStatusAndSendsNoRequest()
    {
        var pipeName = NewPipeName("QuitDryRun");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunStatusOnlyServerAsync(pipeName, serverCancellation.Token);

        var cli = await InvokeAsync(
            "quit",
            "--dry-run",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, cli.ExitCode);
        using var json = JsonDocument.Parse(cli.Output);
        Assert.True(json.RootElement.GetProperty("inspectionOnly").GetBoolean());
        Assert.False(json.RootElement.GetProperty("operationIssued").GetBoolean());
        Assert.Equal(ApfsControlCommands.Quit, json.RootElement.GetProperty("wouldIssue").GetProperty("command").GetString());
    }

    [Fact]
    public void AutomaticServiceCandidatesIgnoreEnvironmentOverrideAndRemainUnderPackagedBase()
    {
        var original = Environment.GetEnvironmentVariable("APFSACCESS_SERVICE_PATH");
        var baseDirectory = Path.Combine(Path.GetTempPath(), "ApfsAccessTests", "cli-packaged");
        Environment.SetEnvironmentVariable("APFSACCESS_SERVICE_PATH", @"C:\untrusted\anything.exe");
        try
        {
            var method = typeof(Program).GetMethod(
                "GetAutomaticServiceCandidates",
                BindingFlags.Static | BindingFlags.NonPublic);
            Assert.NotNull(method);
            var candidates = Assert.IsAssignableFrom<IReadOnlyList<string>>(
                method!.Invoke(null, new object[] { baseDirectory }));

            Assert.Equal(
                new[]
                {
                    Path.GetFullPath(Path.Combine(baseDirectory, "ApfsAccess.Service.exe")),
                    Path.GetFullPath(Path.Combine(baseDirectory, "service", "ApfsAccess.Service.exe")),
                },
                candidates);
            Assert.All(candidates, path => Assert.Equal("ApfsAccess.Service.exe", Path.GetFileName(path)));
            Assert.DoesNotContain(candidates, path => path.Contains("untrusted", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Environment.SetEnvironmentVariable("APFSACCESS_SERVICE_PATH", original);
        }
    }

    [Fact]
    public void PackagedServiceStartDetachesRedirectedStandardHandles()
    {
        var servicePath = Path.GetFullPath(
            Path.Combine(
                Path.GetTempPath(),
                "ApfsAccessTests",
                "package & redirected",
                "service",
                "ApfsAccess.Service.exe"));
        var method = typeof(Program).GetMethod(
            "BuildServiceStartInfo",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);

        var startInfo = Assert.IsType<ProcessStartInfo>(
            method!.Invoke(null, new object[] { servicePath }));
        Assert.Equal(servicePath, Path.GetFullPath(startInfo.FileName));
        Assert.Equal(Path.GetDirectoryName(servicePath), startInfo.WorkingDirectory);
        Assert.False(startInfo.UseShellExecute);
        Assert.True(startInfo.CreateNoWindow);
        Assert.Empty(startInfo.ArgumentList);
    }

    [Fact]
    public void PackagedServiceLauncherRoutesStandardHandlesToNull()
    {
        var launcherType = typeof(Program).Assembly.GetType("ApfsAccess.Cli.PackagedServiceLauncher");
        Assert.NotNull(launcherType);
        var startMethod = launcherType!.GetMethod(
            "Start",
            BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic,
            null,
            new[] { typeof(ProcessStartInfo) },
            null);
        Assert.NotNull(startMethod);

        var childPath = Path.Combine(AppContext.BaseDirectory, "ApfsAccess.Cli.TestChild.exe");
        Assert.True(File.Exists(childPath), $"The dedicated test child is missing: {childPath}");
        var root = Path.Combine(Path.GetTempPath(), "apfs-cli-launch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var resultPath = Path.Combine(root, "standard-handle.json");
        var startInfo = new ProcessStartInfo(childPath)
        {
            WorkingDirectory = Path.GetDirectoryName(childPath)!,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("--result-path");
        startInfo.ArgumentList.Add(resultPath);
        startInfo.ArgumentList.Add("--sleep-ms");
        startInfo.ArgumentList.Add("2000");

        Process? child = null;
        try
        {
            var processId = Convert.ToInt32(startMethod!.Invoke(null, new object[] { startInfo }), CultureInfo.InvariantCulture);
            child = Process.GetProcessById(processId);
            var childProcessHandle = child.Handle;
            var childStartTimeUtcTicks = child.StartTime.ToUniversalTime().Ticks;
            Assert.True(
                SpinWait.SpinUntil(() => File.Exists(resultPath), TimeSpan.FromSeconds(10)),
                "The isolated child did not publish atomic standard-handle evidence.");
            var childImagePath = Path.GetFullPath(child.MainModule?.FileName
                ?? throw new Xunit.Sdk.XunitException("The isolated child image path was unavailable."));
            Assert.Equal(Path.GetFullPath(childPath), childImagePath);
            Assert.True(child.WaitForExit(5_000), "The isolated standard-handle probe did not exit.");
            Assert.True(child.HasExited, "The isolated standard-handle child still exists after its bounded wait.");
            Assert.True(GetExitCodeProcess(childProcessHandle, out var exitCode), "The isolated child exit code was unavailable.");
            Assert.Equal(0u, exitCode);

            using var evidence = JsonDocument.Parse(File.ReadAllText(resultPath));
            var rootElement = evidence.RootElement;
            Assert.Equal(1, rootElement.GetProperty("schemaVersion").GetInt32());
            Assert.Equal(processId, rootElement.GetProperty("processId").GetInt32());
            Assert.Equal(
                childStartTimeUtcTicks,
                rootElement.GetProperty("processStartTimeUtcTicks").GetInt64());
            Assert.Equal(childImagePath, rootElement.GetProperty("imagePath").GetString());
            Assert.NotEqual(-1L, rootElement.GetProperty("standardOutputHandleValue").GetInt64());
            Assert.Equal(2u, rootElement.GetProperty("standardOutputFileType").GetUInt32());
        }
        finally
        {
            if (child is { HasExited: false })
            {
                child.Kill(entireProcessTree: true);
                Assert.True(child.WaitForExit(5_000), "The isolated standard-handle child could not be terminated.");
            }

            if (child is not null)
            {
                Assert.True(child.HasExited, "The isolated standard-handle child leaked past test cleanup.");
                child.Dispose();
            }

            Assert.Empty(Directory.EnumerateFiles(root, "standard-handle.json.tmp.*"));

            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }

            Assert.False(Directory.Exists(root), "The isolated standard-handle test directory was not deleted.");
        }
    }

    [Fact]
    public async Task ReconnectQueryCannotExtendTheOriginalAbsoluteTimeoutBudget()
    {
        var pipeName = NewPipeName("Deadline");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunDelayedDisconnectServerAsync(pipeName, serverCancellation.Token);
        var stopwatch = Stopwatch.StartNew();

        var cli = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", VolumeId,
            "--operation-id", OperationId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "800");
        stopwatch.Stop();
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(4, cli.ExitCode);
        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromMilliseconds(1200),
            $"CLI exceeded the absolute 800 ms budget by too much: {stopwatch.Elapsed.TotalMilliseconds:0} ms.");
        using var json = JsonDocument.Parse(cli.Output);
        Assert.True(json.RootElement.GetProperty("pendingDurability").GetBoolean());
        Assert.Equal("not-proven", json.RootElement.GetProperty("finalStatus").GetString());
        Assert.Equal("not-proven", json.RootElement.GetProperty("mountProof").GetString());
        Assert.Equal("not-proven", json.RootElement.GetProperty("ownershipProof").GetString());
        Assert.Equal("not-proven", json.RootElement.GetProperty("durabilityProof").GetString());
        Assert.StartsWith("sha256:", json.RootElement.GetProperty("fingerprint").GetString());
    }

    [Fact]
    public async Task TimeoutBeforeAnyResultReportsConservativeContextAndFingerprint()
    {
        var pipeName = NewPipeName("NoResult");
        var issued = new TaskCompletionSource<ControlOperationRequestPayload>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunMutationServerAsync(pipeName, async (_, request, cancellationToken) =>
        {
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var payload));
            issued.TrySetResult(payload!);
            await Task.Delay(450, cancellationToken);
        }, serverCancellation.Token);

        var cli = await InvokeAsync(
            "mount",
            "--device-id", DeviceId,
            "--volume-id", VolumeId,
            "--operation-id", OperationId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "300");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(4, cli.ExitCode);
        using var json = JsonDocument.Parse(cli.Output);
        Assert.True(json.RootElement.GetProperty("pendingDurability").GetBoolean());
        Assert.Equal("not-proven", json.RootElement.GetProperty("finalStatus").GetString());
        Assert.Equal("not-proven", json.RootElement.GetProperty("mountProof").GetString());
        Assert.Equal("not-proven", json.RootElement.GetProperty("ownershipProof").GetString());
        Assert.Equal("not-proven", json.RootElement.GetProperty("durabilityProof").GetString());
        Assert.Equal(
            ApfsOperationFingerprint.Compute(await issued.Task.WaitAsync(TimeSpan.FromSeconds(1))),
            json.RootElement.GetProperty("fingerprint").GetString());
        var root = json.RootElement;
        Assert.Equal(JsonValueKind.Null, root.GetProperty("result").ValueKind);
        Assert.Equal(JsonValueKind.Object, root.GetProperty("target").ValueKind);
        Assert.Equal(ApfsOperationStates.InProgress, root.GetProperty("operationState").GetString());
        Assert.Equal(ApfsOperationCodes.Timeout, root.GetProperty("resultCode").GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("requestedAtUtc").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("startedAtUtc").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("completedAtUtc").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("evidencePath").ValueKind);
        Assert.Equal(ApfsControlModes.ReadWrite, root.GetProperty("requestedMode").GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("effectiveMode").ValueKind);
        Assert.Equal("not-proven", root.GetProperty("recoveryState").GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("recoveryActive").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("dirtyTransactionCount").ValueKind);
        Assert.Equal(JsonValueKind.String, root.GetProperty("diagnostic").ValueKind);
    }

    private static async Task RunMutationServerAsync(
        string pipeName,
        Func<PipePeer, PipeEnvelope, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
    {
        await using var server = CreateServer(pipeName);
        await server.WaitForConnectionAsync(cancellationToken);
        await using var peer = new PipePeer(server);
        await SendInitialStatusAsync(peer, cancellationToken);
        var request = await ReadRequiredAsync(peer, cancellationToken);
        Assert.Equal(ApfsMessageTypes.ControlOperationRequest, request.Type);
        await handler(peer, request, cancellationToken);
    }

    private static async Task RunDryRunServerAsync(
        string pipeName,
        InventoryPayload inventory,
        CancellationToken cancellationToken)
    {
        await using var server = CreateServer(pipeName);
        await server.WaitForConnectionAsync(cancellationToken);
        await using var peer = new PipePeer(server);
        await SendInitialStatusAsync(peer, cancellationToken);
        var request = await ReadRequiredAsync(peer, cancellationToken);
        Assert.Equal(ApfsMessageTypes.InventoryRequested, request.Type);
        await peer.SendAsync(
            PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory, request.RequestId),
            cancellationToken);
        Assert.Null(await peer.ReadMessageAsync(cancellationToken));
    }

    private static async Task RunStatusOnlyServerAsync(string pipeName, CancellationToken cancellationToken)
    {
        await using var server = CreateServer(pipeName);
        await server.WaitForConnectionAsync(cancellationToken);
        await using var peer = new PipePeer(server);
        await SendInitialStatusAsync(peer, cancellationToken);
        Assert.Null(await peer.ReadMessageAsync(cancellationToken));
    }

    private static async Task RunDelayedDisconnectServerAsync(string pipeName, CancellationToken cancellationToken)
    {
        await using var server = CreateServer(pipeName);
        await server.WaitForConnectionAsync(cancellationToken);
        await using var peer = new PipePeer(server);
        await SendInitialStatusAsync(peer, cancellationToken);
        var request = await ReadRequiredAsync(peer, cancellationToken);
        Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var issued));
        await Task.Delay(650, cancellationToken);
        var requestedAt = DateTime.UtcNow;
        var result = new OperationResultPayload(
            OperationId,
            issued!.Command,
            issued.Target,
            Fingerprint: ApfsOperationFingerprint.Compute(
                issued.Command,
                issued.Target,
                issued.RequestedMode,
                issued.ExpiresAtUtc!.Value),
            State: ApfsOperationStates.InProgress,
            Code: ApfsOperationCodes.OperationInProgress,
            Success: false,
            RequestedAtUtc: requestedAt,
            StartedAtUtc: requestedAt,
            FinalStatus: "not-proven",
            RequestedMode: issued.RequestedMode,
            RecoveryState: "not-proven",
            PendingDurability: true,
            MountProof: "not-proven",
            OwnershipProof: "not-proven",
            DurabilityProof: "not-proven",
            ExpiresAtUtc: issued.ExpiresAtUtc);
        await SendResultAsync(peer, result, OperationId, cancellationToken);
    }

    private static async Task SendInitialStatusAsync(PipePeer peer, CancellationToken cancellationToken)
    {
        var status = new StatusChangedPayload(
            RuntimeState.MountedRo,
            new[] { @"E:\" },
            null,
            DateTime.UtcNow,
            Array.Empty<string>(),
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes: new[]
            {
                new MountedVolumeDisplay(VolumeId, @"E:\", "Main", DeviceId, "USB APFS", MountAccessMode.ReadOnly),
            },
            RecoveryActive: false,
            DirtyTransactionCount: 0);
        await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status), cancellationToken);
    }

    private static InventoryPayload TargetInventory()
        => new(
            new[]
            {
                new DeviceInventory(
                    new DeviceInfo(DeviceId, "USB APFS", true),
                    new[]
                    {
                        new VolumeInfo(
                            VolumeId,
                            DeviceId,
                            "Main",
                            SupportsReadWrite: true,
                            SupportsNativeWrite: true,
                            NativeWriteReadiness: NativeWriteReadiness.CommitReady),
                    }),
            },
            DateTime.UtcNow);

    private static OperationResultPayload ValidSuccessResult(ControlOperationRequestPayload request)
    {
        var requestedAt = DateTime.UtcNow;
        var command = request.Command;
        return new OperationResultPayload(
            request.OperationId,
            command,
            request.Target,
            Fingerprint: ApfsOperationFingerprint.Compute(
                request.Command,
                request.Target,
                request.RequestedMode,
                request.ExpiresAtUtc!.Value),
            State: ApfsOperationStates.Succeeded,
            Code: ApfsOperationCodes.OperationSucceeded,
            Success: true,
            RequestedAtUtc: requestedAt,
            StartedAtUtc: requestedAt.AddMilliseconds(1),
            CompletedAtUtc: requestedAt.AddMilliseconds(2),
            FinalStatus: command == ApfsControlCommands.Eject ? "absent" : "healthy-rw",
            RequestedMode: request.RequestedMode,
            EffectiveMode: command == ApfsControlCommands.Eject ? null : ApfsControlModes.ReadWrite,
            RecoveryState: "clean",
            RecoveryActive: false,
            DirtyTransactionCount: 0,
            PendingDurability: false,
            MountProof: command == ApfsControlCommands.Eject ? "absent" : "present",
            OwnershipProof: command == ApfsControlCommands.Eject ? "proven" : "not-applicable",
            DurabilityProof: command == ApfsControlCommands.Eject ? "proven" : "not-applicable",
            ExpiresAtUtc: request.ExpiresAtUtc);
    }

    private static Task SendResultAsync(
        PipePeer peer,
        OperationResultPayload result,
        string envelopeRequestId,
        CancellationToken cancellationToken)
        => peer.SendAsync(
            PipeMessageCodec.Create(
                ApfsMessageTypes.OperationResult,
                result,
                envelopeRequestId,
                PipeSchemaVersions.Schema2),
            cancellationToken);

    private static NamedPipeServerStream CreateServer(string pipeName)
        => new(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    private static async Task<PipeEnvelope> ReadRequiredAsync(PipePeer peer, CancellationToken cancellationToken)
        => await peer.ReadMessageAsync(cancellationToken)
           ?? throw new Xunit.Sdk.XunitException("The fake service received EOF unexpectedly.");

    private static string NewPipeName(string suffix)
        => $"ApfsAccess.Cli.Adversarial.{suffix}.{Guid.NewGuid():N}";

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
