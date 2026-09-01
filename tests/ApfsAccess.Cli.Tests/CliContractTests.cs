using System.Globalization;
using System.IO.Pipes;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Cli;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class CliContractTests
{
    [Fact]
    public async Task VersionReturnsStructuredSuccessWithOperationId()
    {
        var result = await InvokeAsync("version");

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var root = json.RootElement;
        Assert.True(root.GetProperty("success").GetBoolean());
        Assert.Equal("version", root.GetProperty("command").GetString());
        Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("operationId").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("version").GetString()));
    }

    [Fact]
    public async Task VersionFlagUsesTheSameStructuredContract()
    {
        var result = await InvokeAsync("--version");

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal("version", json.RootElement.GetProperty("command").GetString());
        Assert.Equal(0, json.RootElement.GetProperty("exitCode").GetInt32());
    }

    [Fact]
    public async Task HumanOutputDoesNotLeakAnonymousTypeNames()
    {
        var result = await InvokeAsync("version", "--human");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("version:", result.Output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("AnonymousType", result.Output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RequireAdminUsesStableElevationExitCode()
    {
        var result = await InvokeAsync("status", "--require-admin");

        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var isAdministrator = new System.Security.Principal.WindowsPrincipal(identity)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        if (OperatingSystem.IsWindows() && !isAdministrator)
        {
            Assert.Equal(6, result.ExitCode);
            using var json = JsonDocument.Parse(result.Output);
            Assert.Equal(ApfsOperationCodes.ElevationFailed, json.RootElement.GetProperty("errorCode").GetString());
        }
        else
        {
            Assert.NotEqual(6, result.ExitCode);
        }
    }

    [Fact]
    public async Task DryRunMutationRequiresBoundedServiceInspection()
    {
        var result = await InvokeAsync(
            "mount",
            "--device-id", @"\\.\PhysicalDrive2",
            "--volume-id", @"\\.\PhysicalDrive2|Main",
            "--dry-run",
            "--pipe-name", $"ApfsAccess.Cli.DryRunMissing.{Guid.NewGuid():N}",
            "--no-start-service",
            "--timeout-ms", "1000");

        Assert.Equal(3, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var root = json.RootElement;
        Assert.False(root.GetProperty("success").GetBoolean());
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, root.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task InvalidTimeoutUsesStableArgumentExitCode()
    {
        var result = await InvokeAsync("status", "--timeout-ms", "249");

        Assert.Equal(2, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var root = json.RootElement;
        Assert.False(root.GetProperty("success").GetBoolean());
        Assert.Equal(2, root.GetProperty("exitCode").GetInt32());
        Assert.Contains("at least 250", root.GetProperty("error").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task InvalidMutationArgumentsReportTheRequestedCommand()
    {
        var result = await InvokeAsync(
            "fix",
            "--device-id", @"\\.\PhysicalDrive2");

        Assert.Equal(2, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal("fix", json.RootElement.GetProperty("command").GetString());
        Assert.Equal(ApfsOperationCodes.InvalidArguments, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task MissingServiceUsesBoundedServiceUnavailableExitCode()
    {
        var pipeName = $"ApfsAccess.Cli.Tests.{Guid.NewGuid():N}";
        var started = DateTime.UtcNow;
        var result = await InvokeAsync(
            "status",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "250");
        var elapsed = DateTime.UtcNow - started;

        Assert.Equal(3, result.ExitCode);
        Assert.True(elapsed < TimeSpan.FromSeconds(5), $"CLI took {elapsed.TotalSeconds:0.###} seconds.");
        using var json = JsonDocument.Parse(result.Output);
        var root = json.RootElement;
        Assert.False(root.GetProperty("success").GetBoolean());
        Assert.Equal(3, root.GetProperty("exitCode").GetInt32());
        Assert.Contains("service", root.GetProperty("error").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CapabilitiesAdvertiseTheAgentControlSurface()
    {
        var result = await InvokeAsync("capabilities");

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var commands = json.RootElement.GetProperty("commands").EnumerateArray()
            .Select(static item => item.GetString())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("status", commands);
        Assert.Contains("list", commands);
        Assert.Contains("mount", commands);
        Assert.Contains("fix", commands);
        Assert.Contains("eject", commands);
        Assert.Contains("quit", commands);
        Assert.True(json.RootElement.GetProperty("supportsDryRun").GetBoolean());
        Assert.True(json.RootElement.GetProperty("supportsExplicitElevation").GetBoolean());
        Assert.False(json.RootElement.GetProperty("supportsImplicitElevation").GetBoolean());
        Assert.Equal(2, json.RootElement.GetProperty("elevationResultSchemaVersion").GetInt32());
        Assert.Equal("exact-os-peer-named-pipe", json.RootElement.GetProperty("elevationResultTransport").GetString());
        Assert.Equal("token-specific-job-object", json.RootElement.GetProperty("elevationTreeOwnership").GetString());
    }

    [Fact]
    public async Task QuitReportsSuccessOnlyAfterStoppingSignalAndPipeClosure()
    {
        var pipeName = $"ApfsAccess.Cli.QuitSuccess.{Guid.NewGuid():N}";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunFakeQuitServiceAsync(
            pipeName,
            sendStopping: true,
            holdConnectionAfterAck: false,
            serverCancellation.Token,
            terminalProof: true);

        var result = await InvokeAsync(
            "quit",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var root = json.RootElement;
        Assert.True(root.GetProperty("success").GetBoolean());
        Assert.Equal(ApfsOperationStates.Succeeded, root.GetProperty("operationState").GetString());
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, root.GetProperty("resultCode").GetString());
        Assert.Equal(2, root.GetProperty("schemaVersion").GetInt32());
    }

    [Fact]
    public async Task QuitDoesNotTreatPreShutdownAckAsCompletion()
    {
        var pipeName = $"ApfsAccess.Cli.QuitEarly.{Guid.NewGuid():N}";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunFakeQuitServiceAsync(
            pipeName,
            sendStopping: false,
            holdConnectionAfterAck: false,
            serverCancellation.Token);

        var result = await InvokeAsync(
            "quit",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(4, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var root = json.RootElement;
        Assert.False(root.GetProperty("success").GetBoolean());
        Assert.Equal(ApfsOperationCodes.Timeout, root.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task QuitRejectsStoppingWithoutTerminalCleanupProof()
    {
        var pipeName = $"ApfsAccess.Cli.QuitUnproven.{Guid.NewGuid():N}";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunFakeQuitServiceAsync(
            pipeName,
            sendStopping: true,
            holdConnectionAfterAck: false,
            serverCancellation.Token);

        var result = await InvokeAsync(
            "quit",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(5, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var root = json.RootElement;
        Assert.False(root.GetProperty("success").GetBoolean());
        Assert.Equal(ApfsOperationCodes.OperationFailed, root.GetProperty("resultCode").GetString());
    }

    [Fact]
    public async Task QuitReturnsBoundedTimeoutWhenServiceNeverCompletesShutdown()
    {
        var pipeName = $"ApfsAccess.Cli.QuitTimeout.{Guid.NewGuid():N}";
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunFakeQuitServiceAsync(
            pipeName,
            sendStopping: false,
            holdConnectionAfterAck: true,
            serverCancellation.Token);

        var started = DateTime.UtcNow;
        var result = await InvokeAsync(
            "quit",
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "300");
        var elapsed = DateTime.UtcNow - started;

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(4, result.ExitCode);
        Assert.True(elapsed < TimeSpan.FromSeconds(3), $"CLI took {elapsed.TotalSeconds:0.###} seconds.");
        using var json = JsonDocument.Parse(result.Output);
        var root = json.RootElement;
        Assert.False(root.GetProperty("success").GetBoolean());
        Assert.Equal("timeout", root.GetProperty("errorCode").GetString());
        Assert.True(root.GetProperty("pendingDurability").GetBoolean());
        Assert.Equal("not-proven", root.GetProperty("mountProof").GetString());
        Assert.Equal("not-proven", root.GetProperty("ownershipProof").GetString());
        Assert.Equal("not-proven", root.GetProperty("durabilityProof").GetString());
        Assert.Equal(DateTimeKind.Utc, root.GetProperty("expiresAtUtc").GetDateTime().Kind);
    }

    private static async Task RunFakeQuitServiceAsync(
        string pipeName,
        bool sendStopping,
        bool holdConnectionAfterAck,
        CancellationToken cancellationToken,
        bool terminalProof = false)
    {
        await using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        await server.WaitForConnectionAsync(cancellationToken);
        await using var peer = new PipePeer(server);

        var mountedStatus = new StatusChangedPayload(
            RuntimeState.MountedRw,
            new[] { @"E:\" },
            null,
            DateTime.UtcNow,
            Array.Empty<string>(),
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>());
        await peer.SendAsync(
            PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, mountedStatus),
            cancellationToken);

        var request = await peer.ReadMessageAsync(cancellationToken);
        Assert.NotNull(request);
        Assert.Equal(ApfsMessageTypes.ControlOperationRequest, request!.Type);
        Assert.Equal(PipeSchemaVersions.Schema2, request.SchemaVersion);
        Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var control));
        Assert.NotNull(control);

        if (sendStopping)
        {
            var state = terminalProof ? ApfsOperationStates.Succeeded : ApfsOperationStates.Failed;
            var code = terminalProof ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.OperationFailed;
            var payload = new OperationResultPayload(
                control!.OperationId,
                control.Command,
                control.Target,
                Fingerprint: ApfsOperationFingerprint.Compute(control),
                state,
                code,
                terminalProof,
                RequestedAtUtc: DateTime.UtcNow,
                StartedAtUtc: DateTime.UtcNow,
                CompletedAtUtc: DateTime.UtcNow,
                FinalStatus: terminalProof ? "shutdown-complete" : state,
                MountProof: terminalProof ? "no-mounts" : null,
                OwnershipProof: terminalProof ? "proven" : null,
                DurabilityProof: terminalProof ? "proven" : null,
                QuitMarkerWritten: terminalProof,
                ExpiresAtUtc: control.ExpiresAtUtc);
            await peer.SendAsync(
                PipeMessageCodec.Create(
                    ApfsMessageTypes.OperationResult,
                    payload,
                    control.OperationId,
                    PipeSchemaVersions.Schema2),
                cancellationToken);
            return;
        }

        if (holdConnectionAfterAck)
        {
            await peer.ReadMessageAsync(cancellationToken);
        }
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
