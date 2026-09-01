using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal static class Program
{
    private const int Success = 0;
    private const int InvalidArguments = 2;
    private const int ServiceUnavailable = 3;
    private const int Timeout = 4;
    private const int OperationFailed = 5;
    private const int ElevationFailed = 6;
    private const int MissingVolume = 7;
    private const int AlreadyAchieved = 8;
    private const int BlockedRecovery = 9;
    private const int UnsafeOwnership = 10;
    private const int OperationConflict = 11;
    private const int OperationCancelled = 12;

    private static readonly string[] KnownCommands =
    [
        "status", "list", "mount", "fix", "eject", "quit", "query", "cancel",
        "version", "capabilities", "help",
    ];

    private static readonly string[] ReportedCommands =
    [
        "status", "list", "mount", "fix", "eject", "quit", "query", "cancel",
        "version", "capabilities", "supervise-fshost",
    ];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static async Task<int> Main(string[] args)
    {
        WaitForPhysicalValidatorStartupGate();

        if (CliElevation.IsInternalChildInvocation(args))
        {
            return await CliElevation.RunInternalChildAsync(
                args,
                static (publicArguments, operationDeadlineUtc) =>
                    RunWithAuthenticatedOperationDeadlineAsync(
                        publicArguments,
                        operationDeadlineUtc)).ConfigureAwait(false);
        }

        return await MainCoreAsync(
            args,
            operationDeadlineUtc: null,
            allowInProcessTestPipeMutations: false).ConfigureAwait(false);
    }

    private static void WaitForPhysicalValidatorStartupGate()
    {
        var gatePath = Environment.GetEnvironmentVariable("APFSACCESS_VALIDATOR_STARTUP_GATE");
        var gateToken = Environment.GetEnvironmentVariable("APFSACCESS_VALIDATOR_STARTUP_TOKEN");
        if (string.IsNullOrWhiteSpace(gatePath) && string.IsNullOrWhiteSpace(gateToken))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(gatePath) || string.IsNullOrWhiteSpace(gateToken))
        {
            throw new InvalidOperationException("The physical-validator startup gate is incomplete.");
        }

        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                if (File.Exists(gatePath) &&
                    string.Equals(File.ReadAllText(gatePath), gateToken, StringComparison.Ordinal))
                {
                    Environment.SetEnvironmentVariable("APFSACCESS_VALIDATOR_STARTUP_GATE", null);
                    Environment.SetEnvironmentVariable("APFSACCESS_VALIDATOR_STARTUP_TOKEN", null);
                    return;
                }
            }
            catch (IOException)
            {
            }

            Thread.Sleep(25);
        }

        throw new TimeoutException("The physical-validator startup gate was not authorized before its deadline.");
    }

    internal static Task<int> RunWithAuthenticatedOperationDeadlineAsync(
        string[] args,
        DateTimeOffset operationDeadlineUtc)
        => MainCoreAsync(
            args,
            operationDeadlineUtc,
            allowInProcessTestPipeMutations: false);

    internal static Task<int> RunForTestAsync(string[] args)
        => MainCoreAsync(
            args,
            operationDeadlineUtc: null,
            allowInProcessTestPipeMutations: true);

    internal static Task<int> RunForTestWithAuthenticatedOperationDeadlineAsync(
        string[] args,
        DateTimeOffset operationDeadlineUtc)
        => MainCoreAsync(
            args,
            operationDeadlineUtc,
            allowInProcessTestPipeMutations: true);

    private static async Task<int> MainCoreAsync(
        string[] args,
        DateTimeOffset? operationDeadlineUtc,
        bool allowInProcessTestPipeMutations)
    {
        if (args.Length > 0 &&
            string.Equals(args[0], "supervise-fshost", StringComparison.OrdinalIgnoreCase))
        {
            return await FsHostSupervisorCommand.RunAsync(args[1..]).ConfigureAwait(false);
        }

        if (args.Length > 0 &&
            string.Equals(args[0], "quarantine-fshost", StringComparison.OrdinalIgnoreCase))
        {
            return await FsHostSupervisorCommand.RunQuarantineAsync(args[1..]).ConfigureAwait(false);
        }

        CliElevationPublicArguments elevationArguments;
        try
        {
            elevationArguments = CliElevation.ParsePublicArguments(args);
            args = elevationArguments.Arguments;
        }
        catch (CliElevationValidationException ex)
        {
            return EmitFailure(CreateFailureOptions(args), InvalidArguments, ApfsOperationCodes.InvalidArguments, ex.Message);
        }

        CliOptions options;
        try
        {
            options = Parse(args);
            ValidateCustomPipeSecurity(options, elevationArguments, allowInProcessTestPipeMutations);
        }
        catch (CliArgumentException ex)
        {
            return EmitFailure(CreateFailureOptions(args), InvalidArguments, ApfsOperationCodes.InvalidArguments, ex.Message);
        }

        if (elevationArguments.ElevationRequested && !IsAdministrator())
        {
            var elevated = await CliElevation.RunParentAsync(args, options.Timeout).ConfigureAwait(false);
            if (elevated.Stdout is not null)
            {
                Console.Write(elevated.Stdout);
                return elevated.ExitCode;
            }

            return EmitFailure(
                options with { Human = false },
                elevated.ExitCode,
                elevated.ErrorCode ?? ApfsOperationCodes.OperationFailed,
                elevated.Message ?? "Explicit CLI elevation failed.");
        }

        if (operationDeadlineUtc is { } inheritedDeadline && inheritedDeadline <= DateTimeOffset.UtcNow)
        {
            return EmitFailure(
                options with { Human = false },
                Timeout,
                ApfsOperationCodes.Timeout,
                "The authenticated elevated operation deadline expired before command dispatch.");
        }

        if (options.ShowHelp)
        {
            return RunHelp(options);
        }

        if (options.RequireAdministrator && !IsAdministrator())
        {
            return EmitFailure(
                options,
                ElevationFailed,
                ApfsOperationCodes.ElevationFailed,
                "Administrator permission is required by --require-admin.");
        }

        try
        {
            var deadline = CreateOperationDeadline(options.Timeout, operationDeadlineUtc);
            return options.Command switch
            {
                "status" => await RunStatusAsync(options, deadline.Timestamp).ConfigureAwait(false),
                "list" => await RunInventoryAsync(options, deadline.Timestamp).ConfigureAwait(false),
                "mount" or "fix" or "eject" or "quit" => await RunMutationAsync(options, deadline).ConfigureAwait(false),
                "query" => await RunResultRequestAsync(options, cancellation: false, deadline.Timestamp).ConfigureAwait(false),
                "cancel" => await RunResultRequestAsync(options, cancellation: true, deadline.Timestamp).ConfigureAwait(false),
                "version" => RunVersion(options),
                "capabilities" => RunCapabilities(options),
                "help" => RunHelp(options with { ShowHelp = true }),
                _ => EmitFailure(options, InvalidArguments, ApfsOperationCodes.InvalidArguments, $"Unknown command '{options.Command}'."),
            };
        }
        catch (CliException ex)
        {
            return ex.RejectedResult is null
                ? EmitFailure(options, ex.ExitCode, ex.Code, ex.Message)
                : EmitRejectedOperationResult(options, ex);
        }
        catch (OperationCanceledException ex)
        {
            return EmitFailure(options, Timeout, ApfsOperationCodes.Timeout, ex.Message);
        }
        catch (TimeoutException ex)
        {
            return EmitFailure(options, Timeout, ApfsOperationCodes.Timeout, ex.Message);
        }
        catch (UnauthorizedAccessException ex)
        {
            return EmitFailure(options, ElevationFailed, ApfsOperationCodes.ElevationFailed, ex.Message);
        }
        catch (IOException ex)
        {
            return EmitFailure(options, ServiceUnavailable, ApfsOperationCodes.ServiceUnavailable, ex.Message);
        }
        catch (Exception ex)
        {
            return EmitFailure(options, OperationFailed, ApfsOperationCodes.OperationFailed, ex.Message);
        }
    }

    private static int RunVersion(CliOptions options)
    {
        var response = CreateResponse(options, success: true, Success, ApfsOperationCodes.OperationSucceeded, null);
        Add(response, "version", Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0");
        Add(response, "commands", ReportedCommands);
        Add(response, "defaultOutput", "json");
        Add(response, "supportsDryRun", true);
        Add(response, "supportsExactTargets", true);
        Add(response, "supportsCallerOperationIds", true);
        Add(response, "supportsQueryAndCancel", true);
        Add(response, "supportsExplicitElevation", true);
        Add(response, "supportsImplicitElevation", false);
        Add(response, "elevationResultSchemaVersion", CliElevation.ResultSchemaVersion);
        Add(response, "dryRunBehavior", "service-backed-inspection-only");
        return Emit(options, response, Success);
    }

    private static int RunCapabilities(CliOptions options)
    {
        var response = CreateResponse(options, success: true, Success, ApfsOperationCodes.OperationSucceeded, null);
        Add(response, "version", Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0");
        Add(response, "commands", ReportedCommands);
        Add(response, "supportedSchemaVersions", new[] { PipeSchemaVersions.Schema1, PipeSchemaVersions.Schema2 });
        Add(response, "controlMessageTypes", new[]
        {
            ApfsMessageTypes.ControlOperationRequest,
            ApfsMessageTypes.OperationResult,
            ApfsMessageTypes.OperationResultQuery,
            ApfsMessageTypes.CancellationRequest,
        });
        Add(response, "defaultOutput", "json");
        Add(response, "supportsDryRun", true);
        Add(response, "supportsExactTargets", true);
        Add(response, "supportsCallerOperationIds", true);
        Add(response, "supportsReconnectQuery", true);
        Add(response, "supportsExplicitElevation", true);
        Add(response, "supportsImplicitElevation", false);
        Add(response, "elevationResultSchemaVersion", CliElevation.ResultSchemaVersion);
        Add(response, "elevationLaunchIdentity", "canonical-path+length+sha256+file-id");
        Add(response, "elevationResultBinding", "os-peer-pid+token+args-digest+parent+child+package+stdout");
        Add(response, "elevationResultTransport", "exact-os-peer-named-pipe");
        Add(response, "elevationTreeOwnership", "token-specific-job-object");
        Add(response, "dryRunBehavior", "service-backed-inspection-only");
        Add(response, "automaticServiceStartup", "packaged-exe-only");
        Add(response, "pipeName", options.PipeName);
        Add(response, "exitCodes", new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [ApfsOperationCodes.OperationSucceeded] = Success,
            [ApfsOperationCodes.InvalidArguments] = InvalidArguments,
            [ApfsOperationCodes.ServiceUnavailable] = ServiceUnavailable,
            [ApfsOperationCodes.Timeout] = Timeout,
            [ApfsOperationCodes.OperationFailed] = OperationFailed,
            [ApfsOperationCodes.ElevationFailed] = ElevationFailed,
            [ApfsOperationCodes.MissingVolume] = MissingVolume,
            [ApfsOperationCodes.AlreadyAchieved] = AlreadyAchieved,
            [ApfsOperationCodes.BlockedRecovery] = BlockedRecovery,
            [ApfsOperationCodes.UnsafeOwnership] = UnsafeOwnership,
            [ApfsOperationCodes.OperationConflict] = OperationConflict,
            [ApfsOperationCodes.OperationCancelled] = OperationCancelled,
        });
        return Emit(options, response, Success);
    }

    private static int RunHelp(CliOptions options)
    {
        if (options.Human)
        {
            PrintHumanHelp();
            return Success;
        }

        var response = CreateResponse(options, success: true, Success, ApfsOperationCodes.OperationSucceeded, null);
        Add(response, "usage", "ApfsAccess.Cli.exe <command> [options]");
        Add(response, "commands", ReportedCommands);
        Add(response, "options", new[]
        {
            "--device-id ID", "--volume-id ID", "--operation-id GUID", "--recovery-identity VALUE",
            "--mode read-write|read-only", "--timeout-ms N", "--pipe-name NAME", "--dry-run",
            "--no-start-service", "--require-admin", "--elevate", "--human",
        });
        Add(response, "notes", new[]
        {
            "JSON is the default output format.",
            "Mount, fix, and eject require both exact device and volume IDs.",
            "Query and cancel require an existing operation ID.",
            "Dry-run performs bounded service status and inventory inspection without issuing a mutation or claiming feasibility.",
            "--elevate explicitly relaunches only the exact packaged CLI; --require-admin never elevates implicitly.",
            $"Explicit elevation uses result-envelope schema {CliElevation.ResultSchemaVersion}.",
            "Automatic startup considers only packaged ApfsAccess.Service.exe locations and never prompts for elevation.",
        });
        return Emit(options, response, Success);
    }

    private static async Task<int> RunStatusAsync(CliOptions options, long deadlineTimestamp)
    {
        await using var connection = await ConnectAsync(options, deadlineTimestamp: deadlineTimestamp).ConfigureAwait(false);
        var status = FilterStatus(connection.Status, options);
        var response = CreateResponse(options, success: true, Success, ApfsOperationCodes.OperationSucceeded, null);
        Add(response, "status", status);
        return Emit(options, response, Success);
    }

    private static async Task<int> RunInventoryAsync(CliOptions options, long deadlineTimestamp)
    {
        await using var connection = await ConnectAsync(options, deadlineTimestamp: deadlineTimestamp).ConfigureAwait(false);
        var payload = await RequestInventoryAsync(connection, options.OperationId).ConfigureAwait(false);
        var devices = FilterInventory(payload.Devices, options);
        var response = CreateResponse(options, success: true, Success, ApfsOperationCodes.OperationSucceeded, null);
        Add(response, "devices", devices);
        Add(response, "timestampUtc", payload.TimestampUtc);
        return Emit(options, response, Success);
    }

    private static async Task<InventoryPayload> RequestInventoryAsync(
        CliConnection connection,
        string requestId)
    {
        await connection.Peer.SendAsync(
            PipeMessageCodec.Create(
                ApfsMessageTypes.InventoryRequested,
                new { requester = Environment.UserName, timestampUtc = DateTime.UtcNow },
                requestId),
            connection.Token).ConfigureAwait(false);

        while (true)
        {
            var message = await connection.Peer.ReadMessageAsync(connection.Token).ConfigureAwait(false)
                ?? throw new CliException(
                    ServiceUnavailable,
                    ApfsOperationCodes.ServiceUnavailable,
                    "The APFS service closed the pipe before returning inventory.");
            if (!string.Equals(message.Type, ApfsMessageTypes.Inventory, StringComparison.Ordinal) ||
                !string.Equals(message.RequestId, requestId, StringComparison.Ordinal))
            {
                continue;
            }

            if (!PipeMessageCodec.TryGetPayload<InventoryPayload>(message, out var payload) || payload is null)
            {
                throw new CliException(
                    OperationFailed,
                    ApfsOperationCodes.OperationFailed,
                    "The APFS service returned malformed inventory data.");
            }

            return payload;
        }
    }

    private static async Task<int> RunMutationAsync(CliOptions options, OperationDeadline deadline)
    {
        if (options.DryRun)
        {
            return await RunDryRunAsync(options, deadline).ConfigureAwait(false);
        }

        var issuedRequest = CreateControlOperationPayload(options, deadline.ExpiresAtUtc);
        CliConnection? connection = null;
        OperationResultPayload? latest = null;
        OperationWaitException? interruption = null;
        try
        {
            connection = await ConnectAsync(options, deadlineTimestamp: deadline.Timestamp).ConfigureAwait(false);
            var request = CreateControlOperationRequest(issuedRequest);
            await connection.Peer.SendAsync(request, connection.Token).ConfigureAwait(false);
            var result = await WaitForOperationResultAsync(
                connection.Peer,
                options.OperationId,
                issuedRequest,
                connection.Token,
                waitForTerminal: true).ConfigureAwait(false);
            return EmitOperationResult(options, result, reconciledByQuery: false, issuedRequest);
        }
        catch (OperationWaitException ex)
        {
            latest = ex.Latest;
            interruption = ex;
        }
        catch (OperationCanceledException ex)
        {
            interruption = new OperationWaitException(
                "The operation transport timed out before a terminal result was received.",
                latest,
                ex);
        }
        catch (IOException ex)
        {
            interruption = new OperationWaitException(
                "The operation transport disconnected before a terminal result was received.",
                latest,
                ex);
        }
        finally
        {
            if (connection is not null)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }
        }

        return await ReconcileInterruptedMutationAsync(
            options,
            issuedRequest,
            latest,
            interruption,
            deadline.Timestamp).ConfigureAwait(false);
    }

    private static async Task<int> RunResultRequestAsync(CliOptions options, bool cancellation, long deadlineTimestamp)
    {
        await using var connection = await ConnectAsync(options, deadlineTimestamp: deadlineTimestamp).ConfigureAwait(false);
        var messageType = cancellation
            ? ApfsMessageTypes.CancellationRequest
            : ApfsMessageTypes.OperationResultQuery;
        var payload = cancellation
            ? (object)new OperationCancellationRequestPayload(options.OperationId)
            : new OperationResultQueryPayload(options.OperationId);
        await connection.Peer.SendAsync(
            PipeMessageCodec.Create(messageType, payload, options.OperationId, PipeSchemaVersions.Schema2),
            connection.Token).ConfigureAwait(false);

        var result = await WaitForOperationResultAsync(
            connection.Peer,
            options.OperationId,
            expectedRequest: null,
            connection.Token,
            waitForTerminal: false).ConfigureAwait(false);
        return EmitOperationResult(options, result, reconciledByQuery: false, expectedRequest: null);
    }

    private static async Task<int> ReconcileInterruptedMutationAsync(
        CliOptions options,
        ControlOperationRequestPayload issuedRequest,
        OperationResultPayload? latest,
        OperationWaitException? interruption,
        long deadlineTimestamp)
    {
        var reconnectOptions = options with { NoStartService = true };

        try
        {
            await using var connection = await ConnectAsync(
                reconnectOptions,
                allowStartService: false,
                deadlineTimestamp: deadlineTimestamp).ConfigureAwait(false);
            await connection.Peer.SendAsync(
                PipeMessageCodec.Create(
                    ApfsMessageTypes.OperationResultQuery,
                    new OperationResultQueryPayload(options.OperationId),
                    options.OperationId,
                    PipeSchemaVersions.Schema2),
                connection.Token).ConfigureAwait(false);

            var reconciled = await WaitForOperationResultAsync(
                connection.Peer,
                options.OperationId,
                issuedRequest,
                connection.Token,
                waitForTerminal: true).ConfigureAwait(false);
            return EmitOperationResult(options, reconciled, reconciledByQuery: true, issuedRequest);
        }
        catch (OperationWaitException ex)
        {
            latest = ex.Latest ?? latest;
        }
        catch (CliException ex) when (ex.Code == ApfsOperationCodes.ServiceUnavailable)
        {
            // The original operation was already issued. A failed query is
            // reported as incomplete rather than issuing the mutation again.
        }
        catch (OperationCanceledException)
        {
        }
        catch (TimeoutException)
        {
        }
        catch (IOException)
        {
        }

        var diagnostic = interruption?.Message ?? "The operation did not reach a terminal result.";
        var response = CreateResponse(options, success: false, Timeout, ApfsOperationCodes.Timeout, diagnostic);
        Add(response, "resultCode", latest?.Code ?? ApfsOperationCodes.Timeout);
        Add(response, "operationState", latest?.State ?? ApfsOperationStates.InProgress);
        Add(response, "reconciledByQuery", false);
        if (latest is not null)
        {
            AddResultDetails(response, latest);
        }
        else
        {
            Add(response, "result", null);
            Add(response, "target", issuedRequest.Target);
            Add(response, "fingerprint", ApfsOperationFingerprint.Compute(issuedRequest));
            Add(response, "requestedAtUtc", null);
            Add(response, "startedAtUtc", null);
            Add(response, "completedAtUtc", null);
            Add(response, "expiresAtUtc", issuedRequest.ExpiresAtUtc);
            Add(response, "finalStatus", "not-proven");
            Add(response, "evidencePath", null);
            Add(response, "requestedMode", issuedRequest.RequestedMode);
            Add(response, "effectiveMode", null);
            Add(response, "recoveryState", "not-proven");
            Add(response, "recoveryActive", null);
            Add(response, "dirtyTransactionCount", null);
            Add(response, "pendingDurability", true);
            Add(response, "mountProof", "not-proven");
            Add(response, "ownershipProof", "not-proven");
            Add(response, "durabilityProof", "not-proven");
            Add(response, "diagnostic", diagnostic);
        }

        return Emit(options, response, Timeout);
    }

    private static async Task<OperationResultPayload> WaitForOperationResultAsync(
        PipePeer peer,
        string operationId,
        ControlOperationRequestPayload? expectedRequest,
        CancellationToken cancellationToken,
        bool waitForTerminal)
    {
        OperationResultPayload? latest = null;
        try
        {
            while (true)
            {
                var message = await peer.ReadMessageAsync(cancellationToken).ConfigureAwait(false);
                if (message is null)
                {
                    throw new OperationWaitException(
                        "The APFS service disconnected before returning a terminal operation result.",
                        latest);
                }

                if (!string.Equals(message.Type, ApfsMessageTypes.OperationResult, StringComparison.Ordinal))
                {
                    continue;
                }

                if (message.SchemaVersion != PipeSchemaVersions.Schema2 ||
                    !TryReadOperationResultPayload(message, out var result) ||
                    result is null)
                {
                    throw new CliException(OperationFailed, ApfsOperationCodes.OperationFailed, "The APFS service returned an invalid schema-2 operation result.");
                }

                var validation = PipeMessageCodec.Validate(message);
                if (!validation.IsValid)
                {
                    throw new CliException(
                        OperationFailed,
                        ApfsOperationCodes.OperationFailed,
                        validation.Diagnostic ?? "The APFS service returned a contradictory schema-2 operation result.",
                        rejectedResult: result);
                }

                if (!TryValidateResultFingerprint(result, out var fingerprintDiagnostic))
                {
                    throw new CliException(
                        OperationFailed,
                        ApfsOperationCodes.OperationFailed,
                        fingerprintDiagnostic!,
                        rejectedResult: result);
                }

                if (!string.Equals(message.RequestId, operationId, StringComparison.Ordinal) ||
                    !string.Equals(result.OperationId, operationId, StringComparison.Ordinal))
                {
                    throw new CliException(
                        OperationFailed,
                        ApfsOperationCodes.OperationFailed,
                        "The APFS service returned an operation result for a different request identity.");
                }

                if (expectedRequest is not null &&
                    !TryValidateResultCorrelation(expectedRequest, result, out var correlationDiagnostic))
                {
                    throw new CliException(
                        OperationFailed,
                        ApfsOperationCodes.OperationFailed,
                        correlationDiagnostic!);
                }

                latest = result;
                if (!waitForTerminal || IsTerminal(latest))
                {
                    return latest;
                }
            }
        }
        catch (OperationWaitException)
        {
            throw;
        }
        catch (OperationCanceledException ex)
        {
            throw new OperationWaitException(
                "The operation did not reach a terminal result before the bounded wait expired.",
                latest,
                ex);
        }
        catch (IOException ex)
        {
            throw new OperationWaitException(
                "The APFS service disconnected while returning the operation result.",
                latest,
                ex);
        }
    }

    private static int EmitOperationResult(
        CliOptions options,
        OperationResultPayload result,
        bool reconciledByQuery,
        ControlOperationRequestPayload? expectedRequest)
    {
        if (expectedRequest is not null &&
            !TryValidateResultCorrelation(expectedRequest, result, out var correlationDiagnostic))
        {
            throw new CliException(
                OperationFailed,
                ApfsOperationCodes.OperationFailed,
                correlationDiagnostic!);
        }

        var exitCode = ResolveOperationExitCode(result);
        var response = CreateResponse(options, exitCode == Success, exitCode, result.Code, result.Diagnostic);
        AddResultDetails(response, result);
        Add(response, "reconciledByQuery", reconciledByQuery);
        return Emit(options, response, exitCode);
    }

    private static bool TryReadOperationResultPayload(
        PipeEnvelope message,
        out OperationResultPayload? result)
    {
        result = null;
        if (message.Payload is null)
        {
            return false;
        }

        try
        {
            result = message.Payload.Deserialize<OperationResultPayload>(JsonOptions);
            return result is not null;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    private static int EmitRejectedOperationResult(CliOptions options, CliException exception)
    {
        var result = exception.RejectedResult!;
        var response = CreateResponse(
            options,
            success: false,
            exception.ExitCode,
            exception.Code,
            exception.Message);
        Add(response, "error", exception.Message);
        Add(response, "rejectedResult", result);
        AddResultDetails(response, result);
        return Emit(options, response, exception.ExitCode);
    }

    private static async Task<int> RunDryRunAsync(CliOptions options, OperationDeadline deadline)
    {
        await using var connection = await ConnectAsync(
            options,
            deadlineTimestamp: deadline.Timestamp).ConfigureAwait(false);

        DeviceInventory? exactDevice = null;
        VolumeInfo? exactVolume = null;
        InventoryPayload? inventory = null;
        if (options.Command != ApfsControlCommands.Quit)
        {
            inventory = await RequestInventoryAsync(connection, options.OperationId).ConfigureAwait(false);
            var filtered = FilterInventory(inventory.Devices, options);
            if (filtered.Count != 1)
            {
                throw new CliException(
                    OperationFailed,
                    ApfsOperationCodes.OperationFailed,
                    "The exact selector must resolve to one inventory device.");
            }

            exactDevice = filtered[0];
            var exactVolumes = exactDevice.Volumes
                .Where(volume => string.Equals(volume.VolumeId, options.VolumeId, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (exactVolumes.Length != 1)
            {
                throw new CliException(
                    OperationFailed,
                    ApfsOperationCodes.OperationFailed,
                    "The exact selector must resolve to one inventory volume.");
            }

            exactVolume = exactVolumes[0];
        }

        var mountedMatches = connection.Status.MountedVolumes?
            .Where(volume =>
                options.Command != ApfsControlCommands.Quit &&
                string.Equals(volume.DeviceId, options.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(volume.VolumeId, options.VolumeId, StringComparison.OrdinalIgnoreCase))
            .ToArray() ?? Array.Empty<MountedVolumeDisplay>();
        if (mountedMatches.Length > 1)
        {
            throw new CliException(
                OperationFailed,
                ApfsOperationCodes.OperationFailed,
                "The exact selector resolved to more than one mounted volume.");
        }

        var mounted = mountedMatches.SingleOrDefault();
        var wouldIssue = CreateControlOperationPayload(options, deadline.ExpiresAtUtc);
        var response = CreateResponse(
            options,
            success: true,
            Success,
            ApfsOperationCodes.OperationSucceeded,
            "Service inspection completed; no operation was issued.");
        Add(response, "dryRun", true);
        Add(response, "inspectionOnly", true);
        Add(response, "operationIssued", false);
        Add(response, "operationSucceeded", false);
        Add(response, "feasibility", "not-evaluated");
        Add(response, "requestSchemaVersion", PipeSchemaVersions.Schema2);
        Add(response, "requestType", ApfsMessageTypes.ControlOperationRequest);
        Add(response, "wouldIssue", wouldIssue);
        Add(response, "knownFacts", new
        {
            targetExists = options.Command == ApfsControlCommands.Quit || exactVolume is not null,
            mounted = mounted is not null,
            requestedMode = options.RequestedMode,
            effectiveMode = ToControlMode(mounted?.AccessMode),
            supportsReadWrite = exactVolume?.SupportsReadWrite,
            supportsNativeWrite = exactVolume?.SupportsNativeWrite,
            recoveryIdentity = exactVolume?.RecoveryIdentity,
            state = mounted?.State,
            writeEnabled = mounted is null ? (bool?)null : mounted.WriteEnabled,
            writeBackend = mounted?.WriteBackend,
            commitModel = mounted?.CommitModel,
            nativeWriteReadiness = mounted?.NativeWriteReadiness,
            nativeWriteEngineState = mounted?.NativeWriteEngineState,
            nativeWriteValidationState = mounted?.NativeWriteValidationState,
            nativeWriteSafetyState = mounted?.NativeWriteSafetyState,
            recoveryActive = mounted is null ? (bool?)null : mounted.RecoveryActive,
            recoveryReason = mounted?.RecoveryReason,
            lastRecoveryAction = mounted?.LastRecoveryAction,
            lastCommitXid = mounted?.LastCommitXid,
            writeIncompatibilities = mounted?.WriteIncompatibilities,
            writeUnsupportedFeatures = mounted?.WriteUnsupportedFeatures,
            dirtyTransactionCount = mounted?.DirtyTransactionCount,
            shutdownDrainActive = mounted is null ? (bool?)null : mounted.ShutdownDrainActive,
            inFlightMutationCallbacks = mounted?.InFlightMutationCallbacks,
            nativeWriteValidationEvidence = mounted?.NativeWriteValidationEvidence,
            nativeWriteDiagnostics = mounted?.NativeWriteDiagnostics,
            mountReady = mounted is null ? (bool?)null : mounted.MountReady,
            hostProcessId = mounted?.HostProcessId,
            hostOwnershipState = mounted?.HostOwnershipState,
            walAcceptedSequence = mounted?.WalAcceptedSequence,
            walApfsDurableSequence = mounted?.WalApfsDurableSequence,
            walCleanupSequence = mounted?.WalCleanupSequence,
            pendingDurability = mounted is null ? (bool?)null : mounted.PendingDurability,
        });
        Add(response, "inventoryTimestampUtc", inventory?.TimestampUtc);

        return Emit(options, response, Success);
    }

    private static ControlOperationRequestPayload CreateControlOperationPayload(
        CliOptions options,
        DateTime expiresAtUtc)
    {
        var target = options.Command == ApfsControlCommands.Quit
            ? null
            : new ApfsControlTarget(options.DeviceId!, options.VolumeId!, options.RecoveryIdentity);
        return new ControlOperationRequestPayload(
            options.OperationId,
            options.Command,
            target,
            options.Command == ApfsControlCommands.Mount ? options.RequestedMode : null,
            expiresAtUtc);
    }

    private static PipeEnvelope CreateControlOperationRequest(ControlOperationRequestPayload payload)
    {
        return PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest,
            payload,
            payload.OperationId,
            PipeSchemaVersions.Schema2);
    }

    private static bool TryValidateResultCorrelation(
        ControlOperationRequestPayload expected,
        OperationResultPayload actual,
        out string? diagnostic)
    {
        diagnostic = null;
        if (!string.Equals(expected.OperationId, actual.OperationId, StringComparison.Ordinal))
        {
            diagnostic = "The APFS service result operationId does not match the issued request.";
            return false;
        }

        if (!string.Equals(expected.Command, actual.Command, StringComparison.Ordinal))
        {
            diagnostic = "The APFS service result command does not match the issued request.";
            return false;
        }

        if (!TargetsMatch(expected.Target, actual.Target))
        {
            diagnostic = "The APFS service result target does not match the issued exact target.";
            return false;
        }

        if (!string.Equals(expected.RequestedMode, actual.RequestedMode, StringComparison.Ordinal))
        {
            diagnostic = "The APFS service result requestedMode does not match the issued request.";
            return false;
        }

        if (expected.ExpiresAtUtc != actual.ExpiresAtUtc)
        {
            diagnostic = "The APFS service result expiresAtUtc does not match the issued request.";
            return false;
        }

        if (!string.Equals(
                ApfsOperationFingerprint.Compute(expected),
                actual.Fingerprint,
                StringComparison.Ordinal))
        {
            diagnostic = "The APFS service result fingerprint does not match the issued request.";
            return false;
        }

        return true;
    }

    private static bool TryValidateResultFingerprint(
        OperationResultPayload result,
        out string? diagnostic)
    {
        diagnostic = null;
        if (string.Equals(result.Command, ApfsControlCommands.Unknown, StringComparison.Ordinal))
        {
            if (result.Fingerprint is null)
            {
                return true;
            }

            diagnostic = "The APFS service returned a fingerprint for a contextless operation result.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(result.Fingerprint) || !result.ExpiresAtUtc.HasValue)
        {
            diagnostic = "The APFS service returned a contextual operation result without a fingerprint.";
            return false;
        }

        string expected;
        try
        {
            expected = ApfsOperationFingerprint.Compute(
                result.Command,
                result.Target,
                result.RequestedMode,
                result.ExpiresAtUtc.Value);
        }
        catch (ArgumentException exception)
        {
            diagnostic = $"The APFS service result fingerprint context is invalid: {exception.Message}";
            return false;
        }

        if (string.Equals(expected, result.Fingerprint, StringComparison.Ordinal))
        {
            return true;
        }

        diagnostic = "The APFS service result fingerprint does not match its command, target, requestedMode, and expiry.";
        return false;
    }

    private static bool TargetsMatch(ApfsControlTarget? expected, ApfsControlTarget? actual)
    {
        if (expected is null || actual is null)
        {
            return expected is null && actual is null;
        }

        return string.Equals(expected.DeviceId, actual.DeviceId, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(expected.VolumeId, actual.VolumeId, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(expected.RecoveryIdentity, actual.RecoveryIdentity, StringComparison.Ordinal);
    }

    private static int ResolveOperationExitCode(OperationResultPayload result)
    {
        if (!IsTerminal(result))
        {
            return Timeout;
        }

        return result.Code switch
        {
            ApfsOperationCodes.OperationSucceeded when HasVerifiedTerminalSuccess(result) => Success,
            ApfsOperationCodes.OperationSucceeded => OperationFailed,
            ApfsOperationCodes.MissingVolume => MissingVolume,
            ApfsOperationCodes.AlreadyAchieved => AlreadyAchieved,
            ApfsOperationCodes.BlockedRecovery => BlockedRecovery,
            ApfsOperationCodes.UnsafeOwnership => UnsafeOwnership,
            ApfsOperationCodes.Timeout => Timeout,
            ApfsOperationCodes.ElevationFailed => ElevationFailed,
            ApfsOperationCodes.OperationConflict => OperationConflict,
            ApfsOperationCodes.OperationCancelled => OperationCancelled,
            ApfsOperationCodes.InvalidArguments or
                ApfsOperationCodes.InvalidOperationId or
                ApfsOperationCodes.UnknownCommand or
                ApfsOperationCodes.AmbiguousTarget or
                ApfsOperationCodes.MalformedMessage or
                ApfsOperationCodes.UnsupportedSchema or
                ApfsOperationCodes.UnsupportedMessageType => InvalidArguments,
            ApfsOperationCodes.ServiceUnavailable => ServiceUnavailable,
            _ => OperationFailed,
        };
    }

    private static bool HasVerifiedTerminalSuccess(OperationResultPayload result)
    {
        if (result.State != ApfsOperationStates.Succeeded ||
            result.Code != ApfsOperationCodes.OperationSucceeded ||
            !result.Success ||
            result.StartedAtUtc is null ||
            result.CompletedAtUtc is null ||
            result.StartedAtUtc.Value < result.RequestedAtUtc ||
            result.CompletedAtUtc.Value < result.StartedAtUtc.Value ||
            string.IsNullOrWhiteSpace(result.FinalStatus) ||
            result.PendingDurability)
        {
            return false;
        }

        return result.Command switch
        {
            ApfsControlCommands.Mount =>
                result.RequestedMode is ApfsControlModes.ReadOnly or ApfsControlModes.ReadWrite &&
                result.RequestedMode == result.EffectiveMode &&
                result.MountProof == "present" &&
                result.OwnershipProof == "not-applicable" &&
                result.DurabilityProof == "not-applicable",
            ApfsControlCommands.Fix =>
                result.EffectiveMode == ApfsControlModes.ReadWrite &&
                result.FinalStatus == "healthy-rw" &&
                !result.RecoveryActive &&
                result.DirtyTransactionCount == 0 &&
                result.MountProof == "present" &&
                result.OwnershipProof == "not-applicable" &&
                result.DurabilityProof == "not-applicable",
            ApfsControlCommands.Eject =>
                result.FinalStatus == "absent" &&
                result.MountProof == "absent" &&
                result.OwnershipProof == "proven" &&
                result.DurabilityProof == "proven",
            ApfsControlCommands.Quit =>
                result.FinalStatus == "shutdown-complete" &&
                result.MountProof == "no-mounts" &&
                result.OwnershipProof == "proven" &&
                result.DurabilityProof == "proven" &&
                result.QuitMarkerWritten &&
                !result.RecoveryActive &&
                result.DirtyTransactionCount == 0,
            _ => false,
        };
    }

    private static bool IsTerminal(OperationResultPayload result)
        => result.State is ApfsOperationStates.Succeeded or
            ApfsOperationStates.Failed or
            ApfsOperationStates.Cancelled;

    private static async Task<CliConnection> ConnectAsync(
        CliOptions options,
        bool allowStartService = true,
        long? deadlineTimestamp = null)
    {
        var deadline = deadlineTimestamp ?? CreateDeadline(options.Timeout);
        var initialRemaining = GetRemaining(deadline);
        if (initialRemaining <= TimeSpan.Zero)
        {
            throw new CliException(
                ServiceUnavailable,
                ApfsOperationCodes.ServiceUnavailable,
                $"APFS service pipe '{options.PipeName}' is unavailable within {options.Timeout.TotalMilliseconds:0} ms.");
        }

        var timeoutCts = new CancellationTokenSource(initialRemaining);
        PackagedServiceStartup? startup = null;
        try
        {
            Exception? lastError = null;
            var startAttempted = false;

            while (GetRemaining(deadline) > TimeSpan.Zero && !timeoutCts.IsCancellationRequested)
            {
                var remaining = GetRemaining(deadline);
                var remainingMilliseconds = (int)Math.Min(
                    1000,
                    Math.Max(1, Math.Ceiling(remaining.TotalMilliseconds)));
                try
                {
                    var peer = await NamedPipeMessageClient
                        .ConnectAsync(options.PipeName, remainingMilliseconds, timeoutCts.Token)
                        .ConfigureAwait(false);
                    var connection = await ReadInitialStatusAsync(peer, timeoutCts).ConfigureAwait(false);
                    try
                    {
                        startup?.TransferOwnership();
                        startup?.Dispose();
                        startup = null;
                        return connection;
                    }
                    catch
                    {
                        await connection.DisposeAsync().ConfigureAwait(false);
                        throw;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    throw new CliException(
                        ElevationFailed,
                        ApfsOperationCodes.ElevationFailed,
                        $"Access to APFS service pipe '{options.PipeName}' was denied.",
                        ex);
                }
                catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
                {
                    break;
                }
                catch (IOException ex)
                {
                    lastError = ex;
                }
                catch (TimeoutException ex)
                {
                    lastError = ex;
                }
                catch (InvalidOperationException ex)
                {
                    lastError = ex;
                }

                if (allowStartService && !options.NoStartService && !startAttempted)
                {
                    startup = TryStartService();
                    startAttempted = true;
                }

                if (!timeoutCts.IsCancellationRequested)
                {
                    try
                    {
                        await Task.Delay(50, timeoutCts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
                    {
                        break;
                    }
                }
            }

            throw new CliException(
                ServiceUnavailable,
                ApfsOperationCodes.ServiceUnavailable,
                $"APFS service pipe '{options.PipeName}' is unavailable within {options.Timeout.TotalMilliseconds:0} ms.",
                lastError);
        }
        catch (Exception primaryException)
        {
            timeoutCts.Dispose();
            if (startup is not null)
            {
                try
                {
                    startup.Dispose();
                }
                catch (Exception cleanupException)
                {
                    throw new CliElevationUnsafeOwnershipException(
                        "The unready packaged service could not be proven absent.",
                        new AggregateException(primaryException, cleanupException));
                }
            }

            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primaryException).Throw();
            throw;
        }
    }

    private static async Task<CliConnection> ReadInitialStatusAsync(
        PipePeer peer,
        CancellationTokenSource timeoutCts)
    {
        var initial = await peer.ReadMessageAsync(timeoutCts.Token).ConfigureAwait(false);
        if (initial is null)
        {
            await peer.DisposeAsync().ConfigureAwait(false);
            throw new InvalidOperationException("The APFS service closed the pipe before publishing status.");
        }

        if (!string.Equals(initial.Type, ApfsMessageTypes.StatusChanged, StringComparison.OrdinalIgnoreCase) ||
            !PipeMessageCodec.TryGetPayload<StatusChangedPayload>(initial, out var status) ||
            status is null)
        {
            await peer.DisposeAsync().ConfigureAwait(false);
            throw new InvalidOperationException("The APFS service returned malformed initial status.");
        }

        return new CliConnection(peer, status, timeoutCts);
    }

    private static PackagedServiceStartup? TryStartService()
    {
        var servicePath = GetAutomaticServiceCandidates(AppContext.BaseDirectory)
            .FirstOrDefault(File.Exists);
        if (string.IsNullOrWhiteSpace(servicePath))
        {
            return null;
        }

        var startInfo = BuildServiceStartInfo(servicePath);
        try
        {
            return PackagedServiceLauncher.StartOwned(startInfo);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 5)
        {
            throw new CliException(
                ElevationFailed,
                ApfsOperationCodes.ElevationFailed,
                "The APFS service could not be started with the current token.",
                ex);
        }
        catch (Win32Exception ex)
        {
            throw new CliException(
                ServiceUnavailable,
                ApfsOperationCodes.ServiceUnavailable,
                "The APFS service could not be started.",
                ex);
        }

    }

    private static IReadOnlyList<string> GetAutomaticServiceCandidates(string baseDirectory)
    {
        var packagedBase = Path.GetFullPath(baseDirectory);
        return
        [
            Path.GetFullPath(Path.Combine(packagedBase, "ApfsAccess.Service.exe")),
            Path.GetFullPath(Path.Combine(packagedBase, "service", "ApfsAccess.Service.exe")),
        ];
    }

    private static ProcessStartInfo BuildServiceStartInfo(string servicePath)
    {
        if (!string.Equals(
                Path.GetFileName(servicePath),
                "ApfsAccess.Service.exe",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Automatic startup requires the packaged ApfsAccess.Service.exe.", nameof(servicePath));
        }

        var fullServicePath = Path.GetFullPath(servicePath);
        var startInfo = new ProcessStartInfo
        {
            FileName = fullServicePath,
            WorkingDirectory = Path.GetDirectoryName(fullServicePath) ?? AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        return startInfo;
    }

    private static long CreateDeadline(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero)
        {
            return Stopwatch.GetTimestamp();
        }

        var timeoutTicks = (long)Math.Ceiling(timeout.TotalSeconds * Stopwatch.Frequency);
        return checked(Stopwatch.GetTimestamp() + Math.Max(1, timeoutTicks));
    }

    private static OperationDeadline CreateOperationDeadline(
        TimeSpan requestedTimeout,
        DateTimeOffset? inheritedDeadlineUtc)
    {
        var now = DateTimeOffset.UtcNow;
        var expiresAtUtc = inheritedDeadlineUtc?.ToUniversalTime() ?? now.Add(requestedTimeout);
        return new OperationDeadline(
            CreateDeadline(expiresAtUtc - now),
            expiresAtUtc.UtcDateTime);
    }

    private static TimeSpan GetRemaining(long deadlineTimestamp)
    {
        var remainingTicks = deadlineTimestamp - Stopwatch.GetTimestamp();
        return remainingTicks <= 0
            ? TimeSpan.Zero
            : TimeSpan.FromSeconds((double)remainingTicks / Stopwatch.Frequency);
    }

    private readonly record struct OperationDeadline(long Timestamp, DateTime ExpiresAtUtc);

    private static bool IsAdministrator()
        => CliElevation.IsAdministrator();

    private static CliOptions Parse(string[] args)
    {
        if (args.Length == 0)
        {
            return CliOptions.Default with { Command = "status" };
        }

        var command = string.Empty;
        string? deviceId = null;
        string? volumeId = null;
        string? recoveryIdentity = null;
        string? requestedMode = null;
        string? operationIdInput = null;
        var operationIdProvided = false;
        var timeout = TimeSpan.FromSeconds(30);
        var human = false;
        var dryRun = false;
        var noStart = false;
        var requireAdmin = false;
        var pipeName = ApfsPipeConstants.PipeName;
        var showHelp = false;
        var showVersion = false;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var index = 0; index < args.Length; index++)
        {
            var token = args[index];
            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                if (!string.IsNullOrEmpty(command))
                {
                    throw new CliArgumentException("Only one command may be supplied.");
                }

                command = token.ToLowerInvariant();
                continue;
            }

            var normalizedOption = token.ToLowerInvariant() switch
            {
                "-h" => "--help",
                "--requested-mode" => "--mode",
                _ => token.ToLowerInvariant(),
            };
            if (!seen.Add(normalizedOption))
            {
                throw new CliArgumentException($"Option '{token}' may only be supplied once.");
            }

            switch (normalizedOption)
            {
                case "--help":
                    showHelp = true;
                    break;
                case "--version":
                    showVersion = true;
                    break;
                case "--human":
                    human = true;
                    break;
                case "--dry-run":
                    dryRun = true;
                    break;
                case "--no-start-service":
                    noStart = true;
                    break;
                case "--require-admin":
                    requireAdmin = true;
                    break;
                case "--device-id":
                    deviceId = RequireValue(args, ref index, token);
                    break;
                case "--volume-id":
                    volumeId = RequireValue(args, ref index, token);
                    break;
                case "--recovery-identity":
                    recoveryIdentity = RequireValue(args, ref index, token);
                    break;
                case "--operation-id":
                    operationIdInput = RequireValue(args, ref index, token);
                    operationIdProvided = true;
                    break;
                case "--mode":
                    requestedMode = NormalizeRequestedMode(RequireValue(args, ref index, token));
                    break;
                case "--timeout-ms":
                    if (!int.TryParse(RequireValue(args, ref index, token), out var timeoutMs) || timeoutMs < 250)
                    {
                        throw new CliArgumentException("--timeout-ms must be an integer of at least 250.");
                    }

                    timeout = TimeSpan.FromMilliseconds(Math.Min(timeoutMs, 300000));
                    break;
                case "--pipe-name":
                    pipeName = RequireValue(args, ref index, token);
                    if (string.IsNullOrWhiteSpace(pipeName))
                    {
                        throw new CliArgumentException("--pipe-name requires a nonblank value.");
                    }

                    break;
                default:
                    throw new CliArgumentException($"Unknown option '{token}'.");
            }
        }

        if (showHelp && showVersion)
        {
            throw new CliArgumentException("--help and --version cannot be combined.");
        }

        var operationId = operationIdProvided
            ? CanonicalizeOperationId(operationIdInput!)
            : NewOperationId();

        if (showHelp)
        {
            return new CliOptions(
                "help", deviceId, volumeId, recoveryIdentity, requestedMode, timeout, human, dryRun,
                noStart, requireAdmin, pipeName, true, operationId, operationIdProvided);
        }

        if (showVersion)
        {
            if (!string.IsNullOrWhiteSpace(command) && !string.Equals(command, "version", StringComparison.OrdinalIgnoreCase))
            {
                throw new CliArgumentException("--version cannot be combined with another command.");
            }

            command = "version";
        }

        if (string.IsNullOrWhiteSpace(command))
        {
            throw new CliArgumentException("A command is required.");
        }

        if (!KnownCommands.Contains(command, StringComparer.OrdinalIgnoreCase))
        {
            throw new CliArgumentException($"Unknown command '{command}'.");
        }

        if (string.Equals(command, ApfsControlCommands.Mount, StringComparison.OrdinalIgnoreCase) &&
            requestedMode is null)
        {
            requestedMode = ApfsControlModes.ReadWrite;
        }

        var options = new CliOptions(
            command,
            deviceId,
            volumeId,
            recoveryIdentity,
            requestedMode,
            timeout,
            human,
            dryRun,
            noStart,
            requireAdmin,
            pipeName,
            false,
            operationId,
            operationIdProvided);
        ValidateOptions(options);
        return options;
    }

    private static CliOptions CreateFailureOptions(string[] args)
    {
        var command = args.FirstOrDefault(argument =>
            KnownCommands.Contains(argument, StringComparer.OrdinalIgnoreCase));
        if (command is null && args.Contains("--version", StringComparer.OrdinalIgnoreCase))
        {
            command = "version";
        }
        else if (command is null &&
                 (args.Contains("--help", StringComparer.OrdinalIgnoreCase) ||
                  args.Contains("-h", StringComparer.OrdinalIgnoreCase)))
        {
            command = "help";
        }

        return CliOptions.Default with
        {
            Command = command?.ToLowerInvariant() ?? CliOptions.Default.Command,
        };
    }

    private static void ValidateOptions(CliOptions options)
    {
        var hasDevice = !string.IsNullOrWhiteSpace(options.DeviceId);
        var hasVolume = !string.IsNullOrWhiteSpace(options.VolumeId);
        var hasRecoveryIdentity = options.RecoveryIdentity is not null;
        var hasMode = options.RequestedMode is not null;

        if (options.Command is "mount" or "fix" or "eject")
        {
            if (!hasDevice || !hasVolume)
            {
                throw new CliArgumentException("mount, fix, and eject require both --device-id and --volume-id.");
            }

            ValidateExactTarget(options.DeviceId!, options.VolumeId!);
            if (options.Command != ApfsControlCommands.Mount && hasMode)
            {
                throw new CliArgumentException("--mode is only valid for mount.");
            }

            if (hasRecoveryIdentity && string.IsNullOrWhiteSpace(options.RecoveryIdentity))
            {
                throw new CliArgumentException("--recovery-identity requires a nonblank value.");
            }

            return;
        }

        if (options.Command == ApfsControlCommands.Quit)
        {
            if (hasDevice || hasVolume || hasRecoveryIdentity || hasMode)
            {
                throw new CliArgumentException("quit does not accept a target, recovery identity, or requested mode.");
            }

            return;
        }

        if (options.Command is "status" or "list")
        {
            if (options.DryRun || hasRecoveryIdentity || hasMode)
            {
                throw new CliArgumentException("status and list accept only exact device or volume selectors.");
            }

            if (hasDevice && IsDriveLetterPath(options.DeviceId!))
            {
                throw new CliArgumentException("--device-id must be an exact device ID, not a drive-letter path.");
            }

            if (hasVolume && IsDriveLetterPath(options.VolumeId!))
            {
                throw new CliArgumentException("--volume-id must be an exact volume ID, not a drive-letter path.");
            }

            if (hasDevice && hasVolume && !VolumeBelongsToDevice(options.DeviceId!, options.VolumeId!))
            {
                throw new CliArgumentException("--volume-id does not belong to the exact --device-id.");
            }

            return;
        }

        if (options.Command is "query" or "cancel")
        {
            if (!options.OperationIdProvided)
            {
                throw new CliArgumentException($"{options.Command} requires --operation-id.");
            }

            if (hasDevice || hasVolume || hasRecoveryIdentity || hasMode || options.DryRun)
            {
                throw new CliArgumentException($"{options.Command} accepts only --operation-id and connection options.");
            }

            return;
        }

        if ((options.Command is "version" or "capabilities" or "help") &&
            (hasDevice || hasVolume || hasRecoveryIdentity || hasMode || options.DryRun))
        {
            throw new CliArgumentException($"{options.Command} does not accept a target or mutation option.");
        }
    }

    private static void ValidateCustomPipeSecurity(
        CliOptions options,
        CliElevationPublicArguments elevationArguments,
        bool allowInProcessTestPipeMutations)
    {
        if (string.Equals(options.PipeName, ApfsPipeConstants.PipeName, StringComparison.Ordinal))
        {
            return;
        }

        if (allowInProcessTestPipeMutations)
        {
            return;
        }

        if (!options.NoStartService)
        {
            throw new CliArgumentException("A custom --pipe-name requires --no-start-service.");
        }

        if (elevationArguments.ElevationRequested || options.RequireAdministrator)
        {
            throw new CliArgumentException("A custom --pipe-name cannot be combined with --elevate or --require-admin.");
        }

        if (!options.DryRun &&
            options.Command is "mount" or "fix" or "eject" or "quit" or "cancel")
        {
            throw new CliArgumentException("A custom --pipe-name cannot be used for a real mutation.");
        }
    }

    private static void ValidateExactTarget(string deviceId, string volumeId)
    {
        if (string.IsNullOrWhiteSpace(deviceId) || string.IsNullOrWhiteSpace(volumeId))
        {
            throw new CliArgumentException("An exact device ID and volume ID are required.");
        }

        if (IsDriveLetterPath(deviceId) || IsDriveLetterPath(volumeId))
        {
            throw new CliArgumentException("Drive-letter paths are not valid exact device or volume IDs.");
        }

        if (!VolumeBelongsToDevice(deviceId, volumeId))
        {
            throw new CliArgumentException("The exact volume ID must begin with the exact device ID followed by '|'.");
        }
    }

    private static bool VolumeBelongsToDevice(string deviceId, string volumeId)
    {
        var separatorIndex = volumeId.IndexOf('|');
        return separatorIndex > 0 &&
               separatorIndex < volumeId.Length - 1 &&
               string.Equals(volumeId[..separatorIndex], deviceId, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDriveLetterPath(string value)
        => value.Length >= 2 && char.IsLetter(value[0]) && value[1] == ':';

    private static string NormalizeRequestedMode(string value)
        => value.ToLowerInvariant() switch
        {
            "read-write" or "rw" => ApfsControlModes.ReadWrite,
            "read-only" or "ro" => ApfsControlModes.ReadOnly,
            _ => throw new CliArgumentException("--mode must be read-write or read-only."),
        };

    private static string? ToControlMode(MountAccessMode? mode)
        => mode switch
        {
            MountAccessMode.ReadWrite => ApfsControlModes.ReadWrite,
            MountAccessMode.ReadOnly => ApfsControlModes.ReadOnly,
            _ => null,
        };

    private static string CanonicalizeOperationId(string value)
    {
        if (!TryCanonicalizeOperationId(value, out var canonical))
        {
            throw new CliArgumentException("--operation-id must be a valid GUID.");
        }

        return canonical;
    }

    private static bool TryCanonicalizeOperationId(string? value, out string canonical)
    {
        canonical = string.Empty;
        if (value is null || !Guid.TryParse(value, out var parsed))
        {
            return false;
        }

        canonical = parsed.ToString("D").ToLowerInvariant();
        return true;
    }

    private static string NewOperationId()
        => Guid.NewGuid().ToString("D").ToLowerInvariant();

    private static string RequireValue(string[] args, ref int index, string option)
    {
        if (++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal))
        {
            throw new CliArgumentException($"{option} requires a value.");
        }

        return args[index];
    }

    private static StatusChangedPayload FilterStatus(StatusChangedPayload status, CliOptions options)
    {
        if (options.DeviceId is null && options.VolumeId is null)
        {
            return status;
        }

        var mountedVolumes = status.MountedVolumes?
            .Where(volume => MatchesTarget(volume.DeviceId, volume.VolumeId, options))
            .ToArray() ?? Array.Empty<MountedVolumeDisplay>();
        if (mountedVolumes.Length == 0)
        {
            throw new CliException(MissingVolume, ApfsOperationCodes.MissingVolume, "The exact device or volume is not currently mounted.");
        }

        if (mountedVolumes.Length != 1)
        {
            throw new CliException(
                OperationFailed,
                ApfsOperationCodes.OperationFailed,
                "The selector must resolve to exactly one mounted volume.");
        }

        var selected = mountedVolumes[0];

        return status with
        {
            MountedVolumes = mountedVolumes,
            MountPoints = mountedVolumes.Select(static volume => volume.MountPoint).ToArray(),
            State = selected.State,
            WriteEnabled = selected.WriteEnabled,
            WriteBackend = selected.WriteBackend,
            CommitModel = selected.CommitModel,
            NativeWriteReadiness = selected.NativeWriteReadiness,
            NativeWriteEngineState = selected.NativeWriteEngineState,
            NativeWriteValidationState = selected.NativeWriteValidationState,
            NativeWriteSafetyState = selected.NativeWriteSafetyState,
            RecoveryActive = selected.RecoveryActive,
            RecoveryReason = selected.RecoveryReason,
            LastRecoveryAction = selected.LastRecoveryAction,
            LastCommitXid = selected.LastCommitXid,
            WriteIncompatibilities = selected.WriteIncompatibilities,
            WriteUnsupportedFeatures = selected.WriteUnsupportedFeatures,
            DirtyTransactionCount = selected.DirtyTransactionCount,
            ShutdownDrainActive = selected.ShutdownDrainActive,
            InFlightMutationCallbacks = selected.InFlightMutationCallbacks,
            NativeWriteValidationEvidence = selected.NativeWriteValidationEvidence,
            NativeWriteDiagnostics = selected.NativeWriteDiagnostics,
        };
    }

    private static IReadOnlyList<DeviceInventory> FilterInventory(
        IReadOnlyList<DeviceInventory> devices,
        CliOptions options)
    {
        if (options.DeviceId is null && options.VolumeId is null)
        {
            return devices;
        }

        var filtered = new List<DeviceInventory>();
        foreach (var device in devices)
        {
            if (options.DeviceId is not null &&
                !string.Equals(device.Device.DeviceId, options.DeviceId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var volumes = options.VolumeId is null
                ? device.Volumes
                : device.Volumes
                    .Where(volume => string.Equals(volume.VolumeId, options.VolumeId, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
            if (options.VolumeId is not null && volumes.Count == 0)
            {
                continue;
            }

            filtered.Add(device with { Volumes = volumes });
        }

        if (filtered.Count == 0)
        {
            throw new CliException(MissingVolume, ApfsOperationCodes.MissingVolume, "The exact device or volume was not found.");
        }

        return filtered;
    }

    private static bool MatchesTarget(string deviceId, string volumeId, CliOptions options)
        => (options.DeviceId is null || string.Equals(deviceId, options.DeviceId, StringComparison.OrdinalIgnoreCase)) &&
           (options.VolumeId is null || string.Equals(volumeId, options.VolumeId, StringComparison.OrdinalIgnoreCase));

    private static JsonObject CreateResponse(
        CliOptions options,
        bool success,
        int exitCode,
        string code,
        string? message)
    {
        var response = new JsonObject
        {
            ["schemaVersion"] = PipeSchemaVersions.Schema2,
            ["command"] = options.Command,
            ["operationId"] = options.OperationId,
            ["success"] = success,
            ["exitCode"] = exitCode,
            ["code"] = code,
            ["resultCode"] = code,
            ["errorCode"] = success ? null : code,
            ["message"] = message is null ? null : JsonValue.Create(message),
        };
        return response;
    }

    private static void Add(JsonObject response, string name, object? value)
        => response[name] = value is null ? null : JsonSerializer.SerializeToNode(value, JsonOptions);

    private static void AddResultDetails(JsonObject response, OperationResultPayload result)
    {
        Add(response, "result", result);
        Add(response, "operationId", result.OperationId);
        Add(response, "command", result.Command);
        Add(response, "target", result.Target);
        Add(response, "fingerprint", result.Fingerprint);
        Add(response, "operationState", result.State);
        Add(response, "resultCode", result.Code);
        Add(response, "requestedAtUtc", result.RequestedAtUtc);
        Add(response, "startedAtUtc", result.StartedAtUtc);
        Add(response, "completedAtUtc", result.CompletedAtUtc);
        Add(response, "finalStatus", result.FinalStatus);
        Add(response, "evidencePath", result.EvidencePath);
        Add(response, "requestedMode", result.RequestedMode);
        Add(response, "effectiveMode", result.EffectiveMode);
        Add(response, "recoveryState", result.RecoveryState);
        Add(response, "recoveryActive", result.RecoveryActive);
        Add(response, "dirtyTransactionCount", result.DirtyTransactionCount);
        Add(response, "pendingDurability", result.PendingDurability);
        Add(response, "mountProof", result.MountProof);
        Add(response, "ownershipProof", result.OwnershipProof);
        Add(response, "durabilityProof", result.DurabilityProof);
        Add(response, "expiresAtUtc", result.ExpiresAtUtc);
        Add(response, "diagnostic", result.Diagnostic);
    }

    private static int EmitFailure(CliOptions options, int exitCode, string code, string message)
    {
        var response = CreateResponse(options, success: false, exitCode, code, message);
        Add(response, "error", message);
        return Emit(options, response, exitCode);
    }

    private static int Emit(CliOptions options, JsonObject response, int exitCode)
    {
        if (options.Human)
        {
            foreach (var property in response)
            {
                if (property.Value is null)
                {
                    continue;
                }

                var value = property.Value is JsonValue jsonValue && jsonValue.TryGetValue<string>(out var text)
                    ? text
                    : property.Value.ToJsonString(JsonOptions);
                Console.WriteLine($"{property.Key}: {value}");
            }
        }
        else
        {
            Console.WriteLine(response.ToJsonString(JsonOptions));
        }

        return exitCode;
    }

    private static void PrintHumanHelp()
    {
        Console.WriteLine("APFS Access CLI");
        Console.WriteLine("Usage: ApfsAccess.Cli.exe <command> [options]");
        Console.WriteLine();
        Console.WriteLine("Commands: status, list, mount, fix, eject, quit, query, cancel, version, capabilities");
        Console.WriteLine("Target options: --device-id ID --volume-id ID");
        Console.WriteLine("Operation options: --operation-id GUID --mode read-write|read-only --recovery-identity VALUE");
        Console.WriteLine("General options: --timeout-ms N --pipe-name NAME --dry-run --no-start-service --require-admin --elevate --human");
        Console.WriteLine("JSON output is the default; use --human for this format.");
        Console.WriteLine("Dry-run performs bounded service inspection and never issues a mutation or claims feasibility.");
        Console.WriteLine("--elevate is explicit and packaged-exe-only; --require-admin never elevates implicitly.");
        Console.WriteLine($"Explicit elevation uses result-envelope schema {CliElevation.ResultSchemaVersion}.");
    }

    private sealed record CliOptions(
        string Command,
        string? DeviceId,
        string? VolumeId,
        string? RecoveryIdentity,
        string? RequestedMode,
        TimeSpan Timeout,
        bool Human,
        bool DryRun,
        bool NoStartService,
        bool RequireAdministrator,
        string PipeName,
        bool ShowHelp,
        string OperationId,
        bool OperationIdProvided)
    {
        public static CliOptions Default { get; } = new(
            "status", null, null, null, null, TimeSpan.FromSeconds(30), false, false, false, false,
            ApfsPipeConstants.PipeName, false, NewOperationId(), false);
    }

    private sealed class CliArgumentException(string message) : Exception(message);

    private sealed class CliException(
        int exitCode,
        string code,
        string message,
        Exception? innerException = null,
        OperationResultPayload? rejectedResult = null) : Exception(message, innerException)
    {
        public int ExitCode { get; } = exitCode;
        public string Code { get; } = code;
        public OperationResultPayload? RejectedResult { get; } = rejectedResult;
    }

    private sealed class OperationWaitException(
        string message,
        OperationResultPayload? latest,
        Exception? innerException = null) : Exception(message, innerException)
    {
        public OperationResultPayload? Latest { get; } = latest;
    }

    private sealed class CliConnection(
        PipePeer peer,
        StatusChangedPayload status,
        CancellationTokenSource timeoutCts) : IAsyncDisposable
    {
        public PipePeer Peer { get; } = peer;
        public StatusChangedPayload Status { get; } = status;
        public CancellationToken Token => timeoutCts.Token;

        public async ValueTask DisposeAsync()
        {
            try
            {
                await Peer.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                timeoutCts.Dispose();
            }
        }
    }
}
