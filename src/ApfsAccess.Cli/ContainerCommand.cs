using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

// Task 12 Step 5: container-wide mount/unmount control. A container request
// names a device plus a container UUID (never a volume); the service resolves
// membership against live inventory and every attempted member must reach
// proven terminal state. The container UUID is canonicalized to lowercase at
// parse time so the client fingerprint reproduces the service-normalized
// value exactly (fingerprints fold the advertised container UUID verbatim).
internal sealed record ContainerControlOptions(
    string Action,
    string DeviceId,
    string ContainerId,
    string? RequestedMode,
    bool DryRun,
    string OperationId);

internal static class ContainerCommand
{
    internal const string Usage = "container-mount --device-id ID --container-id UUID --mode read-write|read-only [--operation-id ID] [--dry-run] [--no-start-service] | " +
        "container-unmount --device-id ID --container-id UUID [--operation-id ID] [--dry-run] [--no-start-service] | " +
        "container-verify --device-id ID --container-id UUID [--operation-id BATCH_ID] [--dry-run] [--no-start-service] | " +
        "container-fix --device-id ID --container-id UUID [--operation-id BATCH_ID] [--dry-run] [--no-start-service] | " +
        "container-manage --device-id ID --container-id UUID [--operation-id ID] [--no-start-service] | "+ContainerManagementCommand.Usage;
    internal const string ManageRefusal =
        "An unbound atomic container change is unavailable. Use container-manage plan/apply with one exact admitted offline member. No mount or mutation was performed.";

    internal static ContainerControlOptions Parse(string[] args)
    {
        if (args.Length == 0 || args[0] is not ("container-mount" or "container-unmount" or "container-verify" or "container-fix" or "container-manage"))
            throw new ArgumentException("Unknown container control action. " + Usage);
        var action = args[0];
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var dryRun = false;
        var noStartService = false;
        for (var i = 1; i < args.Length; i++)
        {
            // Container commands always connect to an existing service.
            if (string.Equals(args[i], "--no-start-service", StringComparison.OrdinalIgnoreCase))
            {
                if (noStartService) throw new ArgumentException("Duplicate container control option. " + Usage);
                noStartService = true;
                continue;
            }

            if (string.Equals(args[i], "--dry-run", StringComparison.OrdinalIgnoreCase))
            {
                if (dryRun) throw new ArgumentException("Duplicate container control option. " + Usage);
                dryRun = true;
                continue;
            }

            if (args[i] is not ("--device-id" or "--container-id" or "--mode" or "--operation-id") ||
                i + 1 == args.Length || !values.TryAdd(args[i], args[++i]))
                throw new ArgumentException("Invalid or duplicate container control option. " + Usage);
        }

        var operationId = values.GetValueOrDefault("--operation-id") ?? Guid.NewGuid().ToString("D");
        if (!Guid.TryParseExact(operationId, "D", out var parsedId) || parsedId.ToString("D") != operationId)
            throw new ArgumentException("Invalid operation identity. " + Usage);
        values.Remove("--operation-id");

        if (!values.TryGetValue("--device-id", out var device) || string.IsNullOrWhiteSpace(device))
            throw new ArgumentException("Container control requires --device-id. " + Usage);
        if (!values.TryGetValue("--container-id", out var container) || string.IsNullOrWhiteSpace(container))
            throw new ArgumentException("Container control requires --container-id. " + Usage);

        string? mode = null;
        if (action == "container-mount")
        {
            if (!values.TryGetValue("--mode", out var rawMode) || values.Count != 3)
                throw new ArgumentException("Container mount requires --device-id, --container-id, and --mode. " + Usage);
            mode = rawMode.Trim().ToLowerInvariant() switch
            {
                "read-only" or "ro" => ApfsControlModes.ReadOnly,
                "read-write" or "rw" => ApfsControlModes.ReadWrite,
                _ => throw new ArgumentException("Container mount mode must be read-only or read-write. " + Usage),
            };
        }
        else if (values.TryGetValue("--mode", out _) || values.Count != 2)
        {
            throw new ArgumentException(action == "container-unmount"
                ? "Container unmount requires --device-id and --container-id with no --mode. " + Usage
                : $"Container {action[10..]} requires --device-id and --container-id with no --mode. " + Usage);
        }

        return new ContainerControlOptions(action, device, container.Trim().ToLowerInvariant(), mode, dryRun, operationId);
    }

    internal static string? TryExtractCanonicalOperationId(string[] args)
    {
        for (var i = 0; i + 1 < args.Length; i++)
        {
            if (!string.Equals(args[i], "--operation-id", StringComparison.OrdinalIgnoreCase)) continue;
            var candidate = args[i + 1];
            if (Guid.TryParseExact(candidate, "D", out var parsed) && parsed.ToString("D") == candidate)
                return candidate;
            return null;
        }

        return null;
    }

    internal static bool ContainerMatches(string? requested, string? member)
        => ApfsTopology.MatchesContainerUuid(requested, member);

    internal static async Task<int> RunAsync(string[] args, IContainerVerificationClient? verificationClient = null,
        CancellationToken cancellationToken = default, DateTimeOffset? operationDeadlineUtc = null,
        Func<string, int, CancellationToken, Task<AgentControlClient>>? clientConnect = null,
        string? pipeName = null)
    {
        if(args.Length>1&&args[0]=="container-manage"&&args[1] is "plan" or "apply")
            return await ContainerManagementCommand.RunAsync(args,token:cancellationToken,operationDeadlineUtc:operationDeadlineUtc).ConfigureAwait(false);
        string? operationId = null;
        try
        {
            var options = Parse(args);
            operationId = options.OperationId;
            if (options.Action == "container-manage")
                return EmitUnavailable(options);
            if (options.Action is "container-verify" or "container-fix")
            {
                async Task<int> Batch(IContainerVerificationClient client, CancellationToken token)
                    => options.Action == "container-fix"
                        ? ContainerFixBatch.Emit(await ContainerFixBatch.RunAsync(options, client, token, operationDeadlineUtc).ConfigureAwait(false))
                        : ContainerVerificationBatch.Emit(await ContainerVerificationBatch.RunAsync(options, client, token, operationDeadlineUtc).ConfigureAwait(false));
                if (verificationClient is not null)
                    return await Batch(verificationClient, cancellationToken).ConfigureAwait(false);
                await using var verificationPipeClient = new PipeContainerVerificationClient();
                using var interrupted = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; interrupted.Cancel(); };
                Console.CancelKeyPress += handler;
                try
                {
                    return await Batch(verificationPipeClient, interrupted.Token).ConfigureAwait(false);
                }
                finally { Console.CancelKeyPress -= handler; }
            }
            var isUnmount = options.Action == "container-unmount";
            using var deadline = new CancellationTokenSource(
                isUnmount ? TimeSpan.FromSeconds(180) : TimeSpan.FromSeconds(90));
            clientConnect ??= AgentControlClient.ConnectAsync;
            await using var client = await clientConnect(pipeName ?? ApfsPipeConstants.PipeName, 2000, deadline.Token).ConfigureAwait(false);
            await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.InventoryRequested, new { }, "container-control-inventory"), deadline.Token).ConfigureAwait(false);
            InventoryPayload? inventory = null;
            while (inventory is null)
            {
                var response = await client.ReadMessageAsync(deadline.Token).ConfigureAwait(false) ?? throw new IOException();
                if (response.Type == ApfsMessageTypes.Inventory) PipeMessageCodec.TryGetPayload(response, out inventory);
            }

            var devices = inventory.Devices
                .Where(d => string.Equals(d.Device.DeviceId, options.DeviceId, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (devices.Length != 1)
                throw new ArgumentException(devices.Length == 0
                    ? $"Device '{options.DeviceId}' is not connected."
                    : $"Device '{options.DeviceId}' is not uniquely inventoried.");
            var members = devices[0].Volumes
                .Where(v => ContainerMatches(options.ContainerId, v.CatalogContainerUuid))
                .ToArray();
            if (members.Length == 0)
                throw new ArgumentException($"Container '{options.ContainerId}' has no inventoried volumes on device '{options.DeviceId}'.");

            if (options.DryRun)
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    schemaVersion = PipeSchemaVersions.Schema2,
                    command = options.Action,
                    operationId = options.OperationId,
                    success = true,
                    exitCode = 0,
                    dryRun = true,
                    inspectionOnly = true,
                    operationIssued = false,
                    members = members.Select(static m => new
                    {
                        m.VolumeId,
                        m.VolumeName,
                        m.SupportsExplorerMount,
                        m.IsEncrypted,
                        catalogDecision = m.CatalogDecision?.ToString(),
                        catalogAutoMountAllowed = m.CatalogAutoMountAllowed,
                    }).ToArray(),
                }, new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }

            var command = options.Action == "container-mount" ? ApfsControlCommands.ContainerMount : ApfsControlCommands.ContainerUnmount;
            var target = new ApfsControlTarget(options.DeviceId, string.Empty, null, null, options.ContainerId);
            var request = new ControlOperationRequestPayload(
                options.OperationId, command, target,
                RequestedMode: options.RequestedMode,
                ExpiresAtUtc: DateTime.UtcNow.AddSeconds(isUnmount ? 170 : 80));
            var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, PipeSchemaVersions.Schema2);
            if (!PipeMessageCodec.Validate(envelope).IsValid) throw new ArgumentException("Invalid container control operation.");
            await client.SendAsync(envelope, deadline.Token).ConfigureAwait(false);
            while (true)
            {
                var response = await client.ReadMessageAsync(deadline.Token).ConfigureAwait(false) ?? throw new IOException();
                if (response.Type != ApfsMessageTypes.OperationResult || response.RequestId != request.OperationId) continue;
                if (!PipeMessageCodec.Validate(response).IsValid || !PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result) ||
                    result is null || result.Fingerprint != ApfsOperationFingerprint.Compute(request)) throw new IOException();
                if (result.State is ApfsOperationStates.Accepted or ApfsOperationStates.InProgress)
                {
                    await Task.Delay(200, deadline.Token).ConfigureAwait(false);
                    await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery, new OperationResultQueryPayload(request.OperationId), request.OperationId, 2), deadline.Token).ConfigureAwait(false);
                    continue;
                }

                Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
                return result.Success ? 0 : 5;
            }
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine(JsonSerializer.Serialize(new {
                schemaVersion = PipeSchemaVersions.Schema2, command = CommandName(args),
                operationId = operationId ?? TryExtractCanonicalOperationId(args) ?? Guid.NewGuid().ToString("D"),
                success = false, exitCode = 2, code = ApfsOperationCodes.InvalidArguments,
                resultCode = ApfsOperationCodes.InvalidArguments, errorCode = ApfsOperationCodes.InvalidArguments,
                message = ex.Message, error = ex.Message, usage = Usage
            }, new JsonSerializerOptions { WriteIndented = true }));
            return 2;
        }
        catch
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new { operationId, success = false, message = "Container control operation interrupted. Use query --operation-id to inspect the owned operation before retrying." }));
            return 5;
        }
    }

    internal static string CommandName(string[] args) =>
        args.Length > 0 && args[0] is "container-mount" or "container-unmount" or "container-verify" or "container-fix" or "container-manage" ? args[0] : "container";

    // Live management still has no safe repair contract.
    internal static int EmitUnavailable(ContainerControlOptions options)
    {
        var message = ManageRefusal;
        Console.WriteLine(JsonSerializer.Serialize(new {
            schemaVersion = PipeSchemaVersions.Schema2, command = options.Action,
            operationId = options.OperationId,
            success = false, exitCode = 3, code = ApfsOperationCodes.ServiceUnavailable,
            resultCode = ApfsOperationCodes.ServiceUnavailable, errorCode = ApfsOperationCodes.ServiceUnavailable,
            message, error = message, usage = Usage
        }, new JsonSerializerOptions { WriteIndented = true }));
        return 3;
    }
}
