using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

// Task 12 action-contract parity: expose the service-side verify-plan-confirm-apply
// management path through the agent-friendly CLI. The service remains the only
// planner authority: plan binds device/volume/operation to the live observed
// checkpoint, apply consumes a single-use confirmation token. This command only
// forwards exact canonical operation names (rename-volume, set-quota-reserve)
// and caller-supplied parameters; all checkpoint/quiesce/keeper semantics stay
// service-side. Exit codes follow the existing control-command contract:
// 0 success, 2 argument errors with schema-2 envelope, 5 interrupted/failed.
internal sealed record ManagementControlOptions(
    string Action,
    string DeviceId,
    string VolumeId,
    string? Operation,
    string? Token,
    string? Name,
    string? QuotaBytes,
    string? ReserveBytes,
    string? ImagePath,
    bool DryRun,
    string OperationId, VolumeManagementParameters? VolumeManagement = null,
    string? ContainerUuid = null, string? PlanOperationId = null);

internal static class ManagementCommand
{
    internal const string Usage = "management-plan --device-id ID --volume-id ID --operation rename-volume|set-quota-reserve [--operation-id ID] [--dry-run] | " +
        "management-apply --device-id ID --volume-id ID --operation rename-volume|set-quota-reserve --token TOKEN --image-path PATH [--name NAME | --quota-bytes N --reserve-bytes N] [--operation-id ID] [--dry-run] | " +
        "volume-verify|snapshot-list --device-id ID --volume-id ID [--operation-id ID] [--dry-run]";

    internal static ManagementControlOptions Parse(string[] args)
    {
        if (args.Length > 0 && VolumeManagementParameters.IsCommand(args[0])) return VolumeTopologyCommand.Parse(args);
        if (args.Length == 0 || args[0] is not ("management-plan" or "management-apply" or "volume-verify" or "snapshot-list"))
            throw new ArgumentException("Unknown management control action. " + Usage);
        var action = args[0];
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var dryRun = false;
        for (var i = 1; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--dry-run", StringComparison.OrdinalIgnoreCase))
            {
                if (dryRun) throw new ArgumentException("Duplicate management control option. " + Usage);
                dryRun = true;
                continue;
            }

            if (args[i] is not ("--device-id" or "--volume-id" or "--operation" or "--token" or "--name" or
                    "--quota-bytes" or "--reserve-bytes" or "--image-path" or "--operation-id") ||
                i + 1 == args.Length || !values.TryAdd(args[i], args[++i]))
                throw new ArgumentException("Invalid or duplicate management control option. " + Usage);
        }

        var operationId = values.GetValueOrDefault("--operation-id") ?? Guid.NewGuid().ToString("D");
        if (!Guid.TryParseExact(operationId, "D", out var parsedId) || parsedId.ToString("D") != operationId)
            throw new ArgumentException("Invalid operation identity. " + Usage);
        values.Remove("--operation-id");

        if (action is "volume-verify" or "snapshot-list")
        {
            if (values.Count != 2 || !values.TryGetValue("--device-id", out var source) || string.IsNullOrWhiteSpace(source) ||
                !values.TryGetValue("--volume-id", out var selected) || string.IsNullOrWhiteSpace(selected))
                throw new ArgumentException("Volume verify requires exactly --device-id and --volume-id. " + Usage);
            return new(action, source, selected, null, null, null, null, null, null, dryRun, operationId);
        }

        if (!values.TryGetValue("--device-id", out var device) || string.IsNullOrWhiteSpace(device) ||
            !values.TryGetValue("--volume-id", out var volume) || string.IsNullOrWhiteSpace(volume) ||
            !values.TryGetValue("--operation", out var operation) ||
            (operation is not (ApfsManagementOperations.RenameVolume or ApfsManagementOperations.SetQuotaReserve)))
            throw new ArgumentException("Management control requires --device-id, --volume-id, and --operation rename-volume|set-quota-reserve. " + Usage);

        values.TryGetValue("--token", out var token);
        values.TryGetValue("--name", out var name);
        values.TryGetValue("--quota-bytes", out var quotaBytes);
        values.TryGetValue("--reserve-bytes", out var reserveBytes);
        values.TryGetValue("--image-path", out var imagePath);

        if (action == "management-plan")
        {
            if (token is not null || name is not null || quotaBytes is not null || reserveBytes is not null || imagePath is not null || values.Count != 3)
                throw new ArgumentException("Management plan takes only --device-id, --volume-id, and --operation. " + Usage);
        }
        else
        {
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(imagePath))
                throw new ArgumentException("Management apply requires --token and --image-path. " + Usage);
            var isRename = string.Equals(operation, ApfsManagementOperations.RenameVolume, StringComparison.Ordinal);
            if (isRename)
            {
                if (string.IsNullOrWhiteSpace(name) ||
                    quotaBytes is not null || reserveBytes is not null || values.Count != 6)
                    throw new ArgumentException("Management rename apply requires --token, --name, and --image-path with no quota values. " + Usage);
            }
            else
            {
                if (name is not null ||
                    string.IsNullOrWhiteSpace(quotaBytes) || string.IsNullOrWhiteSpace(reserveBytes) || values.Count != 7)
                    throw new ArgumentException("Management quota apply requires --token, --image-path, --quota-bytes, and --reserve-bytes with no name. " + Usage);
            }
        }

        return new ManagementControlOptions(action, device, volume, operation, token, name, quotaBytes, reserveBytes, imagePath, dryRun, operationId);
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

    internal static async Task<int> RunAsync(string[] args,string? expectedContainerUuid=null,
        CancellationToken cancellationToken=default,DateTimeOffset? operationDeadlineUtc=null,Guid? privateInstance=null,
        Func<string,int,CancellationToken,Task<PipePeer>>? connect=null,
        Func<string,int,CancellationToken,Task<AgentControlClient>>? clientConnect=null)
    {
        string? operationId = null;
        string? selectedPipe = null;
        var issued = false;
        if (clientConnect is null)
        {
            if (connect is not null)
                clientConnect = async (pipe, ms, ct) => await AgentControlClient.ConnectAsync(await connect(pipe, ms, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
            else
                clientConnect = AgentControlClient.ConnectAsync;
        }
        try
        {
            var options = Parse(args);
            operationId = options.OperationId;
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var remaining=operationDeadlineUtc is { } inherited?inherited-DateTimeOffset.UtcNow:TimeSpan.FromSeconds(90);
            if(remaining<=TimeSpan.Zero)throw new OperationCanceledException("The inherited management deadline expired.");
            deadline.CancelAfter(remaining<TimeSpan.FromSeconds(90)?remaining:TimeSpan.FromSeconds(90));
            deadline.Token.ThrowIfCancellationRequested();
            selectedPipe=privateInstance is { } instance?FusionControlEndpoint.ForPrivateInstance(instance):ApfsPipeConstants.PipeName;
            await using var client = await clientConnect(selectedPipe, 2000, deadline.Token).ConfigureAwait(false);
            var initialStatus = client.ValidatedInitialStatus;
            InventoryPayload? inventory = RetainedQueryInventory(options, initialStatus);
            if (inventory is null)
                await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.InventoryRequested, new { }, "management-control-inventory"), deadline.Token).ConfigureAwait(false);
            while (inventory is null)
            {
                var response = await client.ReadMessageAsync(deadline.Token).ConfigureAwait(false) ?? throw new IOException();
                if (response.Type == ApfsMessageTypes.Inventory) PipeMessageCodec.TryGetPayload(response, out inventory);
            }

            var matches = inventory.Devices.SelectMany(d => d.Volumes.Select(v => (d, v))).Where(x =>
                string.Equals(x.v.DeviceId, options.DeviceId, StringComparison.OrdinalIgnoreCase) && x.v.VolumeId == options.VolumeId).ToArray();
            ApfsControlTarget target;
            var topology = options.VolumeManagement;
            if (VolumeManagementParameters.IsCommand(options.Action))
                (target, topology) = await VolumeTopologyCommand.ResolveAsync(options, inventory, client, deadline.Token).ConfigureAwait(false);
            else
            {
                if (matches.Length != 1) throw new ArgumentException("Select exactly one known volume by device and volume ID.");
                target = SelectedControlTarget.Create(matches[0].d, matches[0].v);
                if (!SelectedControlTarget.Matches(inventory.Devices, target)) throw new ArgumentException("Ambiguous volume identity.");
            }
            RequireContainerTarget(expectedContainerUuid,target);
            if(expectedContainerUuid is not null)
            {
                _ = BoundContainerActions.RequireOfflineMember(initialStatus,target,inventory.Devices);
            }

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
                    deviceId = options.DeviceId,
                    volumeId = options.VolumeId,
                    managementOperation = options.Operation,
                }, new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }

            var command = VolumeManagementParameters.IsCommand(options.Action) ? options.Action : options.Action == "volume-verify" ? ApfsControlCommands.VolumeVerify :
                options.Action == "snapshot-list" ? ApfsControlCommands.SnapshotList :
                options.Action == "management-plan" ? ApfsControlCommands.ManagementPlan : ApfsControlCommands.ManagementApply;
            var request = new ControlOperationRequestPayload(
                options.OperationId, command, target,
                ExpiresAtUtc: operationDeadlineUtc is { } expires&&expires.UtcDateTime<DateTime.UtcNow.AddSeconds(80)?expires.UtcDateTime:DateTime.UtcNow.AddSeconds(80),
                ManagementOperation: options.Operation,
                ManagementToken: options.Token,
                ManagementName: options.Name,
                ManagementQuotaBytes: options.QuotaBytes,
                ManagementReserveBytes: options.ReserveBytes,
                ManagementImagePath: options.ImagePath, VolumeManagement: topology);
            var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, PipeSchemaVersions.Schema2);
            if (!PipeMessageCodec.Validate(envelope).IsValid) throw new ArgumentException("Invalid management control operation.");
            issued = true;
            await client.SendAsync(envelope, deadline.Token).ConfigureAwait(false);
            while (true)
            {
                var response = await client.ReadMessageAsync(deadline.Token).ConfigureAwait(false) ?? throw new IOException();
                if (response.Type != ApfsMessageTypes.OperationResult || response.RequestId != request.OperationId) continue;
                if (!PipeMessageCodec.Validate(response).IsValid || !PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result) ||
                    result is null || result.OperationId != request.OperationId || result.Command != request.Command ||
                    result.Fingerprint != ApfsOperationFingerprint.Compute(request)) throw new IOException();
                if (result.State is ApfsOperationStates.Accepted or ApfsOperationStates.InProgress)
                {
                    await Task.Delay(200, deadline.Token).ConfigureAwait(false);
                    await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery, new OperationResultQueryPayload(request.OperationId), request.OperationId, 2), deadline.Token).ConfigureAwait(false);
                    continue;
                }

                var output = JsonSerializer.SerializeToNode(result, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase })!.AsObject();
                output["schemaVersion"] = PipeSchemaVersions.Schema2;
                output["exitCode"] = result.Success ? 0 : 5;
                Console.WriteLine(output.ToJsonString());
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
        catch (Exception ex)
        {
            if (issued && ex is OperationCanceledException && operationId is not null && selectedPipe is not null)
            {
                try { await ManagementTryCancelAsync(selectedPipe, operationId, clientConnect).ConfigureAwait(false); }
                catch (Exception cancelEx) when (cancelEx is IOException or OperationCanceledException or InvalidOperationException) { }
            }
            Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = PipeSchemaVersions.Schema2, command = CommandName(args),
                operationId = operationId ?? TryExtractCanonicalOperationId(args) ?? Guid.NewGuid().ToString("D"), success = false,
                exitCode = 5, code = ApfsOperationCodes.ServiceUnavailable,
                message = "Control operation interrupted. Use query --operation-id to inspect the owned operation before retrying.",
                error = ex.GetType().Name }));
            return 5;
        }
    }

    internal static InventoryPayload? RetainedQueryInventory(ManagementControlOptions options, PipeEnvelope greeting)
    {
        if (options.Action is not ("volume-verify" or "snapshot-list")) return null;
        if (!PipeMessageCodec.TryGetPayload<StatusChangedPayload>(greeting, out var status) || status is null)
            throw new IOException("Current owner status is unavailable.");
        return RetainedQueryInventory(options, status);
    }

    internal static InventoryPayload? RetainedQueryInventory(ManagementControlOptions options, StatusChangedPayload status)
    {
        if (options.Action is not ("volume-verify" or "snapshot-list")) return null;
        var selected = (status.ConnectedInventory ?? []).SelectMany(d => d.Volumes).Where(v =>
            string.Equals(v.DeviceId, options.DeviceId, StringComparison.OrdinalIgnoreCase) && v.VolumeId == options.VolumeId).ToArray();
        var hasOwner = (status.MountedVolumes ?? []).Any(m =>
            string.Equals(m.DeviceId, options.DeviceId, StringComparison.OrdinalIgnoreCase) ||
            selected.Any(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, m.CatalogContainerUuid)));
        if (!hasOwner) return null;
        if (status.ConnectedInventory is null || selected.Length != 1)
            throw new IOException("The retained owner's admitted inventory is unavailable.");
        return new(status.ConnectedInventory, status.TimestampUtc);
    }

    internal static void RequireContainerTarget(string? expected,ApfsControlTarget target)
    {
        if(expected is not null&&!TopologyAdmission.SameUuid(expected,target.ContainerUuid))
            throw new ArgumentException("The selected volume is not in the requested current container. Refresh before acting.");
    }

    internal static async Task<bool> ManagementTryCancelAsync(string selectedPipe, string operationId,
        Func<string, int, CancellationToken, Task<AgentControlClient>>? clientConnect = null,
        CancellationToken cancellationToken = default)
    {
        clientConnect ??= AgentControlClient.ConnectAsync;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        await using var client = await clientConnect(selectedPipe, 1000, deadline.Token).ConfigureAwait(false);
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.CancellationRequest,
            new OperationCancellationRequestPayload(operationId), operationId, PipeSchemaVersions.Schema2);
        if (!PipeMessageCodec.Validate(envelope).IsValid)
            throw new InvalidOperationException("Invalid cancellation request.");
        await client.SendAsync(envelope, deadline.Token).ConfigureAwait(false);
        while (await client.ReadMessageAsync(deadline.Token).ConfigureAwait(false) is { } response)
        {
            if (response.Type == ApfsMessageTypes.OperationResult && response.RequestId == operationId)
                return true;
        }
        return false;
    }

    private static Task TryCancelAsync(string selectedPipe, string operationId,
        Func<string, int, CancellationToken, Task<AgentControlClient>> clientConnect)
        => ManagementTryCancelAsync(selectedPipe, operationId, clientConnect);

    internal static string CommandName(string[] args) =>
        args.Length > 0 && (VolumeManagementParameters.IsCommand(args[0]) || args[0] is "management-plan" or "management-apply" or "volume-verify" or "snapshot-list") ? args[0] : "management";
}
