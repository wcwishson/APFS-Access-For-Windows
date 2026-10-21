using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
namespace ApfsAccess.Cli;

internal sealed record SnapshotControlOptions(
    string Action,
    string? DeviceId,
    string? VolumeId,
    string? SnapshotName,
    IReadOnlyList<string>? SnapshotIdentity,
    string OperationId);

internal static class SnapshotControlCommand
{
    internal const string Usage = "snapshots create --device-id ID --volume-id ID --name NAME [--operation-id ID] | " +
        "snapshots delete --device-id ID --volume-id ID --snapshot-xid XID --snapshot-name NAME --superblock-block N --omap-block N --omap-tree-block N --root-oid N --root-block N --extentref-block N --source-xid N [--operation-id ID] | " +
        "snapshots recover --device-id ID --volume-id ID [--operation-id ID]";

    private static readonly string[] DeleteFlags =
    [
        "--snapshot-xid", "--snapshot-name", "--superblock-block", "--omap-block",
        "--omap-tree-block", "--root-oid", "--root-block", "--extentref-block", "--source-xid",
    ];

    internal static SnapshotControlOptions Parse(string[] args)
    {
        if (args.Length == 0 || args[0] is not ("create" or "delete" or "recover"))
            throw new ArgumentException("Unknown snapshots control action. " + Usage);
        var action = args[0];
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 1; i < args.Length; i++)
        {
            if (args[i] is not ("--device-id" or "--volume-id" or "--name" or "--operation-id" or
                    "--snapshot-xid" or "--snapshot-name" or "--superblock-block" or "--omap-block" or
                    "--omap-tree-block" or "--root-oid" or "--root-block" or "--extentref-block" or "--source-xid") ||
                i + 1 == args.Length || !values.TryAdd(args[i], args[++i]))
                throw new ArgumentException("Invalid or duplicate snapshots control option. " + Usage);
        }

        var operationId = values.GetValueOrDefault("--operation-id") ?? Guid.NewGuid().ToString("D");
        if (!Guid.TryParseExact(operationId, "D", out var parsedId) || parsedId.ToString("D") != operationId)
            throw new ArgumentException("Invalid operation identity. " + Usage);
        values.Remove("--operation-id");

        if (!values.TryGetValue("--device-id", out var device) || string.IsNullOrWhiteSpace(device) ||
            !values.TryGetValue("--volume-id", out var volume) || string.IsNullOrWhiteSpace(volume))
            throw new ArgumentException("Snapshots control requires --device-id and --volume-id. " + Usage);

        string? name = null;
        IReadOnlyList<string>? identity = null;
        if (action == "create")
        {
            if (!values.TryGetValue("--name", out name) || values.Count != 3)
                throw new ArgumentException("Snapshots create requires --device-id, --volume-id, and --name. " + Usage);
        }
        else if (action == "delete")
        {
            if (values.Count != DeleteFlags.Length + 2)
                throw new ArgumentException("Snapshots delete requires --device-id, --volume-id, and the full nine-field snapshot identity from snapshots list. " + Usage);
            var fields = new string[DeleteFlags.Length];
            for (var i = 0; i < DeleteFlags.Length; i++)
            {
                if (!values.TryGetValue(DeleteFlags[i], out var field) || string.IsNullOrEmpty(field))
                    throw new ArgumentException($"Snapshots delete is missing {DeleteFlags[i]}. " + Usage);
                fields[i] = field;
            }

            identity = fields;
        }
        else if (values.Count != 2)
        {
            throw new ArgumentException("Snapshots recover requires --device-id and --volume-id. " + Usage);
        }

        return new SnapshotControlOptions(action, device, volume, name, identity, operationId);
    }

    internal static string? TryExtractCanonicalOperationId(string[] args)
    {
        for (var i = 0; i + 1 < args.Length; i++)
        {
            if (!string.Equals(args[i], "--operation-id", StringComparison.Ordinal)) continue;
            var candidate = args[i + 1];
            if (Guid.TryParseExact(candidate, "D", out var parsed) && parsed.ToString("D") == candidate)
                return candidate;
            return null;
        }
        return null;
    }

    internal static async Task<int> RunAsync(string[] args,
        Func<string, int, CancellationToken, Task<AgentControlClient>>? clientConnect = null,
        string? pipeName = null)
    {
        string? operationId = null;
        try
        {
            var options = Parse(args);
            operationId = options.OperationId;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            clientConnect ??= AgentControlClient.ConnectAsync;
            await using var client = await clientConnect(pipeName ?? ApfsPipeConstants.PipeName, 2000, deadline.Token).ConfigureAwait(false);
            await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.InventoryRequested, new { }, "snapshot-control-inventory"), deadline.Token).ConfigureAwait(false);
            InventoryPayload? inventory = null;
            while (inventory is null)
            {
                var response = await client.ReadMessageAsync(deadline.Token).ConfigureAwait(false) ?? throw new IOException();
                if (response.Type == ApfsMessageTypes.Inventory) PipeMessageCodec.TryGetPayload(response, out inventory);
            }

            var matches = inventory.Devices.SelectMany(d => d.Volumes.Select(v => (d, v))).Where(x =>
                string.Equals(x.v.DeviceId, options.DeviceId, StringComparison.OrdinalIgnoreCase) && x.v.VolumeId == options.VolumeId).ToArray();
            if (matches.Length != 1) throw new ArgumentException("Select exactly one known volume by device and volume ID.");
            var target = SelectedControlTarget.Create(matches[0].d, matches[0].v);
            if (!SelectedControlTarget.Matches(inventory.Devices, target)) throw new ArgumentException("Ambiguous volume identity.");

            var command = options.Action switch
            {
                "create" => ApfsControlCommands.SnapshotCreate,
                "delete" => ApfsControlCommands.SnapshotDelete,
                _ => ApfsControlCommands.SnapshotRecover,
            };
            var request = new ControlOperationRequestPayload(
                options.OperationId, command, target,
                ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80),
                SnapshotName: options.SnapshotName, SnapshotIdentity: options.SnapshotIdentity);
            var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, PipeSchemaVersions.Schema2);
            if (!PipeMessageCodec.Validate(envelope).IsValid) throw new ArgumentException("Invalid snapshots control operation.");
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
                schemaVersion = PipeSchemaVersions.Schema2, command = "snapshots",
                operationId = operationId ?? TryExtractCanonicalOperationId(args) ?? Guid.NewGuid().ToString("D"),
                success = false, exitCode = 2, code = ApfsOperationCodes.InvalidArguments,
                resultCode = ApfsOperationCodes.InvalidArguments, errorCode = ApfsOperationCodes.InvalidArguments,
                message = ex.Message, error = ex.Message, usage = Usage
            }, new JsonSerializerOptions { WriteIndented = true }));
            return 2;
        }
        catch
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new { operationId, success = false, message = "Snapshots control operation interrupted. Use query --operation-id to inspect the owned operation before retrying." }));
            return 5;
        }
    }
}
