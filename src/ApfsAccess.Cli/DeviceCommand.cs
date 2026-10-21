using System.Text.Json;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

// Task 12: physical device control actions:
// - device-eject: drains every container/volume on one physical device.
// - rescan / device-rescan: triggers fresh hardware and APFS container/volume
//   discovery across connected devices (or for a single physical device).
internal sealed record DeviceEjectOptions(string DeviceId, bool DryRun, string OperationId);

internal sealed record DeviceControlOptions(string Command, string? DeviceId, bool DryRun, string OperationId);

internal static class DeviceCommand
{
    internal const string Usage = "device-eject --device-id ID [--operation-id ID] [--dry-run] | rescan [--device-id ID] [--operation-id ID] [--dry-run]";

    internal static DeviceEjectOptions Parse(string[] args)
    {
        var options = ParseControl(args);
        if (options.Command != "device-eject")
            throw new ArgumentException("Unknown device control action. " + Usage);
        if (string.IsNullOrWhiteSpace(options.DeviceId))
            throw new ArgumentException("Device eject requires exactly --device-id. " + Usage);
        return new DeviceEjectOptions(options.DeviceId, options.DryRun, options.OperationId);
    }

    internal static DeviceControlOptions ParseControl(string[] args)
    {
        if (args.Length == 0 || args[0] is not ("device-eject" or "rescan" or "device-rescan"))
            throw new ArgumentException("Unknown device control action. " + Usage);

        var command = args[0];
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var dryRun = false;
        for (var i = 1; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--dry-run", StringComparison.OrdinalIgnoreCase))
            {
                if (dryRun) throw new ArgumentException("Duplicate device control option. " + Usage);
                dryRun = true;
                continue;
            }

            if (args[i] is not ("--device-id" or "--operation-id") ||
                i + 1 == args.Length || !values.TryAdd(args[i], args[++i]))
                throw new ArgumentException("Invalid or duplicate device control option. " + Usage);
        }

        var operationId = values.GetValueOrDefault("--operation-id") ?? Guid.NewGuid().ToString("D");
        if (!Guid.TryParseExact(operationId, "D", out var parsedId) || parsedId.ToString("D") != operationId)
            throw new ArgumentException("Invalid operation identity. " + Usage);
        values.Remove("--operation-id");

        var device = values.GetValueOrDefault("--device-id");
        if (command == "device-eject")
        {
            if (string.IsNullOrWhiteSpace(device) || values.Count != 1)
                throw new ArgumentException("Device eject requires exactly --device-id. " + Usage);
        }
        else
        {
            if (values.Count > 1 || (values.Count == 1 && !values.ContainsKey("--device-id")))
                throw new ArgumentException("Invalid device control option. " + Usage);
        }

        return new DeviceControlOptions(command, device, dryRun, operationId);
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

    internal static async Task<int> RunAsync(string[] args,
        Func<string, int, CancellationToken, Task<AgentControlClient>>? clientConnect = null,
        string? pipeName = null)
    {
        string? operationId = null;
        string commandName = args.Length > 0 && args[0] is "rescan" or "device-rescan" ? args[0] : "device-eject";
        try
        {
            var options = ParseControl(args);
            commandName = options.Command;
            operationId = options.OperationId;

            if (options.Command is "rescan" or "device-rescan")
            {
                return await RunRescanAsync(options, clientConnect, pipeName).ConfigureAwait(false);
            }

            return await RunEjectAsync(options, clientConnect, pipeName).ConfigureAwait(false);
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine(JsonSerializer.Serialize(new {
                schemaVersion = PipeSchemaVersions.Schema2,
                command = commandName,
                operationId = operationId ?? TryExtractCanonicalOperationId(args) ?? Guid.NewGuid().ToString("D"),
                success = false,
                exitCode = 2,
                code = ApfsOperationCodes.InvalidArguments,
                resultCode = ApfsOperationCodes.InvalidArguments,
                errorCode = ApfsOperationCodes.InvalidArguments,
                message = ex.Message,
                error = ex.Message,
                usage = Usage
            }, new JsonSerializerOptions { WriteIndented = true }));
            return 2;
        }
        catch
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new {
                operationId,
                success = false,
                message = $"{commandName} operation interrupted. Use query --operation-id to inspect the owned operation before retrying."
            }));
            return 5;
        }
    }

    private static async Task<int> RunRescanAsync(DeviceControlOptions options,
        Func<string, int, CancellationToken, Task<AgentControlClient>>? clientConnect = null,
        string? pipeName = null)
    {
        if (options.DryRun)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                schemaVersion = PipeSchemaVersions.Schema2,
                command = options.Command,
                operationId = options.OperationId,
                success = true,
                exitCode = 0,
                dryRun = true,
                inspectionOnly = true,
                operationIssued = false,
                deviceId = options.DeviceId,
                scope = options.DeviceId is not null ? "device" : "all",
            }, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        clientConnect ??= AgentControlClient.ConnectAsync;
        await using var client = await clientConnect(pipeName ?? ApfsPipeConstants.PipeName, 2000, deadline.Token).ConfigureAwait(false);

        await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.InventoryRequested, new { }, "device-rescan-inventory"), deadline.Token).ConfigureAwait(false);
        InventoryPayload? inventory = null;
        while (inventory is null)
        {
            var response = await client.ReadMessageAsync(deadline.Token).ConfigureAwait(false) ?? throw new IOException();
            if (response.Type == ApfsMessageTypes.Inventory) PipeMessageCodec.TryGetPayload(response, out inventory);
        }

        var devices = inventory.Devices;
        if (!string.IsNullOrWhiteSpace(options.DeviceId))
        {
            var matched = devices.Where(d => string.Equals(d.Device.DeviceId, options.DeviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matched.Length == 0)
                throw new ArgumentException($"Device '{options.DeviceId}' is not connected.");
            devices = matched;
        }

        Console.WriteLine(JsonSerializer.Serialize(new
        {
            schemaVersion = PipeSchemaVersions.Schema2,
            command = options.Command,
            operationId = options.OperationId,
            success = true,
            exitCode = 0,
            deviceId = options.DeviceId,
            devices,
            timestampUtc = inventory.TimestampUtc,
        }, new JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }

    private static async Task<int> RunEjectAsync(DeviceControlOptions options,
        Func<string, int, CancellationToken, Task<AgentControlClient>>? clientConnect = null,
        string? pipeName = null)
    {
        if (string.IsNullOrWhiteSpace(options.DeviceId))
            throw new ArgumentException("Device eject requires exactly --device-id. " + Usage);

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(180));
        clientConnect ??= AgentControlClient.ConnectAsync;
        await using var client = await clientConnect(pipeName ?? ApfsPipeConstants.PipeName, 2000, deadline.Token).ConfigureAwait(false);
        await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.InventoryRequested, new { }, "device-control-inventory"), deadline.Token).ConfigureAwait(false);
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
        var containers = devices[0].Volumes
            .Where(static v => !string.IsNullOrWhiteSpace(v.CatalogContainerUuid))
            .Select(static v => v.CatalogContainerUuid!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (options.DryRun)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                schemaVersion = PipeSchemaVersions.Schema2,
                command = "device-eject",
                operationId = options.OperationId,
                success = true,
                exitCode = 0,
                dryRun = true,
                inspectionOnly = true,
                operationIssued = false,
                containers = containers.Select(container => new
                {
                    containerUuid = container,
                    members = devices[0].Volumes
                        .Where(v => string.Equals(v.CatalogContainerUuid, container, StringComparison.OrdinalIgnoreCase))
                        .Select(static v => v.VolumeId).ToArray(),
                }).ToArray(),
            }, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }

        var target = new ApfsControlTarget(options.DeviceId, string.Empty);
        var request = new ControlOperationRequestPayload(
            options.OperationId, ApfsControlCommands.DeviceEject, target,
            ExpiresAtUtc: DateTime.UtcNow.AddSeconds(170));
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, PipeSchemaVersions.Schema2);
        if (!PipeMessageCodec.Validate(envelope).IsValid) throw new ArgumentException("Invalid device control operation.");
        await client.SendAsync(envelope, deadline.Token).ConfigureAwait(false);
        while (true)
        {
            var response = await client.ReadMessageAsync(deadline.Token).ConfigureAwait(false) ?? throw new IOException();
            if (response.Type != ApfsMessageTypes.OperationResult || response.RequestId != request.OperationId) continue;
            if (!PipeMessageCodec.Validate(response).IsValid || !PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result) ||
                result is null || result.Fingerprint != ApfsOperationFingerprint.Compute(request)) throw new IOException();
            if (result.State is ApfsOperationStates.Accepted or ApfsOperationStates.InProgress)
            {
                await Task.Delay(500, deadline.Token).ConfigureAwait(false);
                await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery, new OperationResultQueryPayload(request.OperationId), request.OperationId, 2), deadline.Token).ConfigureAwait(false);
                continue;
            }

            Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
            return result.Success ? 0 : 5;
        }
    }
}
