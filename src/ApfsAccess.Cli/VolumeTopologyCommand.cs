using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal static class VolumeTopologyCommand
{
    internal const string Usage = "volume-create-plan --device-id IMAGE --container-uuid UUID --name NAME --quota-bytes N --reserve-bytes N --case-sensitive true|false | " +
        "volume-delete-plan --device-id IMAGE --volume-id ID | volume-resize-plan --device-id IMAGE --volume-id ID --kind grow|shrink --target-bytes N | " +
        "volume-format-plan --device-id IMAGE --volume-id ID --kind format|erase --name NAME --case-sensitive true|false | " +
        "volume-management-apply|volume-management-cancel|volume-management-recover --plan-operation-id ID; optional --operation-id ID";
    internal static ManagementControlOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 1; i < args.Length; i++)
            if (args[i] is not ("--device-id" or "--container-uuid" or "--volume-id" or "--name" or "--quota-bytes" or "--reserve-bytes" or
                "--case-sensitive" or "--target-bytes" or "--kind" or "--plan-operation-id" or "--operation-id") || i + 1 >= args.Length || !values.TryAdd(args[i], args[++i]))
                throw new ArgumentException(Usage);
        var id = values.GetValueOrDefault("--operation-id") ?? Guid.NewGuid().ToString("D");
        values.Remove("--operation-id");
        if (!Guid.TryParseExact(id, "D", out var guid) || guid.ToString("D") != id) throw new ArgumentException(Usage);
        var action = args[0];
        var device = values.GetValueOrDefault("--device-id") ?? "";
        var volume = values.GetValueOrDefault("--volume-id") ?? "";
        var container = values.GetValueOrDefault("--container-uuid");
        VolumeManagementParameters? p = null;
        string? plan = null;
        if (action == ApfsControlCommands.VolumeCreatePlan)
        {
            var caseText = values.GetValueOrDefault("--case-sensitive");
            p = new("create", values.GetValueOrDefault("--name"), values.GetValueOrDefault("--quota-bytes"),
                values.GetValueOrDefault("--reserve-bytes"), caseText is "true" ? true : caseText is "false" ? false : null);
            if (values.Count != 6 || !Guid.TryParse(container, out var cg) || cg == Guid.Empty || !VolumeManagementParameters.Valid(action, p))
                throw new ArgumentException(Usage);
        }
        else if (action == ApfsControlCommands.VolumeDeletePlan)
        {
            p = new("delete");
            if (values.Count != 2 || string.IsNullOrWhiteSpace(volume)) throw new ArgumentException(Usage);
        }
        else if (action is ApfsControlCommands.VolumeResizePlan or ApfsControlCommands.VolumeFormatPlan)
        {
            var caseText = values.GetValueOrDefault("--case-sensitive");
            p = new(values.GetValueOrDefault("--kind") ?? "", Name: values.GetValueOrDefault("--name"),
                CaseSensitive: caseText is "true" ? true : caseText is "false" ? false : null, TargetBytes: values.GetValueOrDefault("--target-bytes"));
            if (values.Count != (action == ApfsControlCommands.VolumeResizePlan ? 4 : 5) || string.IsNullOrWhiteSpace(volume) ||
                !VolumeManagementParameters.Valid(action, p)) throw new ArgumentException(Usage);
        }
        else
        {
            plan = values.GetValueOrDefault("--plan-operation-id");
            if (!VolumeManagementParameters.IsCommand(action) || values.Count != 1 ||
                !Guid.TryParseExact(plan, "D", out var pg) || pg.ToString("D") != plan) throw new ArgumentException(Usage);
        }
        var physicalOperation = action is ApfsControlCommands.VolumeResizePlan or ApfsControlCommands.VolumeFormatPlan or
            ApfsControlCommands.VolumeCreatePlan or ApfsControlCommands.VolumeDeletePlan &&
            VolumePhysicalBinding.IsDevicePath(device);
        if (plan is null && !VolumeTopologyProfile.LocalPath(device) && !physicalOperation)
            throw new ArgumentException("Select a local image or a physical drive. " + Usage);
        return new(action, device, volume, null, null, null, null, null, null, false, id, p, container, plan);
    }

    internal static async Task<(ApfsControlTarget, VolumeManagementParameters)> ResolveAsync(ManagementControlOptions o,
        InventoryPayload inventory, AgentControlClient client, CancellationToken ct)
    {
        if (o.PlanOperationId is { } planId)
        {
            await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery, new OperationResultQueryPayload(planId), planId, 2), ct).ConfigureAwait(false);
            while (true)
            {
                var response = await client.ReadMessageAsync(ct).ConfigureAwait(false) ?? throw new IOException("Plan query interrupted.");
                if (response.Type != ApfsMessageTypes.OperationResult || response.RequestId != planId) continue;
                if (!PipeMessageCodec.Validate(response).IsValid || !PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var plan) ||
                    plan is not { Success: true, Target: not null, VolumeManagement: not null, VolumeManagementReport: not null } ||
                    !VolumeManagementParameters.IsPlan(plan.Command)) throw new ArgumentException("No prepared plan is available.");
                var token = plan.VolumeManagementReport.Value.GetProperty("confirmationToken").GetString();
                var p = plan.VolumeManagement with { Token = token };
                if (!VolumeManagementParameters.Valid(o.Action, p)) throw new IOException("Invalid prepared native token.");
                return (plan.Target, p);
            }
        }
        var devices = inventory.Devices.Where(d => string.Equals(d.Device.DeviceId, o.DeviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (devices.Length != 1 || !TopologyAdmission.Validate(devices[0])) throw new ArgumentException("Select one admitted image.");
        if (o.VolumeManagement?.Kind == "create")
        {
            var containers = devices[0].Topology!.Snapshot.Containers.Where(c => TopologyAdmission.SameUuid(c.Uuid, o.ContainerUuid)).ToArray();
            if (containers.Length != 1) throw new ArgumentException("Select one observed container.");
            return (new(o.DeviceId, "", ContainerUuid: containers[0].Uuid), o.VolumeManagement);
        }
        var selected = devices[0].Volumes.Where(v => v.VolumeId == o.VolumeId).ToArray();
        if (selected.Length != 1) throw new ArgumentException("Select one observed volume.");
        return (SelectedControlTarget.Create(devices[0], selected[0]), o.VolumeManagement!);
    }
}
