using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public static class VolumeTopologyWorkflow
{
    public static async Task<OperationResultPayload> RunAsync(ControlOperationRequestPayload planRequest,
        Func<ControlOperationRequestPayload, Task<OperationResultPayload>> send, Func<string, bool> confirm,
        Func<StatusChangedPayload>? latestStatus = null)
    {
        if (!VolumeManagementParameters.IsPlan(planRequest.Command) ||
            !VolumeManagementParameters.Valid(planRequest.Command, planRequest.VolumeManagement)) throw new ArgumentException("Invalid volume plan.");
        var binding = latestStatus is null ? null : CurrentBinding(planRequest, latestStatus());
        var plan = await send(planRequest).ConfigureAwait(true);
        ControlOperationReply.RequireSuccess(planRequest, plan);
        if (!plan.Success || plan.VolumeManagementReport is not { ValueKind: JsonValueKind.Object } report ||
            plan.Fingerprint != ApfsOperationFingerprint.Compute(planRequest) ||
            !PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, plan, plan.OperationId, 2)).IsValid)
            throw new IOException(plan.Diagnostic ?? "No prepared native volume plan was returned.");
        var token = report.GetProperty("confirmationToken").GetString();
        var p = planRequest.VolumeManagement! with { Token = token };
        if (!VolumeManagementParameters.Valid(ApfsControlCommands.VolumeManagementApply, p)) throw new IOException("Missing native token.");
        var changes = p.Kind switch {
            "delete" => "Delete this volume and its files.",
            "grow" or "shrink" => $"Capacity: {report.GetProperty("expectedBytes").GetString()} to {report.GetProperty("targetBytes").GetString()} bytes",
            "format" or "erase" => $"Replace the entire container and every volume.\r\nNew name: {p.Name}\r\nNew container: {report.GetProperty("newContainerUuid").GetString()}\r\nNew volume: {report.GetProperty("newVolumeUuid").GetString()}\r\nCase sensitive: {p.CaseSensitive}" +
                (p.Kind == "erase" ? "\r\nFree space is zeroed; the private recovery journal retains original bytes. This is not secure erasure." : ""),
            _ => $"Name: {p.Name}\r\nQuota: {report.GetProperty("quotaBlocks").GetString()} blocks\r\nReserve: {report.GetProperty("reserveBlocks").GetString()} blocks\r\nCase sensitive: {p.CaseSensitive}" };
        var details = $"Image: {planRequest.Target!.DeviceId}\r\nContainer: {report.GetProperty("containerUuid").GetString()}\r\nVolume: {report.GetProperty("volumeUuid").GetString()}\r\nObject: {report.GetProperty("volumeOid").GetString()}\r\nCheckpoint: {report.GetProperty("preXid").GetString()}\r\n{changes}\r\n\r\nApply this native plan?";
        var approved = confirm(details);
        if (approved && latestStatus is not null)
        {
            var changed = false;
            // Polling withdraws new-plan readiness while this prepared token is
            // pending. Service validates that exact intent when Apply is sent.
            try { changed = CurrentBinding(planRequest, latestStatus(), requirePlanReadiness: false) != binding; }
            catch (InvalidOperationException) { changed = true; }
            if (changed)
            {
                // The prepared token still owns resources even when its target
                // is stale. Cancel that exact token without applying the plan.
                var cancel = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"),
                    ApfsControlCommands.VolumeManagementCancel, planRequest.Target,
                    ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80), VolumeManagement: p);
                try { ControlOperationReply.RequireSuccess(cancel, await send(cancel).ConfigureAwait(true)); }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("Image identity, membership or capability changed. " +
                        "Cancellation was not confirmed; refresh and check the pending plan before retrying.", ex);
                }
                throw new InvalidOperationException("Image identity, membership or capability changed. " +
                    "The prepared plan was cancelled. Review a new plan.");
            }
        }
        var command = approved ? ApfsControlCommands.VolumeManagementApply : ApfsControlCommands.VolumeManagementCancel;
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), command, planRequest.Target,
            ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80), VolumeManagement: p);
        var result = await send(request).ConfigureAwait(true);
        ControlOperationReply.RequireSuccess(request, result);
        return result;
    }

    private static string CurrentBinding(ControlOperationRequestPayload request, StatusChangedPayload status,
        bool requirePlanReadiness = true)
    {
        var target = request.Target ?? throw new InvalidOperationException("Missing image identity.");
        var rows = TopologyDashboard.Project(status).Where(n => n.Row is not null).Select(n => n.Row!)
            .Where(r => string.Equals(r.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                TopologyAdmission.SameUuid(r.CatalogContainerUuid, target.ContainerUuid)).ToArray();
        var resizeFormat = request.Command is ApfsControlCommands.VolumeResizePlan or ApfsControlCommands.VolumeFormatPlan;
        var devices = (status.ConnectedInventory ?? []).Where(d =>
            string.Equals(d.Device.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (rows.Length == 0 || devices.Length != 1 ||
            !status.ImageManagementMutationsEnabled || resizeFormat && !status.ImageResizeFormatEnabled ||
            devices[0].Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, target.ContainerUuid))
                .Any(v => v.IsEncrypted || v.RegisteredImage is not null || !CatalogMountPolicy.AllowsOrdinaryMount(v)) ||
            (status.MountedVolumes ?? []).Any(m => string.Equals(m.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase) ||
                TopologyAdmission.SameUuid(m.CatalogContainerUuid, target.ContainerUuid)) ||
            requirePlanReadiness && rows.Any(r => resizeFormat ? !r.CanPlanImageOperation(request.VolumeManagement!.Kind) : !r.CanManageTopologyImage) ||
            request.Command != ApfsControlCommands.VolumeCreatePlan && !SelectedControlTarget.Matches(status.ConnectedInventory!, target))
            throw new InvalidOperationException("Current image management identity or capability is unavailable. Refresh before acting.");
        return JsonSerializer.Serialize(new {
            Checkpoint = devices[0].Topology!.Snapshot.Containers.Single(c => TopologyAdmission.SameUuid(c.Uuid, target.ContainerUuid)).CheckpointXid,
            Targets = rows.OrderBy(DriveDashboardPresenter.RowIdentity, StringComparer.Ordinal).Select(r =>
                SelectedControlTarget.Create(devices[0], devices[0].Volumes.Single(v => v.VolumeId == r.VolumeId))).ToArray() });
    }
}
