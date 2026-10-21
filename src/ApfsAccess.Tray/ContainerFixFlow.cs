using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

internal enum ContainerFixState { Completed, NoFixNeeded, Failed, Declined, NotAttempted }
internal sealed record ContainerFixMemberResult(DriveDashboardRow Row, ContainerFixState State, string Diagnostic);
internal sealed record ContainerFixReport(IReadOnlyList<ContainerFixMemberResult> Members, string? StopReason = null)
{
    public bool Success => StopReason is null && Members.Count > 0 && Members.All(m => m.State is ContainerFixState.Completed or ContainerFixState.NoFixNeeded);
    public string Summary => $"Container Fix{(StopReason is null ? string.Empty : " stopped")}: {Members.Count(m => m.State == ContainerFixState.Completed)}/{Members.Count} completed, " +
        $"{Members.Count(m => m.State == ContainerFixState.NoFixNeeded)} no Fix needed (status only, not verified), " +
        $"{Members.Count(m => m.State == ContainerFixState.Failed)} failed, {Members.Count(m => m.State == ContainerFixState.Declined)} declined, " +
        $"{Members.Count(m => m.State == ContainerFixState.NotAttempted)} not attempted." +
        (StopReason is null ? string.Empty : " " + StopReason) +
        (Members.FirstOrDefault(m => m.State != ContainerFixState.Completed && m.Diagnostic != StopReason) is { } detail ? " " + detail.Diagnostic : string.Empty);
}

internal sealed class ContainerFixFlow
{
    private readonly DriveDashboardRow[] rows;
    private readonly ContainerFixProof initial;
    internal ApfsActionCapability Capability { get; }
    private ContainerFixFlow(StatusChangedPayload status, DriveDashboardRow[] selected)
    {
        rows = selected;
        if (!DriveDashboardPresenter.TryResolveContainerTarget(rows, out var device, out var container))
            throw new InvalidOperationException("Select the complete original container. Refresh before retrying.");
        initial = ContainerFixProof.CaptureForContainer(status, device, container);
        if (rows.Length != initial.Volumes.Count || rows.Select(r => r.VolumeId).Distinct(StringComparer.Ordinal).Count() != rows.Length ||
            !rows.Select(r => r.VolumeId).ToHashSet(StringComparer.Ordinal).SetEquals(initial.Volumes.Select(v => v.VolumeId)))
            throw new InvalidOperationException("Original container membership changed. Refresh before retrying.");
        foreach (var row in rows)
        {
            var fresh = FreshRow(status, row);
            if (row.CatalogVolumeId != fresh.CatalogVolumeId || row.RecoveryIdentity != fresh.RecoveryIdentity ||
                row.IsMounted != fresh.IsMounted || row.CanFix != fresh.CanFix || row.SnapshotScope != fresh.SnapshotScope)
                throw new InvalidOperationException("The selected rows are stale. Refresh before retrying.");
        }
        if (!rows.Any(DriveDashboardPresenter.CanFixVolume)) throw new InvalidOperationException("No eligible volumes need Fix.");
        Capability = BoundContainerActions.Require(status, initial.Targets, ApfsTopologyAction.Repair);
    }

    public static ContainerFixFlow Capture(StatusChangedPayload status, IReadOnlyList<DriveDashboardRow> rows) => new(status, rows.ToArray());
    private static DriveDashboardRow FreshRow(StatusChangedPayload status, DriveDashboardRow original)
        => TopologyDashboard.Project(status).Where(n => n.Row is not null).Select(n => n.Row!)
            .Single(r => DriveDashboardPresenter.RowIdentity(r) == DriveDashboardPresenter.RowIdentity(original));

    public async Task<ContainerFixReport> RunAsync(Func<StatusChangedPayload> latest,
        Func<ControlOperationRequestPayload, Task<OperationResultPayload>> send, Func<ImageRepairOffer, Task<bool>> confirm,
        CancellationToken cancellationToken = default)
    {
        var results = new List<ContainerFixMemberResult>(); var expected = initial;
        string? stopped = null;
        foreach (var selected in rows)
        {
            if (stopped is not null || cancellationToken.IsCancellationRequested)
            { results.Add(new(selected, ContainerFixState.NotAttempted, stopped ?? "Cancelled before dispatch.")); continue; }
            OperationResultPayload? acknowledged = null;
            try
            {
                var current = latest(); var fresh = expected.Revalidate(current);
                var index = Enumerable.Range(0, fresh.Volumes.Count).Single(i => fresh.Volumes[i].VolumeId == selected.VolumeId);
                var row = FreshRow(current, selected);
                if (fresh.IsHealthy(index))
                {
                    fresh.AcknowledgeHealthy(index); expected = fresh;
                    results.Add(new(row, ContainerFixState.NoFixNeeded, "Current status is healthy; Fix and independent verification were not run for this member."));
                    continue;
                }
                if (!fresh.NeedsFix(index)) throw new InvalidOperationException("The member is busy or ineligible for Fix. Refresh before retrying.");
                _ = BoundContainerActions.Require(current, fresh.Targets, ApfsTopologyAction.Repair);
                var request = DriveDashboardPresenter.CreateSelectedRequest(current, row, ApfsControlCommands.Fix);
                Task<OperationResultPayload> Send(ControlOperationRequestPayload child)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (child.ApprovedImageRepairPlanId is not null) fresh.RevalidateForApproval(latest());
                    return send(child);
                }
                async Task<bool> Confirm(ImageRepairOffer offer)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var approved = await confirm(offer).ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    return approved;
                }
                var result = await ImageRepairFixFlow.ExecuteAsync(request, Send, Confirm).ConfigureAwait(true);
                if (result is null)
                {
                    stopped = "Repair confirmation declined; no approval was sent.";
                    results.Add(new(selected, ContainerFixState.Declined, stopped)); continue;
                }
                if (cancellationToken.IsCancellationRequested || result.FinalStatus != "healthy-rw")
                    throw new InvalidOperationException("Fix completion is cancelled or unconfirmed.");
                // Status delivery can trail the terminal reply. This never retries Fix.
                current = latest();
                for (var attempt = 0; !ContainerFixProof.HasHealthyOwner(current, request.Target!) && attempt < 20; ++attempt)
                { await Task.Delay(100, cancellationToken).ConfigureAwait(true); current = latest(); }
                if (!ContainerFixProof.HasHealthyOwner(current, request.Target!))
                    throw new InvalidOperationException("The acknowledged Fix has no current healthy owner.");
                acknowledged = result;
                var after = fresh.AfterCompletedFix(current, index, out var canContinue, out var stopReason);
                results.Add(new(FreshRow(current, selected), ContainerFixState.Completed, result.Diagnostic ?? "Per-volume Fix completed."));
                if (canContinue) expected = after;
                else stopped = stopReason;
            }
            catch (Exception ex)
            {
                if (acknowledged is not null)
                {
                    stopped = "The service completed the selected Fix, but the original cohort is incomplete. " + ex.Message;
                    results.Add(new(selected, ContainerFixState.Completed, acknowledged.Diagnostic ?? "Per-volume Fix completed."));
                    continue;
                }
                stopped = "Stopped after a failed or unconfirmed operation.";
                results.Add(new(selected, ContainerFixState.Failed, ex.Message));
            }
        }
        if (stopped is null)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var current = latest();
                cancellationToken.ThrowIfCancellationRequested();
                expected.RevalidateForCompletion(current);
                cancellationToken.ThrowIfCancellationRequested();
            }
            catch (OperationCanceledException) { stopped = "Container Fix cancelled before aggregate completion."; }
            catch (Exception ex) { stopped = "Final original cohort is incomplete. " + ex.Message; }
        }
        return new(results.AsReadOnly(), stopped);
    }
}
