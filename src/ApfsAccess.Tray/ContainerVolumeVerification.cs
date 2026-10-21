using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public enum ContainerVolumeVerificationState { Verified, Failed, NotAttempted }

public sealed record ContainerVolumeVerificationResult(DriveDashboardRow Volume,
    ContainerVolumeVerificationState State, string Diagnostic);

public sealed record ContainerVolumeVerificationReport(IReadOnlyList<ContainerVolumeVerificationResult> Volumes)
{
    public bool Success => Volumes.Count > 0 && Volumes.All(v => v.State == ContainerVolumeVerificationState.Verified);
    public string Summary => $"Verify volumes: {Volumes.Count(v => v.State == ContainerVolumeVerificationState.Verified)}/{Volumes.Count} verified, " +
        $"{Volumes.Count(v => v.State == ContainerVolumeVerificationState.Failed)} failed, " +
        $"{Volumes.Count(v => v.State == ContainerVolumeVerificationState.NotAttempted)} not attempted. {ContainerVolumeVerification.Scope}";
    public string Details => Summary + "\r\n\r\n" + string.Join("\r\n", Volumes.Select(v =>
        $"{v.Volume.VolumeName} [{v.Volume.VolumeId}]: {v.State}. {v.Diagnostic}"));
}

// A client batch of existing exact VolumeVerify requests, never a container IPC command.
public sealed class ContainerVolumeVerification
{
    public const string Scope = ContainerVerificationProof.Scope;
    private sealed record Member(DriveDashboardRow Row, ApfsControlTarget Target);
    private readonly Member[] _members;
    private readonly ContainerVerificationProof _proof;
    public IReadOnlyList<DriveDashboardRow> Rows { get; }
    public ApfsActionCapability Capability { get; }

    private ContainerVolumeVerification(StatusChangedPayload current, Member[] members)
    {
        _members = members;
        _proof = ContainerVerificationProof.Capture(current, members.Select(m => m.Target).ToArray());
        Capability = BoundContainerActions.Require(current, _proof.Targets, ApfsTopologyAction.Verify);
        Rows = Array.AsReadOnly(members.Select(m => m.Row).ToArray());
    }

    public static ContainerVolumeVerification Capture(StatusChangedPayload current, IReadOnlyList<DriveDashboardRow> rows)
        => new(current, Resolve(current, rows));

    public static bool TryCapture(StatusChangedPayload current, IReadOnlyList<DriveDashboardRow> rows,
        out ContainerVolumeVerification? selection, out string reason)
    {
        try { selection = Capture(current, rows); reason = selection.Capability.Reason + " " + Scope; return true; }
        catch (InvalidOperationException ex) { selection = null; reason = ex.Message; return false; }
    }

    private static InvalidOperationException Changed(string detail)
        => new($"Verify volumes unavailable: {detail} Refresh before acting.");

    private static Member[] Resolve(StatusChangedPayload current, IReadOnlyList<DriveDashboardRow> rows)
    {
        if (!TopologyStatusProjection.IsBounded(current) || current.InventoryGeneration is not > 0 ||
            !DriveDashboardPresenter.ContainerVerifyAvailable(rows) ||
            !DriveDashboardPresenter.TryResolveContainerTarget(rows, out var deviceId, out var containerUuid))
            throw Changed("Every member needs a unique eligible per-volume target and current topology.");
        var inventory = current.ConnectedInventory ?? [];
        var projected = TopologyDashboard.Project(current).Where(n => n.Row is not null).Select(n => n.Row!).ToArray();
        var result = new List<Member>();
        foreach (var selected in rows)
        {
            var matches = projected.Where(r => DriveDashboardPresenter.RowIdentity(r) == DriveDashboardPresenter.RowIdentity(selected)).ToArray();
            if (matches.Length != 1) throw Changed("A selected member is missing or duplicated.");
            var row = matches[0];
            if (row.CatalogVolumeId != selected.CatalogVolumeId ||
                row.RecoveryIdentity != selected.RecoveryIdentity || row.IsMounted != selected.IsMounted ||
                row.CanVerifyLive != selected.CanVerifyLive || row.CanVerifyOffline != selected.CanVerifyOffline ||
                !DriveDashboardPresenter.ContainerVerifyAvailable([row]))
                throw Changed("A member identity or verification capability changed.");
            var request = DriveDashboardPresenter.CreateSelectedRequest(current, row, ApfsControlCommands.VolumeVerify);
            if (request.Target is null || !SelectedControlTarget.Matches(inventory, request.Target))
                throw Changed("A selected routing identity is ambiguous.");
            result.Add(new(row, request.Target));
        }
        return result.ToArray();
    }

    private Member[] ResolveCurrent(StatusChangedPayload current)
    {
        var fresh = Resolve(current, Rows);
        _proof.Revalidate(current);
        _ = BoundContainerActions.Require(current, _proof.Targets, ApfsTopologyAction.Verify);
        for (var i = 0; i < fresh.Length; i++)
            if (fresh[i].Target != _members[i].Target)
                throw Changed("A member observation, retained owner or verification scope changed.");
        return fresh;
    }

    public async Task<ContainerVolumeVerificationReport> RunAsync(Func<StatusChangedPayload> latestStatus,
        Func<ControlOperationRequestPayload, Task<OperationResultPayload>> sendAsync)
    {
        var results = new List<ContainerVolumeVerificationResult>();
        string? stopped = null;
        foreach (var selected in Rows)
        {
            if (stopped is not null)
            {
                results.Add(new(selected, ContainerVolumeVerificationState.NotAttempted, stopped));
                continue;
            }
            ControlOperationRequestPayload request;
            try
            {
                // Re-resolve every member, including completed ones, immediately
                // before each child. No await separates this check from dispatch.
                var current = latestStatus();
                _ = ResolveCurrent(current);
                request = DriveDashboardPresenter.CreateSelectedRequest(current, selected, ApfsControlCommands.VolumeVerify);
            }
            catch (InvalidOperationException ex)
            {
                stopped = ex.Message;
                results.Add(new(selected, ContainerVolumeVerificationState.NotAttempted, stopped));
                continue;
            }
            try
            {
                var result = await sendAsync(request).ConfigureAwait(true);
                ContainerVerificationProof.RequireVerifiedReply(request, result);
                results.Add(new(selected, ContainerVolumeVerificationState.Verified, result.Diagnostic ?? "Covered current metadata verified."));
            }
            catch (Exception ex)
            {
                // A transport failure may leave the service result unknown. Stop;
                // never silently retry it or report later children as verified.
                stopped = "Stopped after a failed or unconfirmed child operation. Refresh before retrying.";
                results.Add(new(selected, ContainerVolumeVerificationState.Failed, ex.Message));
            }
        }
        return new(results.AsReadOnly());
    }
}
