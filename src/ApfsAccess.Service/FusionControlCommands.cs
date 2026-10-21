using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class AgentControlCommandExecutor
{
    private async Task<OperationResultPayload> ExecuteFusionAsync(ControlOperationRequestPayload request,
        DateTime requested, DateTime started, CancellationToken token)
    {
        OperationResultPayload Fail(string message) => BuildResult(request, requested, started, false,
            ApfsOperationCodes.OperationFailed, "not-proven", diagnostic: message);
        try
        {
            if (request.Command == ApfsControlCommands.Eject)
                return await ExecuteEjectAsync(request, requested, started, token).ConfigureAwait(false);
            if (request.Target?.RegisteredFusion is not {} profile || !SelectedControlTarget.IsWellFormed(request.Target) ||
                (request.Command == ApfsControlCommands.RegisterFusion ? request.RequestedMode is not null : request.RequestedMode != ApfsControlModes.ReadWrite))
                return Fail("Choose an exact Fusion pair and an explicit read-write mount.");
            var generation = _worker.ReserveFusionCommand();
            if (request.Command == ApfsControlCommands.RegisterFusion)
            {
                await _worker.RegisterFusionImageAsync(profile, generation, token).ConfigureAwait(false);
                return BuildResult(request, requested, started, true, ApfsOperationCodes.OperationSucceeded, "registered",
                    diagnostic: "Fusion pair registered. Refresh and mount the selected volume.");
            }
            var result = await _worker.MountSelectedFusionAsync(request.Target, generation, token).ConfigureAwait(false);
            var probe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
            var matches = FindExactMounts(probe.Mounts, request.Target);
            var state = matches.Count == 1 ? matches[0] : null;
            var success = result.Success && probe.Succeeded && state is { MountReady: true, HostProcessId: > 0,
                AccessMode: MountAccessMode.ReadWrite, RecoveryActive: false, RuntimeWatermarksKnown: true } &&
                state.WalAcceptedSequence == state.WalApfsDurableSequence && state.WalAcceptedSequence == state.WalCleanupSequence;
            return BuildResult(request, requested, started, success, success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.OperationFailed,
                success ? "mounted-read-write" : "not-proven", requestedMode: ApfsControlModes.ReadWrite,
                effectiveMode: state is null ? null : ApfsControlModes.ReadWrite, mountProof: success ? "present" : "not-proven",
                ownershipProof: "not-applicable", durabilityProof: "not-applicable", diagnostic: result.Error ?? "Fusion exact pair owner admitted.");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { return Fail(e.Message); }
        finally
        {
            using var refresh = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await _worker.RefreshFusionStatusAsync(refresh.Token).ConfigureAwait(false); } catch { }
        }
    }
}
