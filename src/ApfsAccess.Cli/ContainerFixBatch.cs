using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal sealed record ContainerFixChild(string VolumeId, string VolumeName, ApfsControlTarget Target,
    string State, string Diagnostic, string? OperationId = null, string? Fingerprint = null, OperationResultPayload? Result = null);
internal sealed record ContainerFixBatchReport(string BatchId, bool DryRun, bool Success, int ExitCode,
    string Code, IReadOnlyList<ContainerFixChild> Volumes, string? Diagnostic = null)
{
    public bool OperationIssued => Volumes.Any(v => v.OperationId is not null);
}

internal static class ContainerFixBatch
{
    internal const string Availability = "available: sequential existing per-volume Fix requests with complete original membership and source revalidation. " +
        "Repair offers stop the batch for explicit per-volume approval. Green status alone is not independent verification. Physical owner replacement requires refresh before remaining members.";
    private const string NoFixNeeded = "No Fix needed: current status is healthy; Fix and independent verification were not run for this member.";

    internal static async Task<ContainerFixBatchReport> RunAsync(ContainerControlOptions options,
        IContainerVerificationClient client, CancellationToken cancellationToken = default, DateTimeOffset? operationDeadlineUtc = null)
    {
        var end = DateTimeOffset.UtcNow + ContainerVerificationBatch.BatchTimeout;
        if (operationDeadlineUtc is { } supplied && supplied < end) end = supplied;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (end <= DateTimeOffset.UtcNow) deadline.Cancel(); else deadline.CancelAfter(end - DateTimeOffset.UtcNow);
        var token = deadline.Token;
        ContainerFixProof proof;
        try
        {
            token.ThrowIfCancellationRequested();
            var status = await client.ReadFreshStatusAsync(token).WaitAsync(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            proof = ContainerFixProof.CaptureForContainer(status, options.DeviceId, options.ContainerId);
        }
        catch (Exception ex)
        {
            return new(options.OperationId, options.DryRun, false, ex is OperationCanceledException ? 4 : ex is IOException ? 3 : 5,
                "container-fix-unavailable", [], ex.Message);
        }
        var results = new List<ContainerFixChild>(); string? stopped = null; var exit = 0;
        for (var i = 0; i < proof.Volumes.Count; ++i)
        {
            var volume = proof.Volumes[i]; var target = proof.Targets[i];
            if (options.DryRun || stopped is not null)
            {
                results.Add(new(volume.VolumeId, volume.VolumeName, target, "NotAttempted", stopped ??
                    (proof.IsHealthy(i) ? "Dry run: " + NoFixNeeded : proof.NeedsFix(i) ? "Dry run: eligible exact target; no Fix issued." :
                        "Dry run: member is busy or ineligible for Fix; no operation issued.")));
                continue;
            }
            using var childDeadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            childDeadline.CancelAfter(ContainerVerificationBatch.ChildTimeout);
            var childToken = childDeadline.Token;
            ControlOperationRequestPayload request;
            try
            {
                var current = await client.ReadFreshStatusAsync(childToken).WaitAsync(childToken).ConfigureAwait(false);
                childToken.ThrowIfCancellationRequested();
                proof = proof.Revalidate(current);
                if (proof.IsHealthy(i))
                { proof.AcknowledgeHealthy(i); results.Add(new(volume.VolumeId, volume.VolumeName, target, "NoFixNeeded", NoFixNeeded)); continue; }
                if (!proof.NeedsFix(i)) throw new InvalidOperationException("The member is busy or ineligible for Fix. Refresh before retrying.");
                _ = BoundContainerActions.RequireBatch(current, proof.Targets, ApfsTopologyAction.Repair);
                var expiry = DateTimeOffset.UtcNow + ContainerVerificationBatch.ChildTimeout;
                if (expiry > end) expiry = end;
                string childId;
                do { childId = Guid.NewGuid().ToString("D"); } while (childId == options.OperationId || results.Any(r => r.OperationId == childId));
                request = new(childId, ApfsControlCommands.Fix, target, ExpiresAtUtc: expiry.UtcDateTime);
                if (!PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request,
                    request.OperationId, PipeSchemaVersions.Schema2)).IsValid) throw new InvalidOperationException("Invalid exact Fix request.");
                childToken.ThrowIfCancellationRequested();
            }
            catch (Exception ex)
            {
                stopped = ex.Message; exit = ex is OperationCanceledException ? 4 : 5;
                results.Add(new(volume.VolumeId, volume.VolumeName, target, "NotAttempted", stopped)); continue;
            }
            OperationResultPayload? result = null; var acknowledged = false;
            try
            {
                // The shared transport sends this existing command; no container IPC or approval is minted.
                result = await client.VerifyAsync(request, childToken).WaitAsync(childToken).ConfigureAwait(false);
                childToken.ThrowIfCancellationRequested();
                ContainerFixProof.ValidateReply(request, result);
                if (result.ImageRepairOffer is { } offer)
                {
                    if (offer.ExpiresAtUtc <= DateTime.UtcNow) throw new InvalidOperationException("The returned repair offer has expired.");
                    stopped = "Repair approval required. Review the returned offer and use per-volume fix --approve-image-repair PLAN_ID. No repair was approved.";
                    exit = 5;
                    results.Add(new(volume.VolumeId, volume.VolumeName, target, "RequiresApproval", stopped,
                        request.OperationId, ApfsOperationFingerprint.Compute(request), result)); continue;
                }
                if (!result.Success || result.State != ApfsOperationStates.Succeeded || result.FinalStatus != "healthy-rw")
                    throw new InvalidOperationException(result.Diagnostic ?? "Fix did not reach confirmed healthy completion.");
                var current = await client.ReadFreshStatusAsync(childToken).WaitAsync(childToken).ConfigureAwait(false);
                for (var attempt = 0; !ContainerFixProof.HasHealthyOwner(current, target) && attempt < 20; ++attempt)
                {
                    await Task.Delay(100, childToken).ConfigureAwait(false);
                    current = await client.ReadFreshStatusAsync(childToken).WaitAsync(childToken).ConfigureAwait(false);
                }
                childToken.ThrowIfCancellationRequested();
                if (!ContainerFixProof.HasHealthyOwner(current, target))
                    throw new InvalidOperationException("The acknowledged Fix has no current healthy owner.");
                acknowledged = true;
                var after = proof.AfterCompletedFix(current, i, out var canContinue, out var stopReason);
                results.Add(new(volume.VolumeId, volume.VolumeName, target, "Completed", result.Diagnostic ?? "Per-volume Fix completed.",
                    request.OperationId, ApfsOperationFingerprint.Compute(request), result));
                if (canContinue) proof = after;
                else { stopped = stopReason; exit = 5; }
            }
            catch (Exception ex)
            {
                if (acknowledged)
                {
                    stopped = "The service completed the selected Fix, but the original cohort is incomplete. " + ex.Message;
                    exit = 5;
                    results.Add(new(volume.VolumeId, volume.VolumeName, target, "Completed", result!.Diagnostic ?? "Per-volume Fix completed.",
                        request.OperationId, ApfsOperationFingerprint.Compute(request), result));
                    continue;
                }
                if (ex is OperationCanceledException)
                {
                    using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    try { await client.CancelAsync(request.OperationId, cancel.Token).WaitAsync(cancel.Token).ConfigureAwait(false); }
                    catch (Exception) { /* A cancellation request does not prove the child's outcome. */ }
                }
                stopped = "Stopped after a failed or unconfirmed child. Query its operation ID before retrying.";
                exit = ex is OperationCanceledException ? 4 : 5;
                results.Add(new(volume.VolumeId, volume.VolumeName, target, "Failed", ex.Message,
                    request.OperationId, ApfsOperationFingerprint.Compute(request), result));
            }
        }
        if (stopped is null)
        {
            try
            {
                token.ThrowIfCancellationRequested();
                if (!options.DryRun)
                {
                    var current = await client.ReadFreshStatusAsync(token).WaitAsync(token).ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                    proof.RevalidateForCompletion(current);
                }
                token.ThrowIfCancellationRequested();
            }
            catch (Exception ex)
            {
                stopped = ex is OperationCanceledException ? "Container Fix cancelled before aggregate completion." :
                    "Final original cohort is incomplete. " + ex.Message;
                exit = ex is OperationCanceledException ? 4 : 5;
            }
        }
        var success = stopped is null && (options.DryRun || results.Count > 0 && results.All(r => r.State is "Completed" or "NoFixNeeded"));
        return new(options.OperationId, options.DryRun, success, success ? 0 : exit,
            success ? options.DryRun ? "inspection-complete" : "container-fix-complete" : "container-fix-incomplete", results.AsReadOnly(), stopped);
    }

    internal static int Emit(ContainerFixBatchReport report)
    {
        Console.WriteLine(JsonSerializer.Serialize(new {
            schemaVersion = PipeSchemaVersions.Schema2, command = "container-fix", operationId = report.BatchId, batchId = report.BatchId,
            report.Success, report.ExitCode, report.Code, report.DryRun, inspectionOnly = report.DryRun, report.OperationIssued,
            execution = "client-batch", childCommand = ApfsControlCommands.Fix, atomicContainerRepair = false,
            attempted = report.Volumes.Count(v => v.OperationId is not null), completed = report.Volumes.Count(v => v.State == "Completed"),
            noFixNeeded = report.Volumes.Count(v => v.State == "NoFixNeeded"), failed = report.Volumes.Count(v => v.State == "Failed"),
            requiresApproval = report.Volumes.Count(v => v.State == "RequiresApproval"), notAttempted = report.Volumes.Count(v => v.State == "NotAttempted"),
            scope = Availability, report.Volumes, report.Diagnostic
        }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true }));
        return report.ExitCode;
    }
}
