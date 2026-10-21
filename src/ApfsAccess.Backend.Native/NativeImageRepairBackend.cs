using ApfsAccess.Core;
using System.Text.Json;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsBackend : IImageRepairBackend
{
    public async Task<ImageRepairNativeResult> RunImageRepairAsync(ImageRepairInvocation request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        using var operation = AcquireLifecycleOperationLease();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, _disposeCts.Token);
        await _discoveryGate.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                RequireManagementQuotaOwnerAbsence_NoLock();
                if (!ImageRepairPersistence.LocalPath(request.JournalRoot) || request.JournalRoot != _options.ManagementJournalRoot)
                    throw new IOException("ImageRepairOriginalManagementRootChanged");
                ImageRepairPersistence.RequireFixedFileSystem(request.JournalRoot);
                ImageRepairPersistence.RequireFixedFileSystem(request.Scope.ImagePath);
                ImageRepairIntent? original = null;
                if (request.Approval is { } approval)
                {
                    original = ImageRepairPersistence.Read(ImageRepairPersistence.PathFor(request.JournalRoot, approval.PlanId), request.JournalRoot);
                    if (!original.Pending || original.Offer != approval || original.Offer.Scope != request.Scope ||
                        original.JournalPath != request.JournalPath || original.EvidenceDirectory != request.EvidenceDirectory)
                        throw new IOException("ImageRepairOriginalAcceptedLineageRequired");
                }
                NativeManagementJournalAdmission.RequireRepairImage(request, original);
                var scope = request.Scope;
                var native = new ApfsVolumeRepairRequest(scope.ImagePath, scope.ContainerId, scope.VolumeUuid,
                    scope.VolumeObjectId, scope.CheckpointXid, scope.StoreOffsetBytes, scope.StoreSizeBytes,
                    request.JournalPath, request.EvidenceDirectory, request.Approval?.ExpectedCount ?? "", request.Approval is not null)
                {
                    ApprovalMode = NativeApfsVolumeRepair.ExactSourceApprovalMode,
                    ApprovedSourceIdentity = request.Approval?.SourceIdentity ?? "",
                    ApprovedSourceSha256 = request.Approval?.SourceSha256 ?? "",
                };
                var result = await Task.Run(() => new NativeApfsVolumeRepair().Repair(native, linked.Token), linked.Token).ConfigureAwait(false);
                var report = result.Report;
                if (request.Approval is null && result.NativeExitCode == 3 &&
                    !ImageRepairPersistence.JournalUnaccepted(request.JournalPath, request.JournalRoot))
                    throw new IOException("ImageRepairDryPlanAcceptedJournalUnexpected");
                var source = report.GetProperty("source");
                var plan = report.GetProperty("plan");
                var post = report.GetProperty("postVerify");
                return new(report.GetProperty("code").GetString()!, result.NativeExitCode,
                    source.ValueKind == JsonValueKind.Object ? source.GetProperty("identity").GetString() : null,
                    source.ValueKind == JsonValueKind.Object ? source.GetProperty("sha256").GetString() : null,
                    plan.ValueKind == JsonValueKind.Object ? plan.GetProperty("expectedCount").GetRawText() : null,
                    report.GetProperty("replayed").GetBoolean(), post.ValueKind == JsonValueKind.Object &&
                    post.GetProperty("outcome").GetInt32() == 1 && post.GetProperty("findings").GetUInt64() == 0, report.Clone());
            }
            finally { _gate.Release(); }
        }
        finally { _discoveryGate.Release(); }
    }
}
