using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

internal static class ImageRepairFixFlow
{
    internal static async Task<OperationResultPayload?> ExecuteAsync(
        ControlOperationRequestPayload request,
        Func<ControlOperationRequestPayload, Task<OperationResultPayload>> send,
        Func<ImageRepairOffer, Task<bool>> confirm,
        Func<DateTime>? clock = null)
    {
        if (request.Command != ApfsControlCommands.Fix || request.ApprovedImageRepairPlanId is not null)
            throw new InvalidOperationException("Fix must inspect the volume before requesting repair approval.");
        clock ??= () => DateTime.UtcNow;
        var result = await send(request).ConfigureAwait(false);
        ValidateReply(request, result);
        if (result.ImageRepairOffer is null)
        {
            if (!result.Success) throw new InvalidOperationException(result.Diagnostic ?? "Fix did not complete.");
            return result;
        }
        ValidateOffer(request, result, clock());
        if (!await confirm(result.ImageRepairOffer).ConfigureAwait(false)) return null;
        var now = clock();
        ValidateOffer(request, result, now);
        var approved = request with
        {
            OperationId = Guid.NewGuid().ToString("D"),
            ExpiresAtUtc = new[] { now.AddMinutes(2), result.ImageRepairOffer.ExpiresAtUtc }.Min(),
            ApprovedImageRepairPlanId = result.ImageRepairOffer.PlanId,
        };
        var terminal = await send(approved).ConfigureAwait(false);
        ValidateReply(approved, terminal);
        if (!terminal.Success || terminal.FinalStatus != "healthy-rw" || terminal.ImageRepairOffer is not null ||
            terminal.ApprovedImageRepairPlanId != approved.ApprovedImageRepairPlanId ||
            terminal.ImageRepairReceipt is not { State: "repaired", NativePostVerifyComplete: true } receipt ||
            receipt.Binding != result.ImageRepairOffer)
            throw new InvalidOperationException(terminal.Diagnostic ?? "Repair and final mount verification did not complete.");
        return terminal;
    }

    private static void ValidateOffer(ControlOperationRequestPayload request, OperationResultPayload result, DateTime now)
    {
        var offer = result.ImageRepairOffer;
        if (now.Kind != DateTimeKind.Utc || request.Target is not { RegisteredImage: null } target ||
            !ImageRepairPersistence.ValidOffer(offer) || offer!.ExpiresAtUtc <= now ||
            offer.ExpiresAtUtc > now.AddMinutes(5) || result.ApprovedImageRepairPlanId is not null || result.Success ||
            result.State != ApfsOperationStates.Failed || result.Code != ApfsOperationCodes.BlockedRecovery ||
            result.FinalStatus != "repair-confirmation-required" ||
            !string.Equals(target.DeviceId, offer.Scope.ImagePath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(target.VolumeId, "apfs-vol:" + offer.Scope.ContainerId[15..] + ":" + offer.Scope.VolumeObjectId,
                StringComparison.OrdinalIgnoreCase) ||
            target.RecoveryIdentity is not null && target.RecoveryIdentity != offer.RecoveryIdentity ||
            target.ObservationContract is not null && target.ObservationContract != offer.ObservationContract ||
            target.ContainerUuid is not null && !TopologyAdmission.SameUuid(target.ContainerUuid, offer.Scope.ContainerId[15..]) ||
            target.VolumeUuid is not null && !TopologyAdmission.SameUuid(target.VolumeUuid, offer.Scope.VolumeUuid) ||
            target.VolumeObjectId is not null && target.VolumeObjectId.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) != offer.Scope.VolumeObjectId)
            throw new InvalidOperationException("The repair plan is stale or does not match this volume. Refresh and run Fix again.");
    }

    private static void ValidateReply(ControlOperationRequestPayload request, OperationResultPayload result)
    {
        if (result.OperationId != request.OperationId || result.Command != request.Command || !ControlOperationReply.SameReplyTarget(result.Target, request.Target) ||
            result.ExpiresAtUtc != request.ExpiresAtUtc || result.RequestedMode != request.RequestedMode ||
            result.ApprovedImageRepairPlanId != request.ApprovedImageRepairPlanId ||
            result.Fingerprint != ApfsOperationFingerprint.Compute(request))
            throw new InvalidOperationException("The repair response does not match the requested operation. Refresh before retrying.");
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, result.OperationId, PipeSchemaVersions.Schema2);
        if (!PipeMessageCodec.Validate(envelope).IsValid)
            throw new InvalidOperationException("The service returned invalid repair evidence. Refresh and run Fix again.");
    }

    internal static string ConfirmationText(ImageRepairOffer offer)
        => "APFS Access found a file-count mismatch and can correct the count in this volume's records.\r\n\r\n" +
            $"Image: {offer.Scope.ImagePath}\r\nCorrect file count: {offer.ExpectedCount}\r\n\r\nApply this repair?";
}
