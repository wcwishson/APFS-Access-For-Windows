using ApfsAccess.Ipc;
using ApfsAccess.Core;

namespace ApfsAccess.Tray;

internal static class ControlOperationReply
{
    public static void RequireSuccess(ControlOperationRequestPayload request, OperationResultPayload result)
    {
        if (result.OperationId != request.OperationId || result.Command != request.Command || !SameReplyTarget(result.Target, request.Target) ||
            result.RequestedMode != request.RequestedMode || result.ExpiresAtUtc != request.ExpiresAtUtc ||
            result.Fingerprint != ApfsOperationFingerprint.Compute(request) ||
            !PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result,
                result.OperationId, PipeSchemaVersions.Schema2)).IsValid)
            throw new IOException("Service returned an invalid operation result. Refresh before retrying.");
        if (!result.Success || result.State != ApfsOperationStates.Succeeded)
            throw new IOException(result.Diagnostic ?? result.FinalStatus ?? "The operation did not complete.");
    }

    internal static bool SameReplyTarget(ApfsControlTarget? actual, ApfsControlTarget? expected)
    {
        if (actual == expected) return true;
        if (actual is null || expected is null) return false;
        if (actual.DeviceId != expected.DeviceId &&
            (!string.Equals(actual.DeviceId, expected.DeviceId, StringComparison.OrdinalIgnoreCase) ||
             !IsWindowsDevicePath(actual.DeviceId) || !IsWindowsDevicePath(expected.DeviceId))) return false;
        var normalized = actual with { DeviceId = expected.DeviceId };
        if (actual.RegisteredFusion is { } fusion && expected.RegisteredFusion is { } expectedFusion)
        {
            if (fusion.Members is null || expectedFusion.Members is null ||
                !fusion.Members.SequenceEqual(expectedFusion.Members)) return false;
            normalized = normalized with { RegisteredFusion = fusion with { Members = expectedFusion.Members } };
        }
        return normalized == expected;
    }

    private static bool IsWindowsDevicePath(string path)
        => VolumeTopologyProfile.LocalPath(path) || VolumePhysicalBinding.IsDevicePath(path);
}
