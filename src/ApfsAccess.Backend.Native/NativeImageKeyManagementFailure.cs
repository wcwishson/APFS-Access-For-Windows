using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeImageKeyManagementBackend
{
    private sealed partial class Reservation
    {
        private IOException ObservationFailure(ImageKeyManagementRequest request, HostProcessGuardian guardian)
        {
            var failure = new IOException("Image observation did not finish. Inspect its recovery state before retrying.");
            failure.Data["NativeExitCode"] = exitCode;
            // The native Observe branch never receives credentials. Read only
            // its bounded refusal, bound to this exact retired process owner.
            try
            {
                using var file = Launch!.OpenReceipt();
                if (file.Length is <= 0 or > 16384) return failure;
                var envelope = JsonSerializer.Deserialize<ObservationRefusal>(file, json);
                if (envelope is null || envelope.SchemaVersion != 1 || !envelope.Refused ||
                    envelope.HostPid != guardian.ProcessId || envelope.HostCreationTimeFileTimeUtc != guardian.CreationTimeFileTimeUtc ||
                    envelope.ObservationId != request.OperationId || envelope.NativeExitStage != exitCode ||
                    string.IsNullOrEmpty(envelope.ErrorCode) || envelope.ErrorCode.Length > 4096) return failure;
                failure.Data["NativeObservationRefusal"] = envelope.ErrorCode;
            }
            catch (Exception detail) when (detail is IOException or JsonException or UnauthorizedAccessException) { }
            return failure;
        }
    }

    private sealed record ObservationRefusal(int SchemaVersion, uint HostPid, long HostCreationTimeFileTimeUtc,
        string ObservationId, int NativeExitStage, bool Refused, string ErrorCode);
}
