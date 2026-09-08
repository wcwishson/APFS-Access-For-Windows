namespace ApfsAccess.Ipc;

public sealed record DriveLetterPreferenceRequestPayload(
    string DeviceId, string VolumeId, string VolumeUuid, string Letter);
