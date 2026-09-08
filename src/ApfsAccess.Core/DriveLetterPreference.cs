namespace ApfsAccess.Core;

public sealed record DriveLetterPreference(
    string? VolumeUuid, string? PreferredLetter, string? ActualLetter,
    string State, string Text, string AllowedLetters, bool CanEdit);

public sealed record DriveLetterPreferenceResult(bool Success, string Code, string Message);
