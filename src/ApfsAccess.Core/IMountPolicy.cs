namespace ApfsAccess.Core;

public interface IMountPolicy
{
    // Called with the complete, unfiltered discovery snapshot before selecting letters.
    void UpdateDiscovery(IReadOnlyList<VolumeInfo> volumes) { }

    char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters);

    bool RequiresDriveLetterStorage => false;

    // Capture identity at admission; execute storage outside the mount lock.
    Func<CancellationToken, char> PrepareDriveLetterSelection(VolumeInfo volume, IReadOnlySet<char> usedLetters)
        => token => { token.ThrowIfCancellationRequested(); return SelectDriveLetter(volume, usedLetters); };

    DriveLetterPreference? GetDriveLetterPreference(VolumeInfo volume, char? actualLetter) => null;

    // Must not perform storage I/O or wait for settings access.
    DriveLetterPreference? GetCachedDriveLetterPreference(VolumeInfo volume, char? actualLetter) => null;

    DriveLetterPreferenceResult SetDriveLetterPreference(VolumeInfo volume, Guid expectedUuid, char letter)
        => new(false, "preference-unavailable", "Drive-letter preferences are unavailable.");

    // Capture validated identity without I/O while the caller admits its snapshot.
    // Execute the returned operation outside the mount lock. Legacy policies keep
    // their existing setter; production captures the UUID before leaving admission.
    Func<CancellationToken, DriveLetterPreferenceResult> PrepareDriveLetterPreference(VolumeInfo volume, Guid expectedUuid, char letter)
        => token =>
        {
            token.ThrowIfCancellationRequested();
            return SetDriveLetterPreference(volume, expectedUuid, letter);
        };

    bool ShouldAutoMount(VolumeInfo volume);
}
