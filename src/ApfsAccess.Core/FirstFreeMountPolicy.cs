using System.Collections.Concurrent;

namespace ApfsAccess.Core;

public sealed class FirstFreeMountPolicy : IMountPolicy
{
    private static readonly char[] DefaultCandidateLetters = Enumerable.Range('D', ('Z' - 'D') + 1)
        .Select(value => (char)value)
        .ToArray();

    private readonly char[] _candidateLetters;
    private readonly VolumeDriveLetterAssignments? _assignments;

    public FirstFreeMountPolicy()
        : this(null)
    {
    }

    public FirstFreeMountPolicy(IEnumerable<string>? candidateLetters, VolumeDriveLetterAssignments? assignments = null)
    {
        _candidateLetters = NormalizeCandidates(candidateLetters);
        _assignments = assignments;
    }

    public void UpdateDiscovery(IReadOnlyList<VolumeInfo> volumes)
        => _assignments?.UpdateDiscovery(volumes);

    public bool RequiresDriveLetterStorage => _assignments is not null;

    public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters)
        => PrepareDriveLetterSelection(volume, usedLetters)(CancellationToken.None);

    public Func<CancellationToken, char> PrepareDriveLetterSelection(VolumeInfo volume, IReadOnlySet<char> usedLetters)
    {
        ArgumentNullException.ThrowIfNull(volume);
        ArgumentNullException.ThrowIfNull(usedLetters);

        var occupied = usedLetters.Select(char.ToUpperInvariant).ToHashSet();
        var uuid = _assignments is not null && _assignments.TryResolveUuid(volume, out var resolved) ? resolved : (Guid?)null;
        foreach (var candidate in _candidateLetters)
        {
            if (!occupied.Contains(candidate))
            {
                return token =>
                {
                    token.ThrowIfCancellationRequested();
                    var selected = uuid.HasValue ? _assignments!.Select(uuid.Value, _candidateLetters, occupied, candidate, token) : candidate;
                    if (uuid.HasValue && _assignments!.TryGetCachedPreference(uuid.Value, out var preferred))
                        _selections[uuid.Value] = (selected, preferred, preferred.HasValue && !_candidateLetters.Contains(preferred.Value)
                            ? "outside-pool" : preferred.HasValue && occupied.Contains(preferred.Value) ? "preference-occupied" : "preferred");
                    if (uuid.HasValue) _editedPreferences.TryRemove(uuid.Value, out _);
                    return selected;
                };
            }
        }

        throw new InvalidOperationException(
            $"No available drive letters remain in configured pool '{new string(_candidateLetters)}'."
        );
    }

    public DriveLetterPreference GetDriveLetterPreference(VolumeInfo volume, char? actualLetter)
        => GetDriveLetterPreference(volume, actualLetter, cached: false);

    public DriveLetterPreference GetCachedDriveLetterPreference(VolumeInfo volume, char? actualLetter)
        => GetDriveLetterPreference(volume, actualLetter, cached: true);

    private DriveLetterPreference GetDriveLetterPreference(VolumeInfo volume, char? actualLetter, bool cached)
    {
        var actual = actualLetter?.ToString();
        var allowed = new string(_candidateLetters);
        if (_assignments is null || !_assignments.TryResolveUuid(volume, out var uuid))
            return new(null, null, actual, "identity-unavailable", "Volume identity is stale or ambiguous.", allowed, false);
        char? saved;
        if (!(cached ? _assignments.TryGetCachedPreference(uuid, out saved) : _assignments.TryGetPreference(uuid, out saved)))
            return new(uuid.ToString("D"), null, actual, "storage-unavailable", "Saved letter unavailable. Try again.", allowed, true);
        var state = "preferred";
        var text = saved.HasValue ? $"Preferred {saved}:" : "No saved letter";
        if (saved.HasValue && actualLetter.HasValue && saved != actualLetter)
        {
            state = "temporary-assignment";
            text = $"Preferred {saved}:; using {actualLetter}: temporarily";
            if (_editedPreferences.ContainsKey(uuid))
            {
                state = "next-mount";
                text = $"Preferred {saved}:; applies on next mount";
            }
            else if (_selections.TryGetValue(uuid, out var selection) && selection.Actual == actualLetter)
            {
                state = selection.Preferred != saved ? "next-mount" : selection.Reason;
                text = state switch
                {
                    "next-mount" => $"Preferred {saved}:; applies on next mount",
                    "preference-occupied" => $"Preferred {saved}: occupied; using {actualLetter}: temporarily",
                    "outside-pool" => $"Preferred {saved}: outside letter pool; using {actualLetter}: temporarily",
                    _ => text
                };
            }
        }
        return new(uuid.ToString("D"), saved?.ToString(), actual, state, text, allowed, true);
    }

    private readonly ConcurrentDictionary<Guid, (char Actual, char? Preferred, string Reason)> _selections = new();
    private readonly ConcurrentDictionary<Guid, byte> _editedPreferences = new();

    public DriveLetterPreferenceResult SetDriveLetterPreference(VolumeInfo volume, Guid expectedUuid, char letter)
        => PrepareDriveLetterPreference(volume, expectedUuid, letter)(CancellationToken.None);

    public Func<CancellationToken, DriveLetterPreferenceResult> PrepareDriveLetterPreference(VolumeInfo volume, Guid expectedUuid, char letter)
    {
        letter = char.ToUpperInvariant(letter);
        if (!_candidateLetters.Contains(letter))
            return _ => new(false, "invalid-arguments", "Choose a letter from the configured letter pool.");
        if (_assignments is null || !_assignments.TryResolveUuid(volume, out var uuid) || uuid != expectedUuid)
            return _ => new(false, "ambiguous-target", "Volume identity is stale or ambiguous. Refresh and try again.");
        // This admission captures the actual UUID, never a routing ID to resolve later.
        return token =>
        {
            token.ThrowIfCancellationRequested();
            _assignments.TryGetPreference(uuid, out var previous, token);
            if (!_assignments.SetPreference(uuid, letter, token))
                return new(false, "preference-storage-failed", "Could not save the preferred letter. Try again.");
            // A cancellation after the atomic rename cannot undo a saved preference.
            if (previous != letter) _editedPreferences[uuid] = 0;
            return new(true, "ok", $"Preferred {letter}: saved. Applies on the next clean mount.");
        };
    }

    public bool ShouldAutoMount(VolumeInfo volume)
    {
        ArgumentNullException.ThrowIfNull(volume);
        return true;
    }

    private static char[] NormalizeCandidates(IEnumerable<string>? candidateLetters)
    {
        if (candidateLetters is null)
        {
            return DefaultCandidateLetters;
        }

        var normalized = candidateLetters
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => char.ToUpperInvariant(value[0]))
            .Where(static value => value is >= 'A' and <= 'Z')
            .Distinct()
            .ToArray();

        return normalized.Length == 0 ? DefaultCandidateLetters : normalized;
    }
}
