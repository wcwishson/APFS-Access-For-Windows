namespace ApfsAccess.Core;

public sealed class FirstFreeMountPolicy : IMountPolicy
{
    private static readonly char[] DefaultCandidateLetters = Enumerable.Range('D', ('Z' - 'D') + 1)
        .Select(value => (char)value)
        .ToArray();

    private readonly char[] _candidateLetters;

    public FirstFreeMountPolicy()
        : this(null)
    {
    }

    public FirstFreeMountPolicy(IEnumerable<string>? candidateLetters)
    {
        _candidateLetters = NormalizeCandidates(candidateLetters);
    }

    public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters)
    {
        ArgumentNullException.ThrowIfNull(volume);
        ArgumentNullException.ThrowIfNull(usedLetters);

        foreach (var candidate in _candidateLetters)
        {
            if (!usedLetters.Contains(candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException(
            $"No available drive letters remain in configured pool '{new string(_candidateLetters)}'."
        );
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
