namespace ApfsAccess.Core;

public interface IMountPolicy
{
    char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters);

    bool ShouldAutoMount(VolumeInfo volume);
}
