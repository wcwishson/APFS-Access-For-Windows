using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class FirstFreeMountPolicyTests
{
    private static readonly VolumeInfo SampleVolume = new("vol-1", "dev-1", "Sample", true, false, true, @"\\.\PhysicalDrive1\Ufsd_Volumes\Sample");

    [Fact]
    public void SelectDriveLetter_UsesConfiguredPool()
    {
        var policy = new FirstFreeMountPolicy(["P", "Q", "R"]);
        var used = new HashSet<char> { 'P', 'Q' };

        var letter = policy.SelectDriveLetter(SampleVolume, used);

        Assert.Equal('R', letter);
    }

    [Fact]
    public void SelectDriveLetter_ThrowsWhenNoLettersRemainInPool()
    {
        var policy = new FirstFreeMountPolicy(["X"]);
        var used = new HashSet<char> { 'X' };

        Assert.Throws<InvalidOperationException>(() => policy.SelectDriveLetter(SampleVolume, used));
    }

    [Fact]
    public void ShouldAutoMount_ReturnsTrueForAnyVolume()
    {
        var policy = new FirstFreeMountPolicy();

        var should = policy.ShouldAutoMount(SampleVolume);

        Assert.True(should);
    }
}
