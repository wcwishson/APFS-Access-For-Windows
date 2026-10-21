using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class FirstFreeMountPolicyTests
{
    private static readonly VolumeInfo SampleVolume = new("vol-1", "dev-1", "Sample", true, false, true, @"\\.\PhysicalDrive1\ApfsAccess_Volumes\Sample");

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
    public void SelectDriveLetter_NormalizesOccupiedLettersWithoutPersistence()
    {
        var policy = new FirstFreeMountPolicy(["p", "Q"]);
        Assert.Equal('Q', policy.SelectDriveLetter(SampleVolume, new HashSet<char> { 'p' }));
        Assert.Throws<InvalidOperationException>(() => policy.SelectDriveLetter(SampleVolume, new HashSet<char> { 'p', 'q' }));
    }

    [Fact]
    public void ShouldAutoMount_ReturnsTrueForAnyVolume()
    {
        var policy = new FirstFreeMountPolicy();

        var should = policy.ShouldAutoMount(SampleVolume);

        Assert.True(should);
    }

    [Fact]
    public void ShouldAutoMount_AllowsOrdinaryEligibleDataVolume()
    {
        var policy = new FirstFreeMountPolicy();
        var data = SampleVolume with
        {
            CatalogDecision = ApfsCapabilityDecision.Writable,
            CatalogReasons = [],
            CatalogAutoMountAllowed = true,
        };

        Assert.True(policy.ShouldAutoMount(data));
    }

    [Theory]
    [InlineData("system")]
    [InlineData("recovery")]
    [InlineData("preboot")]
    [InlineData("vm")]
    [InlineData("update")]
    [InlineData("backup")]
    public void ShouldAutoMount_RefusesSpecialRoleVolumes(string role)
    {
        var policy = new FirstFreeMountPolicy();
        var special = SampleVolume with
        {
            CatalogDecision = ApfsCapabilityDecision.Readable,
            CatalogReasons = [$"special-role:{role}"],
            CatalogAutoMountAllowed = false,
        };

        Assert.False(policy.ShouldAutoMount(special));
    }

    [Theory]
    [InlineData(ApfsCapabilityDecision.Locked)]
    [InlineData(ApfsCapabilityDecision.Unsupported)]
    [InlineData(ApfsCapabilityDecision.ReadOnlyFeature)]
    public void ShouldAutoMount_RefusesNonWritableDecisions(ApfsCapabilityDecision decision)
    {
        var policy = new FirstFreeMountPolicy();
        var blocked = SampleVolume with
        {
            CatalogDecision = decision,
            CatalogReasons = ["locked-encrypted"],
            CatalogAutoMountAllowed = false,
        };

        Assert.False(policy.ShouldAutoMount(blocked));
    }

    [Fact]
    public void ShouldAutoMount_RefusesWritableDecisionWithReasons()
    {
        // A Writable verdict accompanied by any reason is incoherent and must
        // fail closed rather than auto-mount.
        var policy = new FirstFreeMountPolicy();
        var incoherent = SampleVolume with
        {
            CatalogDecision = ApfsCapabilityDecision.Writable,
            CatalogReasons = ["special-role:system"],
            CatalogAutoMountAllowed = true,
        };

        Assert.False(policy.ShouldAutoMount(incoherent));
    }
}
