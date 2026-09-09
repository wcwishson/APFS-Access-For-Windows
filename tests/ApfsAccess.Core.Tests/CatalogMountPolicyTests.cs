using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class CatalogMountPolicyTests
{
    private static VolumeInfo Ordinary => new("v", "D:\\test.img", "Data or role-none", true,
        SupportsNativeWrite: true, CatalogDecision: ApfsCapabilityDecision.Writable,
        CatalogReasons: [], CatalogAutoMountAllowed: true);
    private static ServiceHostOptions Options => new()
    {
        EnableNativeWrite = true, WriteRolloutChannel = "Enabled", AllowWriteOnUnsupportedFeatures = true,
    };

    [Fact]
    public void TypedOrdinaryVerdictRetainsMountAndWriteAdmission()
    {
        Assert.True(CatalogMountPolicy.AllowsMount(Ordinary, false));
        Assert.True(CatalogMountPolicy.AllowsReadOnlyInspection(Ordinary));
        Assert.True(WriteGatePolicy.EvaluateForVolume(Options, Ordinary).AllowWrite);
    }

    [Fact]
    public void IdentityWithoutCapabilityVerdictRetainsLegacyBackendBehavior()
    {
        var volume = Ordinary with { CatalogDecision = null, CatalogReasons = null, CatalogAutoMountAllowed = null,
            CatalogVolumeId = "identity-used-for-drive-letter-storage" };
        Assert.True(CatalogMountPolicy.AllowsOrdinaryMount(volume));
        Assert.True(WriteGatePolicy.EvaluateForVolume(Options, volume).AllowWrite);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(null)]
    public void MissingOrDeniedAutoFlagCannotBeOverriddenForWrites(bool? auto)
    {
        var volume = Ordinary with { CatalogAutoMountAllowed = auto };
        Assert.False(CatalogMountPolicy.AllowsMount(volume, false));
        Assert.False(CatalogMountPolicy.AllowsReadOnlyInspection(volume));
        Assert.False(WriteGatePolicy.EvaluateForVolume(Options, volume).AllowWrite);
    }

    [Theory]
    [InlineData("special-role:system")]
    [InlineData("special-role:backup")]
    [InlineData("special-role:unknown")]
    [InlineData("unknown-features")]
    [InlineData("")]
    [InlineData(null)]
    public void ContradictoryWritableReasonsCannotBeOverridden(string? reason)
    {
        var volume = Ordinary with { CatalogReasons = [reason!] };
        Assert.False(CatalogMountPolicy.AllowsReadOnlyInspection(volume));
        Assert.False(WriteGatePolicy.EvaluateForVolume(Options, volume).AllowWrite);
    }

    [Fact]
    public void CatalogPolicyDoesNotOpenNativeSourceAdmission()
    {
        var volume = Ordinary with { NativeWriteAdmissionBlockReason = "Raw APFS write admission is closed." };
        var decision = WriteGatePolicy.EvaluateForVolume(Options, volume);
        Assert.False(decision.AllowWrite);
        Assert.Equal("NativeSourceAdmissionBlocked", decision.GateState);
    }
}
