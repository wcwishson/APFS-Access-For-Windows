using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class ApfsVolumeCapabilitiesTests
{
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";
    private const string ContainerId = "apfs-container:" + ContainerHex;

    // ---- Section 4 decision matrix ----

    [Fact]
    public void Evaluate_OrdinaryDataVolume_IsWritableWithAutomount()
    {
        var result = ApfsVolumeCapabilities.Evaluate(DataVolume(), CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Writable, result.Decision);
        Assert.Empty(result.Reasons);
        Assert.True(result.AutoMountAllowed);
    }

    [Fact]
    public void Evaluate_UnknownCompatibleBits_NeverGate()
    {
        // Section 5: compat unknowns are RECORDED but never gate.
        var volume = DataVolume() with
        {
            CompatibleFeatureBits = ["0x1", "0x40000000"],
        };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Writable, result.Decision);
        Assert.True(result.AutoMountAllowed);
    }

    [Fact]
    public void Evaluate_VolumeIncompatibleBits_IsUnsupported()
    {
        var volume = DataVolume() with { IncompatibleFeatureBits = ["0x2000000000000000"] };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Unsupported, result.Decision);
        Assert.Equal(["unknown-incompatible-bits"], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    [Fact]
    public void Evaluate_ContainerIncompatibleBits_IsUnsupported()
    {
        var container = CleanContainer() with { IncompatibleFeatureBits = ["0x8000000000000000"] };

        var result = ApfsVolumeCapabilities.Evaluate(DataVolume(), container);

        Assert.Equal(ApfsCapabilityDecision.Unsupported, result.Decision);
        Assert.Equal(["unknown-incompatible-bits"], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    [Fact]
    public void Evaluate_VolumeUnknownBits_IsUnsupported_ReadonlyUnknownCoveredConservatively()
    {
        // Frozen NOTE: unknownFeatureBits covers readonly-unknown bits, so any
        // unknown entry is Unsupported (never ReadOnlyFeature).
        var volume = DataVolume() with { UnknownFeatureBits = ["0x2000000"] };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Unsupported, result.Decision);
        Assert.Equal(["unknown-features"], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    [Fact]
    public void Evaluate_ContainerUnknownBits_IsUnsupported()
    {
        var container = CleanContainer() with { UnknownFeatureBits = ["0x100000000"] };

        var result = ApfsVolumeCapabilities.Evaluate(DataVolume(), container);

        Assert.Equal(ApfsCapabilityDecision.Unsupported, result.Decision);
        Assert.Equal(["unknown-features"], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    [Fact]
    public void Evaluate_VolumeKnownReadonlyBits_IsReadOnlyFeature()
    {
        var volume = DataVolume() with { ReadonlyFeatureBits = ["0x4"] };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.ReadOnlyFeature, result.Decision);
        Assert.Equal(["readonly-features"], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    [Fact]
    public void Evaluate_ContainerKnownReadonlyBits_IsReadOnlyFeature()
    {
        var container = CleanContainer() with { ReadonlyFeatureBits = ["0x8"] };

        var result = ApfsVolumeCapabilities.Evaluate(DataVolume(), container);

        Assert.Equal(ApfsCapabilityDecision.ReadOnlyFeature, result.Decision);
        Assert.Equal(["readonly-features"], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    [Theory]
    [InlineData("password")]
    [InlineData("hardware-bound")]
    [InlineData("unknown")]
    public void Evaluate_EncryptedModes_AreLocked(string encryptionMode)
    {
        var volume = DataVolume() with { EncryptionMode = encryptionMode };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Locked, result.Decision);
        Assert.Equal(["locked-encrypted"], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    [Fact]
    public void Evaluate_LockedFlagWithNoEncryption_IsLocked()
    {
        var volume = DataVolume() with { Locked = true };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Locked, result.Decision);
        Assert.Equal(["locked-encrypted"], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    [Theory]
    [InlineData("system")]
    [InlineData("recovery")]
    [InlineData("vm")]
    [InlineData("preboot")]
    [InlineData("installer")]
    [InlineData("baseband")]
    [InlineData("ts")]
    [InlineData("update")]
    [InlineData("xart")]
    [InlineData("hardware")]
    [InlineData("backup")]
    [InlineData("enterprise")]
    [InlineData("prelogin")]
    [InlineData("image")]
    public void Evaluate_EverySpecialRole_IsReadableWithoutAutomount(string role)
    {
        var volume = DataVolume() with { Roles = [role] };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Readable, result.Decision);
        Assert.Equal(["special-role:" + role], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    [Fact]
    public void Evaluate_UnknownRole_IsReadableWithoutAutomount()
    {
        var volume = DataVolume() with { Roles = ["unknown"], RoleRaw = 1L << 40 };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Readable, result.Decision);
        Assert.Equal(["special-role:unknown"], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    [Fact]
    public void Evaluate_MultiRole_ReportsEverySpecialRole()
    {
        var volume = DataVolume() with { Roles = ["system", "recovery"] };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Readable, result.Decision);
        Assert.Equal(["special-role:system", "special-role:recovery"], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    [Fact]
    public void Evaluate_DataPlusSystemRole_IsReadable()
    {
        // Writable requires exactly ["data"]; any additional role keeps the
        // volume out of the automount-writable path.
        var volume = DataVolume() with { Roles = ["data", "system"] };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Readable, result.Decision);
        Assert.Equal(["special-role:system"], result.Reasons);
        Assert.False(result.AutoMountAllowed);
    }

    public static IEnumerable<object[]> ReadonlyRoleCases()
    {
        string[][] roles = [["unknown"], ["future-role"], [], ["data", "unknown"],
            ["system", "future-role"], ["data"], ["system"], ["backup"], ["data", "recovery"]];
        foreach (var containerBits in new[] { false, true })
        foreach (var roleSet in roles)
            yield return [containerBits, roleSet,
                roleSet.Length > 0 && roleSet.All(role => role is "data" or "system" or "backup" or "recovery")];
    }

    [Theory]
    [MemberData(nameof(ReadonlyRoleCases))]
    public void EvaluateToPolicy_ReadonlyFeaturesPreserveRoleEligibility(
        bool containerBits, string[] roles, bool inspectionAllowed)
    {
        var volume = DataVolume() with { Roles = roles,
            ReadonlyFeatureBits = containerBits ? [] : ["0x4"] };
        var container = CleanContainer() with { ReadonlyFeatureBits = containerBits ? ["0x4"] : [] };
        var result = ApfsVolumeCapabilities.Evaluate(volume, container);
        var projected = ProjectCapability(result);

        Assert.Equal(inspectionAllowed, CatalogMountPolicy.AllowsMount(projected, true));
        Assert.False(CatalogMountPolicy.AllowsMount(projected, false));
        Assert.False(result.AutoMountAllowed);
        Assert.Equal(roles.SequenceEqual(new[] { "data" })
            ? ApfsCapabilityDecision.ReadOnlyFeature : ApfsCapabilityDecision.Readable, result.Decision);
    }

    [Theory]
    [InlineData(false, "locked")]
    [InlineData(true, "locked")]
    [InlineData(false, "password")]
    [InlineData(true, "password")]
    [InlineData(false, "hardware-bound")]
    [InlineData(true, "hardware-bound")]
    [InlineData(false, "unknown")]
    [InlineData(true, "unknown")]
    [InlineData(false, "unknown-feature")]
    [InlineData(true, "unknown-feature")]
    [InlineData(false, "incompatible")]
    [InlineData(true, "incompatible")]
    public void EvaluateToPolicy_ReadonlyFeaturesCannotMaskRefusal(bool containerBits, string refusal)
    {
        var volume = DataVolume() with
        {
            ReadonlyFeatureBits = containerBits ? [] : ["0x4"],
            Locked = refusal == "locked",
            EncryptionMode = refusal is "password" or "hardware-bound" or "unknown" ? refusal : "none",
            UnknownFeatureBits = !containerBits && refusal == "unknown-feature" ? ["0x20"] : [],
            IncompatibleFeatureBits = !containerBits && refusal == "incompatible" ? ["0x10"] : [],
        };
        var container = CleanContainer() with
        {
            ReadonlyFeatureBits = containerBits ? ["0x4"] : [],
            UnknownFeatureBits = containerBits && refusal == "unknown-feature" ? ["0x20"] : [],
            IncompatibleFeatureBits = containerBits && refusal == "incompatible" ? ["0x10"] : [],
        };
        var result = ApfsVolumeCapabilities.Evaluate(volume, container);
        Assert.Equal(refusal is "unknown-feature" or "incompatible"
            ? ApfsCapabilityDecision.Unsupported : ApfsCapabilityDecision.Locked, result.Decision);
        Assert.False(CatalogMountPolicy.AllowsMount(ProjectCapability(result), true));
        Assert.False(CatalogMountPolicy.AllowsMount(ProjectCapability(result), false));
    }

    private static VolumeInfo ProjectCapability(ApfsVolumeCapability result) => new(
        "v", "D:\\test.img", "Data", true,
        CatalogDecision: result.Decision, CatalogReasons: result.Reasons,
        CatalogAutoMountAllowed: result.AutoMountAllowed);

    // ---- Precedence: incompat > unknown > locked > roles > readonly ----

    [Fact]
    public void Evaluate_Precedence_IncompatibleBeatsEverything()
    {
        var volume = DataVolume() with
        {
            IncompatibleFeatureBits = ["0x10"],
            UnknownFeatureBits = ["0x20"],
            ReadonlyFeatureBits = ["0x4"],
            EncryptionMode = "password",
            Locked = true,
            Roles = ["system"],
        };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Unsupported, result.Decision);
        Assert.Equal(["unknown-incompatible-bits"], result.Reasons);
    }

    [Fact]
    public void Evaluate_Precedence_UnknownBeatsReadonlyLockedAndRole()
    {
        var volume = DataVolume() with
        {
            UnknownFeatureBits = ["0x20"],
            ReadonlyFeatureBits = ["0x4"],
            Locked = true,
            Roles = ["preboot"],
        };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Unsupported, result.Decision);
        Assert.Equal(["unknown-features"], result.Reasons);
    }

    [Fact]
    public void Evaluate_Precedence_LockedBeatsReadonlyAndRole()
    {
        var volume = DataVolume() with
        {
            ReadonlyFeatureBits = ["0x4"],
            Locked = true,
            Roles = ["recovery"],
        };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Locked, result.Decision);
        Assert.Equal(["locked-encrypted"], result.Reasons);
    }

    [Fact]
    public void Evaluate_Precedence_LockedBeatsRole()
    {
        var volume = DataVolume() with
        {
            EncryptionMode = "password",
            Roles = ["vm"],
        };

        var result = ApfsVolumeCapabilities.Evaluate(volume, CleanContainer());

        Assert.Equal(ApfsCapabilityDecision.Locked, result.Decision);
        Assert.Equal(["locked-encrypted"], result.Reasons);
    }

    [Fact]
    public void Evaluate_NullArguments_Throw()
    {
        Assert.Throws<ArgumentNullException>(
            () => ApfsVolumeCapabilities.Evaluate(null!, CleanContainer()));
        Assert.Throws<ArgumentNullException>(
            () => ApfsVolumeCapabilities.Evaluate(DataVolume(), null!));
    }

    // ---- Helpers ----

    private static ApfsVolumeRecord DataVolume() => new(
        Id: "apfs-vol:" + ContainerHex + ":101",
        Uuid: "c3d4e5f60718293a4b5c6d7e8f90a1b2",
        ObjectId: "101",
        ContainerId: ContainerId,
        Name: "Data",
        NameUtf8Valid: true,
        Roles: ["data"],
        RoleRaw: 32,
        GroupId: null,
        CaseMode: "sensitive",
        EncryptionMode: "none",
        Locked: false,
        CompatibleFeatureBits: ["0x1"],
        UnknownFeatureBits: [],
        IncompatibleFeatureBits: [],
        SuperblockBlock: "12",
        SuperblockXid: "7");

    private static ApfsContainerRecord CleanContainer() => new(
        Id: ContainerId,
        Uuid: ContainerHex,
        BlockSizeBytes: 4096,
        StoreIds: ["apfs-store:11111111-2222-3333-4444-555555555555"],
        VolumeIds: ["apfs-vol:" + ContainerHex + ":101"],
        Fusion: false,
        CheckpointXid: "7",
        CompatibleFeatureBits: ["0x1"],
        UnknownFeatureBits: [],
        IncompatibleFeatureBits: []);
}
