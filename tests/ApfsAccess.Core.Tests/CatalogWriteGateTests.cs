using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

// A4: when a catalog attachment exists, writability derives solely from the
// capability decision. Non-writable decisions block even when the legacy
// override flag (AllowWriteOnUnsupportedFeatures) is set.
public sealed class CatalogWriteGateTests
{
    private static ServiceHostOptions OverrideConfig() => new()
    {
        EnableNativeWrite = true,
        WriteRolloutChannel = "Enabled",
        WriteBackendMode = "Native",
        AllowWriteOnUnsupportedFeatures = true,
    };

    private static VolumeInfo CatalogVolume(ApfsCapabilityDecision decision) => new(
        VolumeId: "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:201",
        DeviceId: @"D:\snap.apfs.img",
        VolumeName: "Data",
        SupportsReadWrite: false,
        IsEncrypted: false,
        SupportsExplorerMount: true,
        NativeVolumePath: @"D:\snap.apfs.img\ApfsAccess_Volumes\Data",
        SupportsNativeWrite: false,
        WriteBlockReason: "catalog-gated",
        CatalogVolumeId: "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:201",
        CatalogContainerUuid: "a9cb92d28b7c4b599eab633c7625f491",
        CatalogVolumeObjectId: 201UL,
        CatalogDecision: decision,
        CatalogReasons: ["catalog"],
        CatalogAutoMountAllowed: false);

    [Theory]
    [InlineData(ApfsCapabilityDecision.Locked)]
    [InlineData(ApfsCapabilityDecision.Unsupported)]
    [InlineData(ApfsCapabilityDecision.ReadOnlyFeature)]
    [InlineData(ApfsCapabilityDecision.Readable)]
    public void EvaluateForVolume_NonWritableCatalogDecision_BlocksDespiteOverride(
        ApfsCapabilityDecision decision)
    {
        var gate = WriteGatePolicy.EvaluateForVolume(OverrideConfig(), CatalogVolume(decision));

        Assert.False(gate.AllowWrite);
        Assert.Equal("CatalogCapabilityBlocked", gate.GateState);
    }

    [Fact]
    public void EvaluateForVolume_WritableCatalogDecision_DoesNotBlock()
    {
        var volume = CatalogVolume(ApfsCapabilityDecision.Writable) with
        {
            SupportsReadWrite = true,
            SupportsNativeWrite = true,
            WriteBlockReason = null,
        };

        var gate = WriteGatePolicy.EvaluateForVolume(OverrideConfig(), volume);

        Assert.True(gate.AllowWrite);
        Assert.Equal("Enabled", gate.GateState);
    }

    [Fact]
    public void EvaluateForVolume_NoCatalogAttachment_KeepsLegacyOverride()
    {
        var volume = new VolumeInfo(
            VolumeId: "v1",
            DeviceId: "d1",
            VolumeName: "Vol",
            SupportsReadWrite: false,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: null,
            SupportsNativeWrite: false,
            WriteBlockReason: "Missing feature support.");

        var gate = WriteGatePolicy.EvaluateForVolume(OverrideConfig(), volume);

        Assert.True(gate.AllowWrite);
        Assert.Equal("Override", gate.GateState);
    }
}
