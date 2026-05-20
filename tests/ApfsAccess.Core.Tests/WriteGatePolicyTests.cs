using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class WriteGatePolicyTests
{
    [Fact]
    public void EvaluateForRequest_DisabledFeature_ReturnsDisabledGate()
    {
        var options = new ServiceHostOptions
        {
            EnableNativeWrite = false,
            WriteRolloutChannel = "Pilot",
        };

        var decision = WriteGatePolicy.EvaluateForRequest(options);

        Assert.False(decision.AllowWrite);
        Assert.Equal("Disabled", decision.GateState);
    }

    [Fact]
    public void EvaluateForVolume_EncryptedVolume_ReturnsEncryptedUnsupported()
    {
        var options = new ServiceHostOptions
        {
            EnableNativeWrite = true,
            WriteRolloutChannel = "Pilot",
        };
        var volume = new VolumeInfo(
            VolumeId: "v1",
            DeviceId: "d1",
            VolumeName: "EncryptedVol",
            SupportsReadWrite: false,
            IsEncrypted: true,
            SupportsExplorerMount: true,
            NativeVolumePath: null,
            SupportsNativeWrite: false,
            WriteBlockReason: "Encrypted volume."
        );

        var decision = WriteGatePolicy.EvaluateForVolume(options, volume);

        Assert.False(decision.AllowWrite);
        Assert.Equal("EncryptedUnsupported", decision.GateState);
    }

    [Fact]
    public void EvaluateForVolume_UnsupportedCapabilityWithOverride_AllowsWrite()
    {
        var options = new ServiceHostOptions
        {
            EnableNativeWrite = true,
            WriteRolloutChannel = "Pilot",
            AllowWriteOnUnsupportedFeatures = true,
        };
        var volume = new VolumeInfo(
            VolumeId: "v1",
            DeviceId: "d1",
            VolumeName: "Vol",
            SupportsReadWrite: false,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: null,
            SupportsNativeWrite: false,
            WriteBlockReason: "Missing feature support."
        );

        var decision = WriteGatePolicy.EvaluateForVolume(options, volume);

        Assert.True(decision.AllowWrite);
        Assert.Equal("Override", decision.GateState);
    }

    [Fact]
    public void EvaluateForVolume_PilotAllowListMissingVolume_BlocksWrite()
    {
        var options = new ServiceHostOptions
        {
            EnableNativeWrite = true,
            WriteRolloutChannel = "Pilot",
            NativeWritePilotVolumeAllowList = ["allowed-volume-id"],
        };
        var volume = new VolumeInfo(
            VolumeId: "v-missing",
            DeviceId: "d1",
            VolumeName: "VolA",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: "/apfs/VolA",
            SupportsNativeWrite: true,
            WriteBlockReason: null
        );

        var decision = WriteGatePolicy.EvaluateForVolume(options, volume);

        Assert.False(decision.AllowWrite);
        Assert.Equal("PilotAllowListBlocked", decision.GateState);
    }

    [Fact]
    public void EvaluateForVolume_RawPhysicalDeviceBlockedByDefault()
    {
        var options = new ServiceHostOptions
        {
            EnableNativeWrite = true,
            WriteRolloutChannel = "Pilot",
            NativeWriteAllowRawPhysicalDevices = false,
        };
        var volume = new VolumeInfo(
            VolumeId: "v1",
            DeviceId: @"\\.\PhysicalDrive3",
            VolumeName: "Vol",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: "ApfsAccess_Volumes/Vol",
            SupportsNativeWrite: true,
            WriteBlockReason: null
        );

        var decision = WriteGatePolicy.EvaluateForVolume(options, volume);

        Assert.False(decision.AllowWrite);
        Assert.Equal("RawPhysicalWriteBlocked", decision.GateState);
    }

    [Fact]
    public void EvaluateForVolume_RawPhysicalDeviceAlternatePrefixBlockedByDefault()
    {
        var options = new ServiceHostOptions
        {
            EnableNativeWrite = true,
            WriteRolloutChannel = "Pilot",
            NativeWriteAllowRawPhysicalDevices = false,
        };
        var volume = new VolumeInfo(
            VolumeId: "v1",
            DeviceId: @"\\?\PhysicalDrive4",
            VolumeName: "Vol",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: "ApfsAccess_Volumes/Vol",
            SupportsNativeWrite: true,
            WriteBlockReason: null
        );

        var decision = WriteGatePolicy.EvaluateForVolume(options, volume);

        Assert.False(decision.AllowWrite);
        Assert.Equal("RawPhysicalWriteBlocked", decision.GateState);
    }

    [Fact]
    public void EvaluateForVolume_ScaffoldPromotionPolicyBlocksPhysicalWrite()
    {
        var options = new ServiceHostOptions
        {
            EnableNativeWrite = true,
            WriteRolloutChannel = "Pilot",
            NativeWriteAllowRawPhysicalDevices = true,
            NativeWritePromotionPolicy = "ScaffoldOnly",
        };
        var volume = new VolumeInfo(
            VolumeId: "v1",
            DeviceId: @"\\.\PhysicalDrive5",
            VolumeName: "Vol",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: "ApfsAccess_Volumes/Vol",
            SupportsNativeWrite: true,
            WriteBlockReason: null
        );

        var decision = WriteGatePolicy.EvaluateForVolume(options, volume);

        Assert.False(decision.AllowWrite);
        Assert.Equal("PromotionPolicyBlocked", decision.GateState);
    }

    [Fact]
    public void EvaluateForVolume_WriteIncompatibilitiesBlockByDefault()
    {
        var options = new ServiceHostOptions
        {
            EnableNativeWrite = true,
            WriteRolloutChannel = "Pilot",
        };
        var volume = new VolumeInfo(
            VolumeId: "v1",
            DeviceId: "d1",
            VolumeName: "Vol",
            SupportsReadWrite: false,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: "ApfsAccess_Volumes/Vol",
            SupportsNativeWrite: false,
            WriteBlockReason: "Unsupported APFS flags.",
            WriteIncompatibilities: ["Unsupported APFS flags."]
        );

        var decision = WriteGatePolicy.EvaluateForVolume(options, volume);

        Assert.False(decision.AllowWrite);
        Assert.Equal("VolumeIncompatibility", decision.GateState);
    }

    [Fact]
    public void EvaluateForVolume_StablePromotionCrossOsValidationIsDeferredToBackendEvidence()
    {
        var options = new ServiceHostOptions
        {
            EnableNativeWrite = true,
            WriteRolloutChannel = "Enabled",
            NativeWriteAllowRawPhysicalDevices = true,
            NativeWritePromotionPolicy = "Stable",
            NativeWriteCrossOsValidationRequired = true,
            NativeWriteCrashFaultMatrixRequired = false,
        };
        var volume = new VolumeInfo(
            VolumeId: "v1",
            DeviceId: @"\\.\PhysicalDrive6",
            VolumeName: "Vol",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: "ApfsAccess_Volumes/Vol",
            SupportsNativeWrite: true,
            WriteBlockReason: null
        );

        var decision = WriteGatePolicy.EvaluateForVolume(options, volume);

        Assert.True(decision.AllowWrite);
        Assert.Equal("Enabled", decision.GateState);
    }

    [Fact]
    public void EvaluateForVolume_StablePromotionCrashMatrixValidationIsDeferredToBackendEvidence()
    {
        var options = new ServiceHostOptions
        {
            EnableNativeWrite = true,
            WriteRolloutChannel = "Enabled",
            NativeWriteAllowRawPhysicalDevices = true,
            NativeWritePromotionPolicy = "Stable",
            NativeWriteCrossOsValidationRequired = false,
            NativeWriteCrashFaultMatrixRequired = true,
        };
        var volume = new VolumeInfo(
            VolumeId: "v1",
            DeviceId: @"\\.\PhysicalDrive6",
            VolumeName: "Vol",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: "ApfsAccess_Volumes/Vol",
            SupportsNativeWrite: true,
            WriteBlockReason: null
        );

        var decision = WriteGatePolicy.EvaluateForVolume(options, volume);

        Assert.True(decision.AllowWrite);
        Assert.Equal("Enabled", decision.GateState);
    }
}
