using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed class PerVolumeStatusTruthTests
{
    [Fact]
    public void BuildMountedVolumeDisplays_PreservesDivergentPerVolumeFacts()
    {
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: "device-a|rw",
                MountPoint: "R:\\",
                AccessMode: MountAccessMode.ReadWrite,
                VolumeName: "Writable",
                DeviceId: "device-a",
                DeviceDisplayName: "APFS device",
                WriteBackend: "Native",
                CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
                NativeWriteReadiness: NativeWriteReadiness.CommitReady,
                NativeWriteEngineState: NativeWriteEngineState.Transactional,
                NativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
                RecoveryActive: true,
                LastCommitXid: 101,
                RecoveryReason: "rw-recovery",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                WriteIncompatibilities: ["rw-incompatibility"],
                WriteUnsupportedFeatures: ["rw-unsupported"],
                LastRecoveryAction: "rw-action",
                DirtyTransactionCount: 2,
                ShutdownDrainActive: true,
                InFlightMutationCallbacks: 3,
                NativeWriteValidationEvidence: new NativeWriteValidationEvidence(CrashFaultPasses: 7),
                NativeWriteDiagnostics: [new NativeWriteDiagnostic("rw-diagnostic", "rw diagnostic")],
                RecoveryIdentity: "rw-identity",
                MountReady: true,
                HostProcessId: 4242,
                WalAcceptedSequence: 12,
                WalApfsDurableSequence: 10,
                WalCleanupSequence: 8),
            new MountedVolumeState(
                VolumeId: "device-a|ro",
                MountPoint: "S:\\",
                AccessMode: MountAccessMode.ReadOnly,
                VolumeName: "Read only",
                DeviceId: "device-a",
                DeviceDisplayName: "APFS device",
                WriteBackend: "Disabled",
                CommitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
                NativeWriteReadiness: NativeWriteReadiness.Unavailable,
                NativeWriteEngineState: NativeWriteEngineState.Scaffold,
                NativeWriteValidationState: NativeWriteValidationState.Scaffold,
                RecoveryActive: false,
                LastCommitXid: 202,
                RecoveryReason: "ro-recovery",
                NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
                WriteIncompatibilities: ["ro-incompatibility"],
                WriteUnsupportedFeatures: ["ro-unsupported"],
                LastRecoveryAction: "ro-action",
                DirtyTransactionCount: 0,
                ShutdownDrainActive: false,
                InFlightMutationCallbacks: 0,
                NativeWriteValidationEvidence: new NativeWriteValidationEvidence(CrashFaultPasses: 2),
                NativeWriteDiagnostics: [new NativeWriteDiagnostic("ro-diagnostic", "ro diagnostic")],
                RecoveryIdentity: "ro-identity",
                MountReady: false,
                HostProcessId: 0,
                WalAcceptedSequence: 5,
                WalApfsDurableSequence: 5,
                WalCleanupSequence: 5),
        };

        var displays = InvokeBuildMountedVolumeDisplays(mounts);
        var jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() },
        };
        var values = displays
            .ToDictionary(display => display.VolumeId, display => JsonSerializer.SerializeToElement(display, jsonOptions));

        var writable = values["device-a|rw"];
        Assert.Equal("MountedRw", writable.GetProperty("state").GetString());
        Assert.True(writable.GetProperty("writeEnabled").GetBoolean());
        Assert.Equal("Native", writable.GetProperty("writeBackend").GetString());
        Assert.Equal("CanonicalApfsCheckpoint", writable.GetProperty("commitModel").GetString());
        Assert.Equal("CommitReady", writable.GetProperty("nativeWriteReadiness").GetString());
        Assert.Equal("Transactional", writable.GetProperty("nativeWriteEngineState").GetString());
        Assert.Equal("HardwarePilotValidated", writable.GetProperty("nativeWriteValidationState").GetString());
        Assert.Equal("RecoveryBlocked", writable.GetProperty("nativeWriteSafetyState").GetString());
        Assert.True(writable.GetProperty("recoveryActive").GetBoolean());
        Assert.Equal("rw-recovery", writable.GetProperty("recoveryReason").GetString());
        Assert.Equal("rw-action", writable.GetProperty("lastRecoveryAction").GetString());
        Assert.Equal(101UL, writable.GetProperty("lastCommitXid").GetUInt64());
        Assert.Equal("rw-identity", writable.GetProperty("recoveryIdentity").GetString());
        Assert.Equal(2, writable.GetProperty("dirtyTransactionCount").GetInt32());
        Assert.True(writable.GetProperty("shutdownDrainActive").GetBoolean());
        Assert.Equal(3, writable.GetProperty("inFlightMutationCallbacks").GetInt32());
        Assert.Equal(7, writable.GetProperty("nativeWriteValidationEvidence").GetProperty("crashFaultPasses").GetInt32());
        Assert.Equal("rw-diagnostic", writable.GetProperty("nativeWriteDiagnostics")[0].GetProperty("code").GetString());
        Assert.Equal("rw-incompatibility", writable.GetProperty("writeIncompatibilities")[0].GetString());
        Assert.Equal("rw-unsupported", writable.GetProperty("writeUnsupportedFeatures")[0].GetString());
        Assert.True(writable.GetProperty("mountReady").GetBoolean());
        Assert.Equal(4242, writable.GetProperty("hostProcessId").GetInt32());
        Assert.Equal("owned", writable.GetProperty("hostOwnershipState").GetString());
        Assert.Equal(12UL, writable.GetProperty("walAcceptedSequence").GetUInt64());
        Assert.Equal(10UL, writable.GetProperty("walApfsDurableSequence").GetUInt64());
        Assert.Equal(8UL, writable.GetProperty("walCleanupSequence").GetUInt64());
        Assert.True(writable.GetProperty("pendingDurability").GetBoolean());

        var readOnly = values["device-a|ro"];
        Assert.Equal("MountedRo", readOnly.GetProperty("state").GetString());
        Assert.False(readOnly.GetProperty("writeEnabled").GetBoolean());
        Assert.Equal("Disabled", readOnly.GetProperty("writeBackend").GetString());
        Assert.Equal("ScaffoldCheckpoint", readOnly.GetProperty("commitModel").GetString());
        Assert.Equal("Unavailable", readOnly.GetProperty("nativeWriteReadiness").GetString());
        Assert.Equal("Scaffold", readOnly.GetProperty("nativeWriteEngineState").GetString());
        Assert.Equal("Scaffold", readOnly.GetProperty("nativeWriteValidationState").GetString());
        Assert.Equal("ReadOnlyFallback", readOnly.GetProperty("nativeWriteSafetyState").GetString());
        Assert.False(readOnly.GetProperty("recoveryActive").GetBoolean());
        Assert.Equal("ro-recovery", readOnly.GetProperty("recoveryReason").GetString());
        Assert.Equal("ro-action", readOnly.GetProperty("lastRecoveryAction").GetString());
        Assert.Equal(202UL, readOnly.GetProperty("lastCommitXid").GetUInt64());
        Assert.Equal("ro-incompatibility", readOnly.GetProperty("writeIncompatibilities")[0].GetString());
        Assert.Equal("ro-unsupported", readOnly.GetProperty("writeUnsupportedFeatures")[0].GetString());
        Assert.Equal(2, readOnly.GetProperty("nativeWriteValidationEvidence").GetProperty("crashFaultPasses").GetInt32());
        Assert.Equal("ro-diagnostic", readOnly.GetProperty("nativeWriteDiagnostics")[0].GetProperty("code").GetString());
        Assert.Equal("ro-identity", readOnly.GetProperty("recoveryIdentity").GetString());
        Assert.False(readOnly.GetProperty("mountReady").GetBoolean());
        Assert.Equal(0, readOnly.GetProperty("hostProcessId").GetInt32());
        Assert.Equal("unknown", readOnly.GetProperty("hostOwnershipState").GetString());
        Assert.Equal(5UL, readOnly.GetProperty("walAcceptedSequence").GetUInt64());
        Assert.Equal(5UL, readOnly.GetProperty("walApfsDurableSequence").GetUInt64());
        Assert.Equal(5UL, readOnly.GetProperty("walCleanupSequence").GetUInt64());
        Assert.False(readOnly.GetProperty("pendingDurability").GetBoolean());
    }

    private static IReadOnlyList<MountedVolumeDisplay> InvokeBuildMountedVolumeDisplays(
        IReadOnlyList<MountedVolumeState> mounts)
    {
        var method = typeof(ApfsMountWorker).GetMethod(
            "BuildMountedVolumeDisplays",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [mounts]);
        return Assert.IsAssignableFrom<IReadOnlyList<MountedVolumeDisplay>>(result);
    }
}
