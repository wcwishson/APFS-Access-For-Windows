namespace ApfsAccess.Core;

public sealed class ServiceHostOptions
{
    public const string SectionName = "Service";

    public string BackendMode { get; set; } = "Mock";

    public string? NativeFsHostPath { get; set; }

    public string[] NativeDeviceCandidates { get; set; } = [];

    public bool NativeAutoDiscoverPhysicalDrives { get; set; } = false;

    public int NativeMaxPhysicalDriveIndex { get; set; } = 8;

    public string WinFspMode { get; set; } = "System";

    public bool AutoMountEnabled { get; set; } = true;

    public string DriveLetterPolicy { get; set; } = "FirstFree";

    public string[] MountLetterPool { get; set; } = Enumerable.Range('D', ('Z' - 'D') + 1)
        .Select(x => ((char)x).ToString())
        .ToArray();

    public bool EnableNativeWrite { get; set; } = false;

    public string WriteRolloutChannel { get; set; } = "Disabled";

    public string WriteSafetyLevel { get; set; } = "Conservative";

    public string WriteBackendMode { get; set; } = "Disabled";

    public bool AllowWriteOnUnsupportedFeatures { get; set; } = false;

    public int WriteCommitTimeoutSeconds { get; set; } = 15;

    public bool NativeWriteStrictMode { get; set; } = true;

    public int NativeWriteMaxDirtyTransactions { get; set; } = 128;

    public string NativeWriteRecoveryPolicy { get; set; } = "FailClosed";

    public bool NativeWriteAllowRawPhysicalDevices { get; set; } = false;

    public string[] NativeWritePilotVolumeAllowList { get; set; } = [];

    public bool NativeWriteIntegrityCheckOnMount { get; set; } = true;

    public string NativeWriteCrashReplayMode { get; set; } = "FailClosed";

    public string NativeWritePromotionPolicy { get; set; } = "ScaffoldOnly";

    public bool NativeWriteRequireCanonicalCommit { get; set; } = true;

    public bool NativeWriteDisallowScaffoldCommitOnNonFixture { get; set; } = true;

    public bool NativeWriteRejectScaffoldReplayBlobOnNonFixture { get; set; } = true;

    public bool NativeWriteRequireCanonicalReplayCandidateOnNonFixture { get; set; } = true;

    public bool NativeWriteAllowLegacyScaffoldForFixtures { get; set; } = true;

    public string[] NativeWriteHardwarePilotDeviceAllowList { get; set; } = [];

    public bool NativeWriteCrossOsValidationRequired { get; set; } = true;

    public bool NativeWriteCrashFaultMatrixRequired { get; set; } = true;

    public bool NativeWriteRequireMacOsValidationForStable { get; set; } = true;

    public int NativeWriteMinCrashFaultPasses { get; set; } = 1;

    public int NativeWriteMinCrashStageMatrixPasses { get; set; } = 1;

    public int NativeWriteMinHardwarePilotPasses { get; set; } = 3;

    public int NativeWriteMinHotUnplugPasses { get; set; } = 1;

    public int NativeWriteMinMacOsValidationPasses { get; set; } = 2;

    public int NativeWriteMinMacOsConsistencyPasses { get; set; } = 2;

    public int NativeWriteMinPowerLossReplayPasses { get; set; } = 1;

    public bool NativeWriteStableRequiresPowerLossPass { get; set; } = true;

    public int NativeWriteValidationEvidenceMaxAgeDays { get; set; } = 30;

    public bool NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices { get; set; } = false;

    public int NativeWriteEvidenceSeedCrashFaultPasses { get; set; } = 0;

    public int NativeWriteEvidenceSeedCrashStageMatrixPasses { get; set; } = 0;

    public int NativeWriteEvidenceSeedHardwarePilotPasses { get; set; } = 0;

    public int NativeWriteEvidenceSeedHotUnplugPasses { get; set; } = 0;

    public int NativeWriteEvidenceSeedMacOsValidationPasses { get; set; } = 0;

    public int NativeWriteEvidenceSeedMacOsConsistencyPasses { get; set; } = 0;

    public int NativeWriteEvidenceSeedPowerLossReplayPasses { get; set; } = 0;

    public bool NativeWriteEvidenceSeedPowerLossPassVerified { get; set; } = false;

    public DateTime? NativeWriteEvidenceSeedLastValidatedUtc { get; set; }

    public string? NativeWriteEvidenceSeedLastValidationProfileId { get; set; }

    public string NativeWriteEvidenceStorePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "ApfsAccess",
        "write-evidence.json"
    );

    public bool SkipEncryptedVolumes { get; set; } = true;

    public bool NativeAutoRemountOnReconnect { get; set; } = true;

    public int NativeHostStartupTimeoutSeconds { get; set; } = 8;

    public int NativeHostStopTimeoutSeconds { get; set; } = 5;

    public string ReadWriteMode { get; set; } = "RwWithRoFallback";

    public string LogLevel { get; set; } = "Information";

    public int PollSeconds { get; set; } = 2;
}
