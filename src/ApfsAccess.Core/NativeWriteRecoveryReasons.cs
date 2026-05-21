namespace ApfsAccess.Core;

public static class NativeWriteRecoveryReasons
{
    private static readonly IReadOnlyDictionary<string, string> CanonicalReasonAliases =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["committimedout"] = "CommitTimedOut",
            ["commitnotwritable"] = "CommitNotWritable",
            ["commitmodelnotcanonical"] = "CommitModelNotCanonical",
            ["fixturelegacyfallbackactive"] = "FixtureLegacyFallbackActive",
            ["fixturecompatibilitypathactive"] = "FixtureCompatibilityPathActive",
            ["scaffoldcommitblobactive"] = "ScaffoldCommitBlobActive",
            ["commitnotready"] = "CommitNotReady",
            ["commitallocationfailed"] = "CommitAllocationFailed",
            ["commitinvariantfailed"] = "CommitInvariantFailed",
            ["commitpersistorflushfailed"] = "CommitPersistOrFlushFailed",
            ["commitinterruptedbeforeobjectmappersist"] = "CommitInterruptedBeforeObjectMapPersist",
            ["commitobjectmappersistfailed"] = "CommitObjectMapPersistFailed",
            ["commitobjectmaproundtripfailed"] = "CommitObjectMapRoundTripFailed",
            ["commitinterruptedbeforespacemanpersist"] = "CommitInterruptedBeforeSpacemanPersist",
            ["commitspacemanpersistfailed"] = "CommitSpacemanPersistFailed",
            ["commitspacemanroundtripfailed"] = "CommitSpacemanRoundTripFailed",
            ["commitinterruptedbeforeinodepersist"] = "CommitInterruptedBeforeInodePersist",
            ["commitinodepersistfailed"] = "CommitInodePersistFailed",
            ["commitinoderoundtripfailed"] = "CommitInodeRoundTripFailed",
            ["commitinterruptedbeforebtreepersist"] = "CommitInterruptedBeforeBtreePersist",
            ["commitbtreepersistfailed"] = "CommitBtreePersistFailed",
            ["commitbtreeroundtripfailed"] = "CommitBtreeRoundTripFailed",
            ["commitinterruptedbeforereplaypersist"] = "CommitInterruptedBeforeReplayPersist",
            ["commitreplaypersistfailed"] = "CommitReplayPersistFailed",
            ["commitinterruptedbeforereplayroundtripverify"] = "CommitInterruptedBeforeReplayRoundTripVerify",
            ["commitreplayroundtripfailed"] = "CommitReplayRoundTripFailed",
            ["commitinterruptedbeforecheckpointswitch"] = "CommitInterruptedBeforeCheckpointSwitch",
            ["commitcheckpointwritefailed"] = "CommitCheckpointWriteFailed",
            ["commitinterruptedbeforecheckpointroundtripverify"] = "CommitInterruptedBeforeCheckpointRoundTripVerify",
            ["commitcheckpointroundtripfailed"] = "CommitCheckpointRoundTripFailed",
            ["commitinterruptedbeforecheckpointflush"] = "CommitInterruptedBeforeCheckpointFlush",
            ["commitcheckpointflushfailed"] = "CommitCheckpointFlushFailed",
            ["nativewritebootstrapfailed"] = "NativeWriteBootstrapFailed",
            ["containerstateloadfailed"] = "ContainerStateLoadFailed",
            ["objectmaploadfailed"] = "ObjectMapLoadFailed",
            ["spacemanstateloadfailed"] = "SpacemanStateLoadFailed",
            ["volumestateloadfailed"] = "VolumeStateLoadFailed",
            ["persistentstateloadfailed"] = "PersistentStateLoadFailed",
            ["rootstateinvalid"] = "RootStateInvalid",
            ["integritycheckfailedonmount"] = "IntegrityCheckFailedOnMount",
            ["integritymissingallocationmap"] = "IntegrityMissingAllocationMap",
            ["missingallocation"] = "IntegrityMissingAllocationMap",
            ["missingallocationmap"] = "IntegrityMissingAllocationMap",
            ["persistentstateaheadofsuperblock"] = "PersistentStateAheadOfSuperblock",
            ["persistentstatebehindsuperblock"] = "PersistentStateBehindSuperblock",
            ["recoveryloadvolumestatefailed"] = "RecoveryLoadVolumeStateFailed",
            ["recoverypersistentstateloadfailed"] = "RecoveryPersistentStateLoadFailed",
            ["replayintegritycheckfailed"] = "ReplayIntegrityCheckFailed",
            ["replaymetadatastatemissing"] = "ReplayMetadataStateMissing",
            ["replaycanonicalcandidatemissing"] = "ReplayCanonicalCandidateMissing",
            ["replaycheckpointpendingwindow"] = "ReplayCheckpointPendingWindow",
            ["replaycheckpointnotpendingwindow"] = "ReplayCheckpointNotPendingWindow",
            ["replayxidwindowinvalid"] = "ReplayXidWindowInvalid",
            ["replaycommitblobinvalid"] = "ReplayCommitBlobInvalid",
            ["replaycommitblobreadfailed"] = "ReplayCommitBlobReadFailed",
            ["replayinterruptedbeforecheckpointswitch"] = "ReplayInterruptedBeforeCheckpointSwitch",
            ["replaycheckpointwritefailed"] = "ReplayCheckpointWriteFailed",
            ["replayinterruptedbeforecheckpointflush"] = "ReplayInterruptedBeforeCheckpointFlush",
            ["replaycheckpointflushfailed"] = "ReplayCheckpointFlushFailed",
            ["recoverymarkerdirty"] = "RecoveryMarkerDirty",
            ["recoveryrequired"] = "RecoveryRequired",
            ["dirtytransactionlimitexceeded"] = "DirtyTransactionLimitExceeded",
            ["nativemutationstagingfailed"] = "NativeMutationStagingFailed",
            ["canonicalpathnotactive"] = "CanonicalPathNotActive",
            ["canonicalgatefailure"] = "CanonicalPathNotActive",
            ["canonicalstatenotloaded"] = "CanonicalStateNotLoaded",
            ["canonicalvolumestateloadfailed"] = "CanonicalVolumeStateLoadFailed",
            ["canonicalobjectmapstateinvalid"] = "CanonicalObjectMapStateInvalid",
            ["canonicalspacemanstateinvalid"] = "CanonicalSpacemanStateInvalid",
            ["canonicalvolumetreestateinvalid"] = "CanonicalVolumeTreeStateInvalid",
            ["nativewritenotready"] = "NativeWriteNotReady",
            ["writedevicenotallowed"] = "WriteDeviceNotAllowed",
            ["commitpathnotready"] = "CommitPathNotReady",
            ["canonicalcommitnotready"] = "CanonicalCommitNotReady",
            ["validationevidenceinsufficient"] = "ValidationEvidenceInsufficient",
            ["validationcrashfaultevidenceinsufficient"] = "ValidationCrashFaultEvidenceInsufficient",
            ["validationcrashstagematrixevidenceinsufficient"] = "ValidationCrashStageMatrixEvidenceInsufficient",
            ["validationhardwarepilotevidenceinsufficient"] = "ValidationHardwarePilotEvidenceInsufficient",
            ["validationhotunplugevidenceinsufficient"] = "ValidationHotUnplugEvidenceInsufficient",
            ["validationcrossosevidenceinsufficient"] = "ValidationCrossOsEvidenceInsufficient",
            ["validationmacosevidenceinsufficient"] = "ValidationMacOsEvidenceInsufficient",
            ["validationmacosconsistencyevidenceinsufficient"] = "ValidationMacOsConsistencyEvidenceInsufficient",
            ["validationpowerlossreplayevidenceinsufficient"] = "ValidationPowerLossReplayEvidenceInsufficient",
            ["validationpowerlossevidenceinsufficient"] = "ValidationPowerLossEvidenceInsufficient",
            ["validationcanonicalevidenceinsufficient"] = "ValidationCanonicalEvidenceInsufficient",
            ["validationhardwarepilotevidencestale"] = "ValidationHardwarePilotEvidenceStale",
            ["validationstableevidencestale"] = "ValidationStableEvidenceStale",
            ["writegateblocked"] = "WriteGateBlocked",
            ["writegatepolicyblocked"] = "WriteGateBlocked",
        };

    private static readonly HashSet<string> ValidationEvidenceReasons = new(StringComparer.OrdinalIgnoreCase)
    {
        "ValidationEvidenceInsufficient",
        "ValidationCrashFaultEvidenceInsufficient",
        "ValidationCrashStageMatrixEvidenceInsufficient",
        "ValidationHardwarePilotEvidenceInsufficient",
        "ValidationHotUnplugEvidenceInsufficient",
        "ValidationCrossOsEvidenceInsufficient",
        "ValidationMacOsEvidenceInsufficient",
        "ValidationMacOsConsistencyEvidenceInsufficient",
        "ValidationPowerLossReplayEvidenceInsufficient",
        "ValidationPowerLossEvidenceInsufficient",
        "ValidationCanonicalEvidenceInsufficient",
        "ValidationHardwarePilotEvidenceStale",
        "ValidationStableEvidenceStale",
    };

    private static readonly string[] ExplicitCanonicalGateReasons =
    [
        "CanonicalStateNotLoaded",
        "CanonicalVolumeStateLoadFailed",
        "CanonicalObjectMapStateInvalid",
        "CanonicalSpacemanStateInvalid",
        "CanonicalVolumeTreeStateInvalid",
        "NativeWriteNotReady",
        "WriteDeviceNotAllowed",
        "CommitPathNotReady",
        "CanonicalCommitNotReady",
        "FixtureCompatibilityPathActive",
        "ScaffoldCommitBlobActive",
    ];

    private static readonly string[] HighPriorityReplayReasons =
    [
        "IntegrityMissingAllocationMap",
        "ReplayCheckpointPendingWindow",
        "ReplayCheckpointNotPendingWindow",
        "ReplayCanonicalCandidateMissing",
    ];

    public static int GetPriority(string? recoveryReason)
    {
        var normalized = Normalize(recoveryReason);
        if (normalized is null)
        {
            return int.MaxValue;
        }

        if (ExplicitCanonicalGateReasons.Any(reason => string.Equals(reason, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            return 0;
        }

        if (HighPriorityReplayReasons.Any(reason => string.Equals(reason, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            return 1;
        }

        return normalized switch
        {
            "CanonicalPathNotActive" => 2,
            "WriteGateBlocked" => 3,
            _ => 4,
        };
    }

    public static string? TryExtractReasonToken(string? warning)
    {
        if (string.IsNullOrWhiteSpace(warning))
        {
            return null;
        }

        const string marker = "reason=";
        var markerIndex = warning.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (markerIndex < 0)
        {
            return null;
        }

        var start = markerIndex + marker.Length;
        var end = start;
        while (end < warning.Length && (char.IsLetterOrDigit(warning[end]) || warning[end] is '_' or '-'))
        {
            end++;
        }

        if (end <= start)
        {
            return null;
        }

        return warning[start..end];
    }

    public static bool IsValidationEvidenceReason(string? recoveryReason)
    {
        var normalized = Normalize(recoveryReason);
        return normalized is not null && ValidationEvidenceReasons.Contains(normalized);
    }

    public static string? Normalize(string? recoveryReason)
    {
        if (string.IsNullOrWhiteSpace(recoveryReason))
        {
            return null;
        }

        var trimmed = recoveryReason.Trim();
        var canonicalTokenBuilder = new System.Text.StringBuilder(trimmed.Length);
        foreach (var ch in trimmed)
        {
            if (char.IsLetterOrDigit(ch))
            {
                canonicalTokenBuilder.Append(char.ToLowerInvariant(ch));
            }
        }

        var canonicalToken = canonicalTokenBuilder.ToString();
        return CanonicalReasonAliases.TryGetValue(canonicalToken, out var normalized)
            ? normalized
            : trimmed;
    }
}
