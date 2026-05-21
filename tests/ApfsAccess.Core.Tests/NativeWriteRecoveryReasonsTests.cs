using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class NativeWriteRecoveryReasonsTests
{
    [Theory]
    [InlineData("CanonicalCommitNotReady", 0)]
    [InlineData("FixtureCompatibilityPathActive", 0)]
    [InlineData("ScaffoldCommitBlobActive", 0)]
    [InlineData("IntegrityMissingAllocationMap", 1)]
    [InlineData("ReplayCheckpointPendingWindow", 1)]
    [InlineData("ReplayCheckpointNotPendingWindow", 1)]
    [InlineData("ReplayCanonicalCandidateMissing", 1)]
    [InlineData("CanonicalPathNotActive", 2)]
    [InlineData("WriteGateBlocked", 3)]
    [InlineData("", int.MaxValue)]
    [InlineData(null, int.MaxValue)]
    public void GetPriority_UsesSharedReasonOrdering(string? recoveryReason, int expected)
    {
        var actual = NativeWriteRecoveryReasons.GetPriority(recoveryReason);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(" commit timed-out ", "CommitTimedOut")]
    [InlineData(" missing allocation ", "IntegrityMissingAllocationMap")]
    [InlineData(" canonical path not active ", "CanonicalPathNotActive")]
    [InlineData(" write gate policy blocked ", "WriteGateBlocked")]
    [InlineData("UnknownReason", "UnknownReason")]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void Normalize_CanonicalizesKnownBackendReasonAliases(string? recoveryReason, string? expected)
    {
        var actual = NativeWriteRecoveryReasons.Normalize(recoveryReason);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("Write blocked (reason=CanonicalCommitNotReady)", "CanonicalCommitNotReady")]
    [InlineData("Write blocked (reason=NativeWriteNotReady).", "NativeWriteNotReady")]
    [InlineData("Write blocked (reason=CanonicalPathNotActive)", "CanonicalPathNotActive")]
    [InlineData("Write blocked (reason = CanonicalCommitNotReady)", null)]
    [InlineData("Write blocked", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void TryExtractReasonToken_ParsesSupportedWarningShape(string? warning, string? expected)
    {
        var actual = NativeWriteRecoveryReasons.TryExtractReasonToken(warning);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("ValidationEvidenceInsufficient", true)]
    [InlineData("ValidationCrashFaultEvidenceInsufficient", true)]
    [InlineData("ValidationStableEvidenceStale", true)]
    [InlineData("WriteGateBlocked", false)]
    [InlineData(null, false)]
    public void IsValidationEvidenceReason_RecognizesEvidenceGateReasons(string? recoveryReason, bool expected)
    {
        var actual = NativeWriteRecoveryReasons.IsValidationEvidenceReason(recoveryReason);

        Assert.Equal(expected, actual);
    }
}
