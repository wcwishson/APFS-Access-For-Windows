using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ContainerRuntimeDiagnosticsTests
{
    [Fact]
    public void CanonicalOnlyHealthyOwnerProjectsCanonicalRuntimeWithoutCertification()
    {
        var result = ContainerRuntimeDiagnostics.Project(true, true, true, true, true, false, false, 42);
        Assert.Equal(NativeWriteCommitModel.CanonicalApfsCheckpoint, result.CommitModel);
        Assert.Equal(NativeWriteReadiness.CommitReady, result.Readiness);
        Assert.Equal(NativeWriteEngineState.Transactional, result.EngineState);
        Assert.Equal(NativeWriteValidationState.CanonicalImageValidated, result.ValidationState);
        Assert.True(result.ValidationState < NativeWriteValidationState.HardwarePilotValidated);
    }

    [Theory]
    [InlineData(false, true, true, true, true, false, false, 42UL)]
    [InlineData(true, false, true, true, true, false, false, 42UL)]
    [InlineData(true, true, false, true, true, false, false, 42UL)]
    [InlineData(true, true, true, false, true, false, false, 42UL)]
    [InlineData(true, true, true, true, false, false, false, 42UL)]
    [InlineData(true, true, true, true, true, false, false, 0UL)]
    [InlineData(true, true, true, true, true, true, false, 42UL)]
    [InlineData(true, true, true, true, true, false, true, 42UL)]
    public void MissingOrRecoveryEvidenceCannotProjectHealthyCommit(bool canonical, bool known, bool lease,
        bool ready, bool writable, bool recovery, bool degraded, ulong xid)
    {
        var result = ContainerRuntimeDiagnostics.Project(canonical, known, lease, ready, writable, recovery, degraded, xid);
        Assert.NotEqual(NativeWriteReadiness.CommitReady, result.Readiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, result.ValidationState);
    }
}
