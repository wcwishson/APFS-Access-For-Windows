using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class AgentControlCommandExecutorTests
{
    private const string DeviceId = "device-1";
    private const string VolumeId = "device-1|Main";
    private const string RecoveryIdentity = "apfs-recovery-v1|main";

    [Fact]
    public void UnmountResult_ProofFieldsDefaultToFalse()
    {
        var result = new UnmountResult(false, "E:\\", "not complete");

        Assert.False(result.HostOwnershipReleased);
        Assert.False(result.PendingDurabilityCleared);
    }

    [Fact]
    public async Task ExecuteAsync_ResultUsesSharedFingerprintIncludingExactUtcExpiry()
    {
        var backend = new ScenarioBackend();
        var worker = CreateWorker(backend);
        var expiresAtUtc = new DateTime(2026, 8, 28, 12, 34, 56, DateTimeKind.Utc);
        var request = CreateRequest(
            ApfsControlCommands.Mount,
            new ApfsControlTarget(DeviceId, VolumeId, RecoveryIdentity),
            ApfsControlModes.ReadWrite) with
        {
            ExpiresAtUtc = expiresAtUtc,
        };

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.Equal(ApfsOperationFingerprint.Compute(request), result.Fingerprint);
            Assert.Equal(expiresAtUtc, result.ExpiresAtUtc);
            Assert.NotEqual(
                result.Fingerprint,
                ApfsOperationFingerprint.Compute(request with { ExpiresAtUtc = expiresAtUtc.AddTicks(1) }));
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Mount_UsesExactDeviceAndVolumeAndPreservesRecoveryIdentity()
    {
        var backend = new ScenarioBackend();
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Mount,
            new ApfsControlTarget(DeviceId, VolumeId, RecoveryIdentity),
            ApfsControlModes.ReadWrite);

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.True(result.Success);
            Assert.Equal(ApfsOperationStates.Succeeded, result.State);
            Assert.Equal(ApfsOperationCodes.OperationSucceeded, result.Code);
            Assert.Equal(ApfsControlModes.ReadWrite, result.RequestedMode);
            Assert.Equal(ApfsControlModes.ReadWrite, result.EffectiveMode);
            Assert.Equal(RecoveryIdentity, result.Target!.RecoveryIdentity);
            Assert.Equal(1, backend.MountCalls);
            Assert.Equal(MountAccessMode.ReadWrite, backend.LastMountMode);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Mount_MismatchedRecoveryIdentityIsRejectedBeforeMutation()
    {
        var backend = new ScenarioBackend();
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Mount,
            new ApfsControlTarget(DeviceId, VolumeId, "apfs-recovery-v1|other"),
            ApfsControlModes.ReadWrite);

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.AmbiguousTarget, result.Code);
            Assert.Equal(0, backend.MountCalls);
            Assert.Equal(0, backend.UnmountCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Mount_RecoveryIdentityChangingWhileQueuedIsRejectedBeforeMutation()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        backend.StallNextUnmount();
        var worker = CreateWorker(backend);
        var ejectTask = worker.EjectExactAsync(DeviceId, VolumeId, CancellationToken.None);

        try
        {
            await backend.WaitForUnmountStartedAsync().WaitAsync(TimeSpan.FromSeconds(2));

            var request = CreateRequest(
                ApfsControlCommands.Mount,
                new ApfsControlTarget(DeviceId, VolumeId, RecoveryIdentity),
                ApfsControlModes.ReadWrite);
            var execution = CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            await backend.WaitForSecondVolumeProbeAsync().WaitAsync(TimeSpan.FromSeconds(2));
            backend.CurrentRecoveryIdentity = "apfs-recovery-v1|replacement";
            backend.ReleaseUnmount();
            await ejectTask.WaitAsync(TimeSpan.FromSeconds(2));

            var result = await execution.WaitAsync(TimeSpan.FromSeconds(2));

            Assert.False(result.Success);
            Assert.Equal(0, backend.MountCalls);
            Assert.Contains("recovery identity", result.Diagnostic ?? string.Empty, StringComparison.OrdinalIgnoreCase);
            Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        }
        finally
        {
            backend.ReleaseUnmount();
            await ejectTask.WaitAsync(TimeSpan.FromSeconds(2));
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_RecoveryIdentityIsCheckedByWorkerBeforeMutation()
    {
        var backend = new ScenarioBackend
        {
            CurrentRecoveryIdentity = "apfs-recovery-v1|replacement",
        };
        backend.SetMounted(DegradedMount() with { RecoveryIdentity = backend.CurrentRecoveryIdentity });
        var worker = CreateWorker(backend);

        try
        {
            var result = await worker.EnsureMountedExactAsync(
                DeviceId,
                VolumeId,
                MountAccessMode.ReadWrite,
                CancellationToken.None,
                RecoveryIdentity);

            Assert.False(result.Success);
            Assert.Contains("recovery identity", result.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(0, backend.MountCalls);
            Assert.Equal(0, backend.UnmountCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Mount_ReadWriteFallbackIsReportedAsFailureWithFinalReadOnlyFacts()
    {
        var backend = new ScenarioBackend { ReturnReadOnlyForReadWrite = true };
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Mount,
            new ApfsControlTarget(DeviceId, VolumeId),
            ApfsControlModes.ReadWrite);

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationStates.Failed, result.State);
            Assert.Equal(ApfsOperationCodes.OperationFailed, result.Code);
            Assert.Equal(ApfsControlModes.ReadOnly, result.EffectiveMode);
            Assert.Equal("present", result.MountProof);
            Assert.Contains("read-only", result.Diagnostic ?? string.Empty, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(1, backend.MountCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Mount_MismatchedDeviceAndVolumeDoesNotMutateWorker()
    {
        var backend = new ScenarioBackend();
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Mount,
            new ApfsControlTarget("device-2", VolumeId),
            ApfsControlModes.ReadWrite);

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.AmbiguousTarget, result.Code);
            Assert.Equal(0, backend.MountCalls);
            Assert.Equal(0, backend.UnmountCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Mount_VolumeReportingAnotherDeviceIsRejectedBeforeMutation()
    {
        var backend = new ScenarioBackend { ReturnMismatchedVolumeDeviceId = true };
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Mount,
            new ApfsControlTarget(DeviceId, VolumeId),
            ApfsControlModes.ReadWrite);

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.AmbiguousTarget, result.Code);
            Assert.Equal(0, backend.MountCalls);
            Assert.Equal(0, backend.UnmountCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Mount_MissingTargetIsRejectedBeforeAnyWorkerMutation()
    {
        var backend = new ScenarioBackend();
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Mount,
            new ApfsControlTarget(DeviceId, "device-1|Missing"),
            ApfsControlModes.ReadWrite);

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.MissingVolume, result.Code);
            Assert.Equal(0, backend.MountCalls);
            Assert.Equal(0, backend.UnmountCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_ReportsHealthyReadWriteOnlyAfterAllAuthoritativeFactsSettle()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(DegradedMount());
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(DeviceId, VolumeId));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.True(result.Success);
            Assert.Equal(ApfsOperationCodes.OperationSucceeded, result.Code);
            Assert.Equal("healthy-rw", result.FinalStatus);
            Assert.Equal("inactive", result.RecoveryState);
            Assert.Equal(0, result.DirtyTransactionCount);
            Assert.False(result.PendingDurability);
            Assert.Equal(ApfsControlModes.ReadWrite, result.EffectiveMode);
            Assert.True(backend.UnmountCalls > 0);
            Assert.True(backend.MountCalls > 0);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_DegradedFinalStateIsNotReportedAsSuccess()
    {
        var backend = new ScenarioBackend
        {
            KeepDegradedAfterMount = true,
        };
        backend.SetMounted(DegradedMount());
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(DeviceId, VolumeId));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.BlockedRecovery, result.Code);
            Assert.Equal("degraded", result.FinalStatus);
            Assert.Equal("active", result.RecoveryState);
            Assert.Equal("read-only", result.EffectiveMode);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_CancelledAfterRemountReconcilesHealthyFinalState()
    {
        using var cancellation = new CancellationTokenSource();
        var backend = new ScenarioBackend
        {
            CancelAfterMount = cancellation,
        };
        backend.SetMounted(DegradedMount());
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(DeviceId, VolumeId));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, cancellation.Token);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationStates.Cancelled, result.State);
            Assert.Equal(ApfsOperationCodes.OperationCancelled, result.Code);
            Assert.Equal("healthy-rw", result.FinalStatus);
            Assert.Equal("present", result.MountProof);
            Assert.Equal(ApfsControlModes.ReadWrite, result.EffectiveMode);
            Assert.Equal("inactive", result.RecoveryState);
            Assert.False(result.RecoveryActive);
            Assert.False(result.PendingDurability);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Eject_RequiresExactTargetAndBothUnmountProofs()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Eject,
            new ApfsControlTarget(DeviceId, VolumeId));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.True(result.Success);
            Assert.Equal(ApfsOperationCodes.OperationSucceeded, result.Code);
            Assert.Equal("absent", result.MountProof);
            Assert.Equal("proven", result.OwnershipProof);
            Assert.Equal("proven", result.DurabilityProof);
            Assert.False(result.PendingDurability);
            Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Eject_KnownExactVolumeAlreadyAbsentReturnsAlreadyAchievedWithoutFabricatedProofs()
    {
        var backend = new ScenarioBackend();
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Eject,
            new ApfsControlTarget(DeviceId, VolumeId));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.True(result.Success);
            Assert.Equal(ApfsOperationStates.Succeeded, result.State);
            Assert.Equal(ApfsOperationCodes.AlreadyAchieved, result.Code);
            Assert.Equal("absent", result.FinalStatus);
            Assert.Equal("absent", result.MountProof);
            Assert.Equal("not-proven", result.OwnershipProof);
            Assert.Equal("not-proven", result.DurabilityProof);
            Assert.False(result.PendingDurability);
            Assert.Equal(0, backend.UnmountCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Eject_DuplicateExactMountRowsAreRejectedWithoutClaimingAbsence()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        backend.SetMounted(HealthyMount() with { MountPoint = "F:\\" });
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Eject,
            new ApfsControlTarget(DeviceId, VolumeId, RecoveryIdentity));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationStates.Failed, result.State);
            Assert.Equal(ApfsOperationCodes.AmbiguousTarget, result.Code);
            Assert.Equal("ambiguous", result.FinalStatus);
            Assert.Equal("not-proven", result.MountProof);
            Assert.Equal("not-proven", result.OwnershipProof);
            Assert.Equal("not-proven", result.DurabilityProof);
            Assert.Equal(0, backend.UnmountCalls);
            Assert.Equal(2, (await backend.GetMountStateAsync(CancellationToken.None)).Count);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Eject_RecoveryIdentityIsCheckedByWorkerBeforeUnmount()
    {
        var backend = new ScenarioBackend
        {
            CurrentRecoveryIdentity = "apfs-recovery-v1|replacement",
        };
        backend.SetMounted(HealthyMount() with { RecoveryIdentity = backend.CurrentRecoveryIdentity });
        var worker = CreateWorker(backend);

        try
        {
            var result = await worker.EjectExactAsync(
                DeviceId,
                VolumeId,
                CancellationToken.None,
                RecoveryIdentity);

            Assert.False(result.Success);
            Assert.Contains("recovery identity", result.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(0, backend.UnmountCalls);
            Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Eject_UnknownVolumeRemainsMissingVolumeWithoutMutation()
    {
        var backend = new ScenarioBackend();
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Eject,
            new ApfsControlTarget(DeviceId, "device-1|Missing"));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.MissingVolume, result.Code);
            Assert.Equal(0, backend.MountCalls);
            Assert.Equal(0, backend.UnmountCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Eject_ProofFailureRemainsFailureEvenWhenMountIsRemoved()
    {
        var backend = new ScenarioBackend
        {
            UnmountResponse = new UnmountResult(
                Success: false,
                MountPoint: "",
                Error: "durability was not proven",
                MountRemoved: true),
        };
        backend.SetMounted(HealthyMount());
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Eject,
            new ApfsControlTarget(DeviceId, VolumeId));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.UnsafeOwnership, result.Code);
            Assert.Equal("absent", result.MountProof);
            Assert.Equal("not-proven", result.OwnershipProof);
            Assert.Equal("not-proven", result.DurabilityProof);
            Assert.True(result.PendingDurability);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Eject_CancelledAfterMutationReconcilesFinalStateAndUnmountProofs()
    {
        using var cancellation = new CancellationTokenSource();
        var backend = new ScenarioBackend
        {
            CancelAfterUnmount = cancellation,
        };
        backend.SetMounted(HealthyMount());
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Eject,
            new ApfsControlTarget(DeviceId, VolumeId));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, cancellation.Token);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationStates.Cancelled, result.State);
            Assert.Equal(ApfsOperationCodes.OperationCancelled, result.Code);
            Assert.Equal("absent", result.FinalStatus);
            Assert.Equal("absent", result.MountProof);
            Assert.Equal("proven", result.OwnershipProof);
            Assert.Equal("proven", result.DurabilityProof);
            Assert.False(result.PendingDurability);
            Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Quit_WritesMarkerAndRequiresCompleteShutdownProofs()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        var worker = CreateWorker(backend);
        var markerWrites = 0;
        var executor = CreateExecutor(worker, _ =>
        {
            markerWrites++;
            return true;
        });

        try
        {
            var result = await executor.ExecuteAsync(
                CreateRequest(ApfsControlCommands.Quit, target: null),
                CancellationToken.None);

            Assert.True(result.Success);
            Assert.True(result.QuitMarkerWritten);
            Assert.Equal(1, markerWrites);
            Assert.Equal("shutdown-complete", result.FinalStatus);
            Assert.Equal("no-mounts", result.MountProof);
            Assert.Equal("proven", result.OwnershipProof);
            Assert.Equal("proven", result.DurabilityProof);
            Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Quit_MarkerFailureStillRunsShutdownButCannotSucceed()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker, _ => false);

        try
        {
            var result = await executor.ExecuteAsync(
                CreateRequest(ApfsControlCommands.Quit, target: null),
                CancellationToken.None);

            Assert.False(result.Success);
            Assert.False(result.QuitMarkerWritten);
            Assert.Equal(ApfsOperationCodes.OperationFailed, result.Code);
            Assert.Equal("shutdown-complete", result.FinalStatus);
            Assert.Contains("quit marker", result.Diagnostic ?? string.Empty, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(1, backend.UnmountCalls);
            Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Quit_ShutdownFailureDoesNotClaimOwnershipOrDurability()
    {
        var backend = new ScenarioBackend
        {
            UnmountResponse = new UnmountResult(
                Success: false,
                MountPoint: "",
                Error: "host remained attached",
                MountRemoved: false),
        };
        backend.SetMounted(HealthyMount());
        var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker, _ => true);

        try
        {
            var result = await executor.ExecuteAsync(
                CreateRequest(ApfsControlCommands.Quit, target: null),
                CancellationToken.None);

            Assert.False(result.Success);
            Assert.False(result.PendingDurability);
            Assert.Equal("not-proven", result.OwnershipProof);
            Assert.Equal("not-proven", result.DurabilityProof);
            Assert.NotEqual("shutdown-complete", result.FinalStatus);
            Assert.NotEmpty(await backend.GetMountStateAsync(CancellationToken.None));
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Quit_CancelledAfterUnmountReconcilesShutdownAndTypedProofs()
    {
        using var cancellation = new CancellationTokenSource();
        var backend = new ScenarioBackend
        {
            CancelAfterUnmount = cancellation,
        };
        backend.SetMounted(HealthyMount());
        var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker, _ => true);

        try
        {
            var result = await executor.ExecuteAsync(
                CreateRequest(ApfsControlCommands.Quit, target: null),
                cancellation.Token);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationStates.Cancelled, result.State);
            Assert.Equal(ApfsOperationCodes.OperationCancelled, result.Code);
            Assert.True(result.QuitMarkerWritten);
            Assert.Equal("shutdown-complete", result.FinalStatus);
            Assert.Equal("no-mounts", result.MountProof);
            Assert.Equal("proven", result.OwnershipProof);
            Assert.Equal("proven", result.DurabilityProof);
            Assert.False(result.PendingDurability);
            Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task ExecuteAsync_PropagatesCancellationBeforeMutation()
    {
        var backend = new ScenarioBackend();
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Mount,
            new ApfsControlTarget(DeviceId, VolumeId),
            ApfsControlModes.ReadWrite);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                CreateExecutor(worker).ExecuteAsync(request, cancellation.Token));
            Assert.Equal(0, backend.MountCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Mount_CancelledAfterMutationReconcilesCommittedMountState()
    {
        using var cancellation = new CancellationTokenSource();
        var backend = new ScenarioBackend
        {
            CancelAfterMount = cancellation,
        };
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Mount,
            new ApfsControlTarget(DeviceId, VolumeId),
            ApfsControlModes.ReadWrite);

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, cancellation.Token);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationStates.Cancelled, result.State);
            Assert.Equal(ApfsOperationCodes.OperationCancelled, result.Code);
            Assert.Equal("healthy-rw", result.FinalStatus);
            Assert.Equal("present", result.MountProof);
            Assert.Equal(ApfsControlModes.ReadWrite, result.EffectiveMode);
            Assert.Equal("inactive", result.RecoveryState);
            Assert.False(result.PendingDurability);
            Assert.Equal("not-applicable", result.OwnershipProof);
            Assert.Equal("not-applicable", result.DurabilityProof);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task ExecuteAsync_CancellationDuringUncommittedMutationReturnsReconciledEvidence()
    {
        var backend = new ScenarioBackend { StallMount = true };
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Mount,
            new ApfsControlTarget(DeviceId, VolumeId),
            ApfsControlModes.ReadWrite);
        using var cancellation = new CancellationTokenSource();

        try
        {
            var execution = CreateExecutor(worker).ExecuteAsync(request, cancellation.Token);
            await backend.MountStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
            cancellation.Cancel();

            var result = await execution;

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationStates.Cancelled, result.State);
            Assert.Equal(ApfsOperationCodes.OperationCancelled, result.Code);
            Assert.Equal("absent", result.FinalStatus);
            Assert.Equal("absent", result.MountProof);
            Assert.Equal("not-applicable", result.OwnershipProof);
            Assert.Equal("not-applicable", result.DurabilityProof);
            Assert.Equal(1, backend.MountCalls);
        }
        finally
        {
            backend.AllowMount.TrySetResult();
            worker.Dispose();
        }
    }

    [Fact]
    public async Task ExecuteAsync_RejectsMissingTargetAndUnknownMode()
    {
        var backend = new ScenarioBackend();
        var worker = CreateWorker(backend);

        try
        {
            var missingTarget = await CreateExecutor(worker).ExecuteAsync(
                CreateRequest(
                    ApfsControlCommands.Mount,
                    target: null,
                    requestedMode: ApfsControlModes.ReadWrite),
                CancellationToken.None);
            var unknownMode = await CreateExecutor(worker).ExecuteAsync(
                CreateRequest(
                    ApfsControlCommands.Mount,
                    new ApfsControlTarget(DeviceId, VolumeId),
                    "write-only"),
                CancellationToken.None);

            Assert.Equal(ApfsOperationCodes.InvalidArguments, missingTarget.Code);
            Assert.Equal(ApfsOperationCodes.InvalidArguments, unknownMode.Code);
            Assert.Equal(0, backend.MountCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    private static AgentControlCommandExecutor CreateExecutor(
        ApfsMountWorker worker,
        Func<DateTime, bool>? markerWriter = null)
        => new(worker, markerWriter);

    private static ApfsMountWorker CreateWorker(ScenarioBackend backend)
        => new(
            NullLogger<ApfsMountWorker>.Instance,
            backend,
            new FixedMountPolicy(),
            new RuntimeStatusPublisher(),
            new FixedOptionsMonitor(new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                WriteBackendMode = "Native",
                NativeWritePromotionPolicy = "ScaffoldOnly",
                ReadWriteMode = "RwWithRoFallback",
                NativeHostStopTimeoutSeconds = 1,
            }));

    private static ControlOperationRequestPayload CreateRequest(
        string command,
        ApfsControlTarget? target,
        string? requestedMode = null)
        => new(
            OperationId: Guid.NewGuid().ToString("D"),
            Command: command,
            Target: target,
            RequestedMode: requestedMode,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2));

    private static MountedVolumeState HealthyMount()
        => new(
            VolumeId,
            "E:\\",
            MountAccessMode.ReadWrite,
            VolumeName: "Main",
            DeviceId: DeviceId,
            DeviceDisplayName: "Test APFS Device",
            WriteBackend: "Native",
            NativeWriteReadiness: NativeWriteReadiness.CommitReady,
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            RecoveryActive: false,
            DirtyTransactionCount: 0,
            ShutdownDrainActive: false,
            InFlightMutationCallbacks: 0,
            RecoveryIdentity: RecoveryIdentity);

    private static MountedVolumeState DegradedMount()
        => HealthyMount() with
        {
            AccessMode = MountAccessMode.ReadOnly,
            WriteBackend = "Disabled",
            NativeWriteReadiness = NativeWriteReadiness.Degraded,
            NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback,
            RecoveryActive = true,
            RecoveryReason = "CommitInvariantFailed",
        };

    private sealed class FixedMountPolicy : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters)
        {
            _ = volume;
            _ = usedLetters;
            return 'E';
        }

        public bool ShouldAutoMount(VolumeInfo volume)
        {
            _ = volume;
            return true;
        }
    }

    private sealed class FixedOptionsMonitor(ServiceHostOptions options) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => options;

        public ServiceHostOptions Get(string? name)
        {
            _ = name;
            return options;
        }

        public IDisposable OnChange(Action<ServiceHostOptions, string> listener)
        {
            _ = listener;
            return NoopDisposable.Instance;
        }

        private sealed class NoopDisposable : IDisposable
        {
            public static readonly NoopDisposable Instance = new();
            public void Dispose() { }
        }
    }

    private sealed class ScenarioBackend : IApfsBackend
    {
        private readonly Dictionary<string, MountedVolumeState> _mounts = new(StringComparer.OrdinalIgnoreCase);
        private readonly IReadOnlyList<DeviceInfo> _devices =
        [
            new(DeviceId, "Test APFS Device", true),
        ];
        private readonly Dictionary<string, IReadOnlyList<VolumeInfo>> _volumesByDevice = new(StringComparer.OrdinalIgnoreCase)
        {
            [DeviceId] =
            [
                new VolumeInfo(
                    VolumeId,
                    DeviceId,
                    "Main",
                    SupportsReadWrite: true,
                    SupportsNativeWrite: true,
                    RecoveryIdentity: RecoveryIdentity),
                new VolumeInfo(
                    "device-1|Archive",
                    DeviceId,
                    "Archive",
                    SupportsReadWrite: true,
                    SupportsNativeWrite: true),
            ],
        };

        private int _volumeProbeCalls;
        private TaskCompletionSource _secondVolumeProbe = NewSignal();
        private TaskCompletionSource _unmountStarted = NewSignal();
        private TaskCompletionSource _unmountRelease = NewSignal();
        private bool _stallNextUnmount;

        public int MountCalls { get; private set; }
        public int UnmountCalls { get; private set; }
        public MountAccessMode? LastMountMode { get; private set; }
        public string CurrentRecoveryIdentity { get; set; } = RecoveryIdentity;
        public bool StallMount { get; init; }
        public TaskCompletionSource MountStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource AllowMount { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool ReturnReadOnlyForReadWrite { get; init; }
        public bool KeepDegradedAfterMount { get; init; }
        public bool ReturnMismatchedVolumeDeviceId { get; init; }
        public CancellationTokenSource? CancelAfterMount { get; init; }
        public CancellationTokenSource? CancelAfterUnmount { get; init; }
        public UnmountResult UnmountResponse { get; init; } = new(
            Success: true,
            MountPoint: "",
            Error: null,
            MountRemoved: true,
            HostOwnershipReleased: true,
            PendingDurabilityCleared: true);

        public Task WaitForSecondVolumeProbeAsync() => _secondVolumeProbe.Task;

        public void StallNextUnmount()
        {
            _unmountStarted = NewSignal();
            _unmountRelease = NewSignal();
            _stallNextUnmount = true;
        }

        public Task WaitForUnmountStartedAsync() => _unmountStarted.Task;

        public void ReleaseUnmount() => _unmountRelease.TrySetResult();

        public void SetMounted(MountedVolumeState state)
            => _mounts[state.MountPoint] = state;

        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(_devices);
        }

        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(
            string deviceId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Increment(ref _volumeProbeCalls) == 2)
            {
                _secondVolumeProbe.TrySetResult();
            }

            if (!_volumesByDevice.TryGetValue(deviceId, out var volumes))
            {
                return Task.FromResult<IReadOnlyList<VolumeInfo>>(Array.Empty<VolumeInfo>());
            }

            if (ReturnMismatchedVolumeDeviceId)
            {
                volumes = volumes
                    .Select(volume => volume.VolumeId == VolumeId
                        ? volume with { DeviceId = "device-2" }
                    : volume)
                    .ToArray();
            }

            volumes = volumes
                .Select(volume => volume.VolumeId == VolumeId
                    ? volume with { RecoveryIdentity = CurrentRecoveryIdentity }
                    : volume)
                .ToArray();

            return Task.FromResult(volumes);
        }

        public async Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            MountCalls++;
            LastMountMode = request.AccessMode;
            if (StallMount)
            {
                MountStarted.TrySetResult();
                await AllowMount.Task.WaitAsync(cancellationToken);
            }

            var effectiveMode = request.AccessMode == MountAccessMode.ReadWrite &&
                                (ReturnReadOnlyForReadWrite || KeepDegradedAfterMount)
                ? MountAccessMode.ReadOnly
                : request.AccessMode;
            var degraded = KeepDegradedAfterMount;
            var mountPoint = $"{request.DriveLetter}:\\";
            _mounts[mountPoint] = new MountedVolumeState(
                request.VolumeId,
                mountPoint,
                effectiveMode,
                VolumeName: "Main",
                DeviceId: DeviceId,
                DeviceDisplayName: "Test APFS Device",
                WriteBackend: effectiveMode == MountAccessMode.ReadWrite && !degraded ? "Native" : "Disabled",
                NativeWriteReadiness: effectiveMode == MountAccessMode.ReadWrite && !degraded
                    ? NativeWriteReadiness.CommitReady
                    : NativeWriteReadiness.Degraded,
                NativeWriteSafetyState: effectiveMode == MountAccessMode.ReadWrite && !degraded
                    ? NativeWriteSafetyState.PilotReadWrite
                    : NativeWriteSafetyState.ReadOnlyFallback,
                RecoveryActive: degraded || effectiveMode == MountAccessMode.ReadOnly,
                RecoveryReason: degraded ? "CommitInvariantFailed" : null,
                DirtyTransactionCount: 0,
                ShutdownDrainActive: false,
                InFlightMutationCallbacks: 0,
                RecoveryIdentity: CurrentRecoveryIdentity);
            CancelAfterMount?.Cancel();

            return new MountResult(
                Success: true,
                MountPoint: mountPoint,
                Error: null,
                EffectiveAccessMode: effectiveMode,
                IsReadOnly: effectiveMode == MountAccessMode.ReadOnly,
                WriteEnabled: effectiveMode == MountAccessMode.ReadWrite && !degraded,
                WriteBackend: effectiveMode == MountAccessMode.ReadWrite && !degraded ? "Native" : "Disabled",
                NativeWriteReadiness: effectiveMode == MountAccessMode.ReadWrite && !degraded
                    ? NativeWriteReadiness.CommitReady
                    : NativeWriteReadiness.Degraded,
                NativeWriteSafetyState: effectiveMode == MountAccessMode.ReadWrite && !degraded
                    ? NativeWriteSafetyState.PilotReadWrite
                    : NativeWriteSafetyState.ReadOnlyFallback);
        }

        public async Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            UnmountCalls++;
            if (_stallNextUnmount)
            {
                _stallNextUnmount = false;
                _unmountStarted.TrySetResult();
                await _unmountRelease.Task.WaitAsync(cancellationToken);
            }

            var result = UnmountResponse with { MountPoint = mountPoint };
            if (result.MountRemoved)
            {
                _mounts.Remove(mountPoint);
            }
            CancelAfterUnmount?.Cancel();

            return result;
        }

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<MountedVolumeState>>(_mounts.Values.ToArray());
        }

        private static TaskCompletionSource NewSignal()
            => new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
