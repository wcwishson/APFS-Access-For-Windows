using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    private const string DeviceId = "device-1";
    private const string VolumeId = "device-1|Main";
    private const string RecoveryIdentity = "apfs-recovery-v1|main";

    [Theory]
    [InlineData(ApfsControlCommands.Mount)]
    [InlineData(ApfsControlCommands.Fix)]
    public async Task ProtectedRoleReadWriteRefusalReportsAbsentWithoutClaimingReadOnlyMount(string command)
    {
        var backend = new ScenarioBackend { ProtectedCatalog = true };
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(command,
            new ApfsControlTarget(DeviceId, VolumeId), ApfsControlModes.ReadWrite), CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("absent", result.MountProof);
        Assert.Contains("read/write mount refused", result.Diagnostic);
        Assert.DoesNotContain("final mount is read-only", result.Diagnostic);
        Assert.Equal(0, backend.MountCalls);
        Assert.Equal(0, backend.UnmountCalls);
    }

    [Fact]
    public void UnmountResult_ProofFieldsDefaultToFalse()
    {
        var result = new UnmountResult(false, "E:\\", "not complete");

        Assert.False(result.HostOwnershipReleased);
        Assert.False(result.PendingDurabilityCleared);
        Assert.False(result.ContainerMemberDetached);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Eject_UsesVerifiedMemberDetachWithoutClaimingSharedHostExit(bool detached)
    {
        var first = HealthyMount() with { HostProcessId = 42, HostProcessCreationTimeFileTimeUtc = 12345,
            CatalogContainerUuid = new string('a', 32), MountReady = true };
        var sibling = first with { VolumeId = "device-1|Archive", MountPoint = "F:\\", VolumeName = "Archive",
            RecoveryIdentity = "apfs-recovery-v1-archive" };
        var backend = new ScenarioBackend
        {
            UnmountResponse = new UnmountResult(true, "E:\\", null, true, false, true)
            { ContainerMemberDetached = detached },
        };
        backend.SetMounted(first); backend.SetMounted(sibling);
        using var worker = CreateWorker(backend);

        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(ApfsControlCommands.Eject,
            new ApfsControlTarget(DeviceId, VolumeId, RecoveryIdentity)), CancellationToken.None);

        Assert.Equal(detached, result.Success);
        Assert.Equal(detached ? "proven" : "not-proven", result.OwnershipProof);
        Assert.Equal("proven", result.DurabilityProof);
        Assert.Equal("absent", result.MountProof);
        Assert.Equal(sibling, Assert.Single(await backend.GetMountStateAsync(CancellationToken.None)));
        Assert.Equal(1, backend.UnmountCalls);
    }

    private static readonly string[] DeleteIdentity =
        ["21", "victim", "249", "17", "230", "8293", "8", "250", "20"];

    private static ControlOperationRequestPayload SnapshotRequest(
        string command,
        ApfsControlTarget? target = null,
        string? snapshotName = null,
        IReadOnlyList<string>? snapshotIdentity = null)
        => CreateRequest(command, target ?? new ApfsControlTarget(DeviceId, VolumeId)) with
        {
            SnapshotName = snapshotName,
            SnapshotIdentity = snapshotIdentity,
        };

    [Fact]
    public async Task SnapshotCreate_MissingName_IsInvalidArgumentsWithoutOwnerContact()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            SnapshotRequest(ApfsControlCommands.SnapshotCreate), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, result.Code);
        Assert.Empty(backend.SnapshotCalls);
    }

    [Theory]
    [InlineData("snapshot-delete")]
    [InlineData("snapshot-recover")]
    public async Task SnapshotDeleteRecover_MalformedParameters_AreInvalidArguments(string command)
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker);
        var badIdentity = command == "snapshot-delete"
            ? SnapshotRequest(command, snapshotName: "victim")
            : SnapshotRequest(command, snapshotName: "backup");

        var result = await executor.ExecuteAsync(badIdentity, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, result.Code);
        Assert.Empty(backend.SnapshotCalls);
    }

    [Fact]
    public async Task SnapshotDelete_ShortIdentity_IsInvalidArguments()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            SnapshotRequest(ApfsControlCommands.SnapshotDelete, snapshotIdentity: ["21", "victim"]),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, result.Code);
        Assert.Empty(backend.SnapshotCalls);
    }

    [Fact]
    public async Task SnapshotCreate_UnknownVolume_IsMissingVolume()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            SnapshotRequest(
                ApfsControlCommands.SnapshotCreate,
                new ApfsControlTarget("device-9", "device-9|Ghost"),
                snapshotName: "backup"),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.MissingVolume, result.Code);
        Assert.Empty(backend.SnapshotCalls);
    }

    [Fact]
    public async Task SnapshotCreate_VolumeWithoutContainerIdentity_IsInvalidArguments()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            SnapshotRequest(
                ApfsControlCommands.SnapshotCreate,
                new ApfsControlTarget(DeviceId, "device-1|Archive"),
                snapshotName: "backup"),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, result.Code);
        Assert.Empty(backend.SnapshotCalls);
    }

    [Fact]
    public async Task SnapshotCreate_WithoutLiveSession_IsServiceUnavailable()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            SnapshotRequest(ApfsControlCommands.SnapshotCreate, snapshotName: "backup"),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, result.Code);
        Assert.Equal("absent", result.MountProof);
        Assert.Empty(backend.SnapshotCalls);
    }

    [Fact]
    public async Task SnapshotCreate_WithoutSnapshotBackend_IsServiceUnavailable()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        using var worker = CreateWorker(new NoSnapshotBackend(backend));
        var result = await CreateExecutor(worker).ExecuteAsync(
            SnapshotRequest(ApfsControlCommands.SnapshotCreate, snapshotName: "backup"),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, result.Code);
    }

    [Theory]
    [InlineData(false, "SnapshotMaintenanceOwnerNotReady", ApfsOperationCodes.BlockedRecovery)]
    [InlineData(false, "SnapshotSessionNotWritable", ApfsOperationCodes.BlockedRecovery)]
    [InlineData(false, "VolumeNotPredeclared", ApfsOperationCodes.ServiceUnavailable)]
    [InlineData(false, "ControlEndpointUnavailable", ApfsOperationCodes.ServiceUnavailable)]
    [InlineData(false, "ControlResponseTimeout", ApfsOperationCodes.Timeout)]
    [InlineData(false, "ControlCanceledAfterPublish", ApfsOperationCodes.Timeout)]
    [InlineData(false, "SomethingWeird", ApfsOperationCodes.OperationFailed)]
    public async Task SnapshotCreate_MapsOwnerOutcomes(bool success, string code, string expected)
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        backend.SnapshotResults.Enqueue(new SnapshotControlResult(success, code));
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            SnapshotRequest(ApfsControlCommands.SnapshotCreate, snapshotName: "backup"),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(expected, result.Code);
        var call = Assert.Single(backend.SnapshotCalls);
        Assert.Equal(new string('a', 32), call.ContainerUuid);
        Assert.Equal(101UL, call.VolumeObjectId);
        Assert.Equal(SnapshotControlAction.Create, call.Action);
        Assert.Equal(["backup"], call.Extras);
        if (expected == ApfsOperationCodes.Timeout)
        {
            Assert.True(result.PendingDurability);
            Assert.Equal("not-proven", result.FinalStatus);
            Assert.Equal("not-proven", result.MountProof);
            Assert.Equal("not-proven", result.OwnershipProof);
            Assert.Equal("not-proven", result.DurabilityProof);
        }
    }

    [Fact]
    public async Task SnapshotCreate_Success_ProvesOwnershipAndEcho()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        using var worker = CreateWorker(backend);
        var request = SnapshotRequest(ApfsControlCommands.SnapshotCreate, snapshotName: "backup");
        var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, result.Code);
        Assert.Equal("snapshot-created", result.FinalStatus);
        Assert.Equal("present", result.MountProof);
        Assert.Equal("proven", result.OwnershipProof);
        Assert.Equal("not-applicable", result.DurabilityProof);
        Assert.Equal("backup", result.SnapshotName);
        Assert.Equal(ApfsOperationFingerprint.Compute(request), result.Fingerprint);
    }

    [Fact]
    public async Task SnapshotDelete_Success_SendsNineIdentityLines()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            SnapshotRequest(ApfsControlCommands.SnapshotDelete, snapshotIdentity: DeleteIdentity),
            CancellationToken.None);

        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal("snapshot-deleted", result.FinalStatus);
        var call = Assert.Single(backend.SnapshotCalls);
        Assert.Equal(SnapshotControlAction.Delete, call.Action);
        Assert.Equal(DeleteIdentity, call.Extras);
        Assert.Equal(DeleteIdentity, result.SnapshotIdentity);
    }

    [Fact]
    public async Task SnapshotCreateAndRecover_NeverEmitDeleteAction()
    {
        // Task 6 Step 5: snapshot deletion is explicit-only. Successful create
        // and recover operations must never record a Delete action at the
        // owner endpoint; only the explicit snapshot-delete command may do so.
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        backend.SnapshotResults.Enqueue(new SnapshotControlResult(true, "SnapshotRecoverNoOp"));
        using var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker);

        var recovered = await executor.ExecuteAsync(
            SnapshotRequest(ApfsControlCommands.SnapshotRecover),
            CancellationToken.None);
        Assert.True(recovered.Success, recovered.Diagnostic);
        var created = await executor.ExecuteAsync(
            SnapshotRequest(ApfsControlCommands.SnapshotCreate, snapshotName: "backup"),
            CancellationToken.None);
        Assert.True(created.Success, created.Diagnostic);

        Assert.Equal(2, backend.SnapshotCalls.Count);
        Assert.DoesNotContain(backend.SnapshotCalls, call => call.Action == SnapshotControlAction.Delete);
    }

    // The scripted keeper operates on the same mock source selected in inventory.
    private const string TestImagePath = DeviceId;

    private static ControlOperationRequestPayload ManagementRequest(
        string command,
        string? operation = ApfsManagementOperations.RenameVolume,
        string? token = null,
        string? name = null,
        string? quotaBytes = null,
        string? reserveBytes = null,
        string? imagePath = null)
        => CreateRequest(command, new ApfsControlTarget(DeviceId, VolumeId)) with
        {
            ManagementOperation = operation,
            ManagementToken = token,
            ManagementName = name,
            ManagementQuotaBytes = quotaBytes,
            ManagementReserveBytes = reserveBytes,
            ManagementImagePath = imagePath,
        };

    [Fact]
    public async Task ManagementPlan_UnmountedTarget_IssuesDryRunPlan()
    {
        // Task 11 Step 2: dry-run issuance binds the live-row identity and
        // the observed container generation without mounting or mutating.
        var backend = new ScenarioBackend { TopologyCheckpointXid = "90" };
        using var worker = CreateWorker(backend);
        var request = ManagementRequest(ApfsControlCommands.ManagementPlan);
        var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, result.Code);
        Assert.Equal("management-plan-issued", result.FinalStatus);
        Assert.Equal("absent", result.MountProof);
        Assert.Equal("proven", result.OwnershipProof);
        Assert.Equal("not-applicable", result.DurabilityProof);
        Assert.Equal(ApfsOperationFingerprint.Compute(request), result.Fingerprint);
        Assert.Equal(ApfsManagementOperations.RenameVolume, result.ManagementOperation);
        Assert.StartsWith("mgmt-plan-v1:", result.ManagementPlanId, StringComparison.Ordinal);
        Assert.Equal(64, result.ManagementToken!.Length);
        Assert.Equal("90", result.ManagementObservedXid);
        Assert.Empty(backend.SnapshotCalls);
        Assert.Equal(0, backend.MountCalls);
        Assert.Equal(0, backend.UnmountCalls);
    }

    [Fact]
    public async Task ManagementPlan_MountedTarget_RequiresQuiesce()
    {
        var backend = new ScenarioBackend { TopologyCheckpointXid = "90" };
        backend.SetMounted(HealthyMount());
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, result.Code);
        Assert.Equal("quiesce-required", result.FinalStatus);
        Assert.Equal("present", result.MountProof);
        Assert.Empty(backend.SnapshotCalls);
        Assert.Equal(0, backend.MountCalls);
        Assert.Equal(0, backend.UnmountCalls);
    }

    [Theory]
    [InlineData("volume-create")]
    [InlineData("volume-delete")]
    [InlineData(null)]
    public async Task ManagementPlan_UnknownOperation_Refused(string? operation)
    {
        var backend = new ScenarioBackend { TopologyCheckpointXid = "90" };
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan, operation), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, result.Code);
        Assert.Empty(backend.SnapshotCalls);
    }

    [Fact]
    public async Task ManagementPlan_WithoutTopology_CheckpointUnobservable()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, result.Code);
        Assert.Equal("checkpoint-unobservable", result.FinalStatus);
        Assert.Equal("absent", result.MountProof);
        Assert.Equal("proven", result.OwnershipProof);
        Assert.Empty(backend.SnapshotCalls);
    }

    [Fact]
    public async Task ManagementApply_UnknownToken_RefusedWithoutOwnerContact()
    {
        var backend = new ScenarioBackend { TopologyCheckpointXid = "90" };
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: new string('a', 64), name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, result.Code);
        Assert.Equal("invalid", result.FinalStatus);
        Assert.Empty(backend.SnapshotCalls);
        Assert.Equal(0, backend.MountCalls);
    }

    [Fact]
    public async Task ManagementApply_CheckpointDrift_ConflictsAndKeepsTokenLive()
    {
        var backend = new ScenarioBackend { TopologyCheckpointXid = "90" };
        using var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        backend.TopologyCheckpointXid = "91";
        var stale = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken, name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);
        Assert.False(stale.Success);
        Assert.Equal(ApfsOperationCodes.OperationConflict, stale.Code);
        Assert.Equal("stale-checkpoint", stale.FinalStatus);
        Assert.Equal("91", stale.ManagementObservedXid);

        backend.TopologyCheckpointXid = "90";
        var fresh = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken, name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);
        Assert.False(fresh.Success);
        Assert.Equal("keeper-unavailable", fresh.FinalStatus);
    }

    [Fact]
    public async Task ManagementApply_FullPath_KeeperUnavailableAndBurnsToken()
    {
        var backend = new ScenarioBackend { TopologyCheckpointXid = "90" };
        using var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var applyRequest = ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken, name: "Renamed", imagePath: TestImagePath);
        var apply = await executor.ExecuteAsync(applyRequest, CancellationToken.None);
        Assert.False(apply.Success);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, apply.Code);
        Assert.Equal("keeper-unavailable", apply.FinalStatus);
        Assert.Equal("absent", apply.MountProof);
        Assert.Equal("proven", apply.OwnershipProof);
        Assert.Equal(ApfsManagementOperations.RenameVolume, apply.ManagementOperation);
        Assert.Equal(plan.ManagementToken, apply.ManagementToken);
        Assert.Equal("90", apply.ManagementObservedXid);
        Assert.Equal("Renamed", apply.ManagementName);
        Assert.Equal(ApfsOperationFingerprint.Compute(applyRequest), apply.Fingerprint);
        Assert.Empty(backend.SnapshotCalls);
        Assert.Equal(0, backend.MountCalls);

        var replay = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken, name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);
        Assert.False(replay.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, replay.Code);
    }

    [Fact]
    public async Task ManagementApply_RenameMissingName_RefusedBeforeConsume()
    {
        var backend = new ScenarioBackend { TopologyCheckpointXid = "90" };
        using var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var bad = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken),
            CancellationToken.None);
        Assert.False(bad.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, bad.Code);

        var good = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken, name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);
        Assert.Equal("keeper-unavailable", good.FinalStatus);
    }

    [Fact]
    public async Task ManagementApply_QuotaValues_RevalidatedAtExecutor()
    {
        var backend = new ScenarioBackend { TopologyCheckpointXid = "90" };
        using var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan, ApfsManagementOperations.SetQuotaReserve),
            CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var bad = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, ApfsManagementOperations.SetQuotaReserve,
                token: plan.ManagementToken, quotaBytes: "01"),
            CancellationToken.None);
        Assert.False(bad.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, bad.Code);

        var good = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, ApfsManagementOperations.SetQuotaReserve,
                token: plan.ManagementToken, quotaBytes: "65536", reserveBytes: "20480",
                imagePath: TestImagePath),
            CancellationToken.None);
        Assert.Equal("keeper-unavailable", good.FinalStatus);
        Assert.Equal("65536", good.ManagementQuotaBytes);
        Assert.Equal("20480", good.ManagementReserveBytes);
        Assert.Equal(TestImagePath, good.ManagementImagePath);
    }

    [Fact]
    public async Task ManagementApply_QuotaKeeperCommits_AppliesWithEchoes()
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        backend.EnqueueQuota(new ManagementKeeperQuotaResult(true, 95, ManagementKeeperCodes.Committed, "ok"));
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan, ApfsManagementOperations.SetQuotaReserve),
            CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);
        var applyRequest = ManagementRequest(ApfsControlCommands.ManagementApply,
            ApfsManagementOperations.SetQuotaReserve, token: plan.ManagementToken,
            quotaBytes: "65536", reserveBytes: "20480", imagePath: TestImagePath);

        var apply = await executor.ExecuteAsync(applyRequest, CancellationToken.None);

        Assert.True(apply.Success, apply.Diagnostic);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, apply.Code);
        Assert.Equal("management-applied", apply.FinalStatus);
        Assert.Equal("absent", apply.MountProof);
        Assert.Equal("proven", apply.OwnershipProof);
        Assert.Equal("proven", apply.DurabilityProof);
        Assert.Equal(ApfsOperationFingerprint.Compute(applyRequest), apply.Fingerprint);
        Assert.Equal(ApfsManagementOperations.SetQuotaReserve, apply.ManagementOperation);
        Assert.Equal(plan.ManagementToken, apply.ManagementToken);
        Assert.Equal(plan.ManagementPlanId, apply.ManagementPlanId);
        Assert.Equal("95", apply.ManagementObservedXid);
        Assert.Equal("65536", apply.ManagementQuotaBytes);
        Assert.Equal("20480", apply.ManagementReserveBytes);
        Assert.Equal(TestImagePath, apply.ManagementImagePath);
        var call = Assert.Single(backend.QuotaCalls);
        Assert.Equal(TestImagePath, call.ImagePath);
        Assert.Equal(new string('a', 32), call.ContainerUuid);
        Assert.Equal(new string('b', 32), call.VolumeUuid);
        Assert.Equal("101", call.VolumeObjectId);
        Assert.Equal("90", call.PreimageXid);
        Assert.Equal("65536", call.QuotaBytes);
        Assert.Equal("20480", call.ReserveBytes);
        // The fake topology carries one sibling (Archive/102) besides the
        // target (Main/101); the keeper census must list exactly it.
        Assert.Equal(["102"], call.SiblingObjectIds);
        Assert.Equal(TestJournalRoot, call.JournalRoot);
    }

    [Fact]
    public async Task ManagementApply_QuotaKeeperStale_ConflictsAndBurnsToken()
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        backend.EnqueueQuota(new ManagementKeeperQuotaResult(false, 0, ManagementKeeperCodes.StalePreimage, "moved"));
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan, ApfsManagementOperations.SetQuotaReserve),
            CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var apply = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, ApfsManagementOperations.SetQuotaReserve,
                token: plan.ManagementToken, quotaBytes: "65536", reserveBytes: "20480",
                imagePath: TestImagePath),
            CancellationToken.None);

        Assert.False(apply.Success);
        Assert.Equal(ApfsOperationCodes.OperationConflict, apply.Code);
        Assert.Equal("stale-checkpoint", apply.FinalStatus);
        Assert.Single(backend.QuotaCalls);

        var replay = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, ApfsManagementOperations.SetQuotaReserve,
                token: plan.ManagementToken, quotaBytes: "65536", reserveBytes: "20480",
                imagePath: TestImagePath),
            CancellationToken.None);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, replay.Code);
    }

    [Fact]
    public async Task ManagementApply_QuotaKeeperRefused_Fails()
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        backend.EnqueueQuota(new ManagementKeeperQuotaResult(false, 0, ManagementKeeperCodes.Refused, "over limit"));
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan, ApfsManagementOperations.SetQuotaReserve),
            CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var apply = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, ApfsManagementOperations.SetQuotaReserve,
                token: plan.ManagementToken, quotaBytes: "65536", reserveBytes: "20480",
                imagePath: TestImagePath),
            CancellationToken.None);

        Assert.False(apply.Success);
        Assert.Equal(ApfsOperationCodes.OperationFailed, apply.Code);
        Assert.Equal("keeper-refused", apply.FinalStatus);
        Assert.Contains("over limit", apply.Diagnostic, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ManagementApply_QuotaWithoutJournalRoot_KeeperUnavailable()
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        using var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan, ApfsManagementOperations.SetQuotaReserve),
            CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var apply = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, ApfsManagementOperations.SetQuotaReserve,
                token: plan.ManagementToken, quotaBytes: "65536", reserveBytes: "20480",
                imagePath: TestImagePath),
            CancellationToken.None);

        Assert.False(apply.Success);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, apply.Code);
        Assert.Equal("keeper-unavailable", apply.FinalStatus);
        Assert.Empty(backend.QuotaCalls);
    }

    private static readonly string TestJournalRoot = Directory.CreateDirectory(
        Path.Combine(Path.GetTempPath(), "keeper-journals-" + Guid.NewGuid().ToString("N"))).FullName;

    [Fact]
    public async Task ManagementApply_RenameMissingImagePath_RefusedWithTokenLive()
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        backend.Enqueue(new ManagementKeeperRenameResult(false, 0,
            ManagementKeeperCodes.KeeperUnavailable, "no keeper here"));
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var bad = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken, name: "Renamed"),
            CancellationToken.None);
        Assert.False(bad.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, bad.Code);
        Assert.Empty(backend.KeeperCalls);

        var good = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken,
                name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);
        Assert.Equal("keeper-unavailable", good.FinalStatus);
    }

    [Fact]
    public async Task ManagementApply_RenameKeeperCommits_AppliesWithEchoes()
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        backend.Enqueue(new ManagementKeeperRenameResult(true, 91, ManagementKeeperCodes.Committed, "ok"));
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);
        var applyRequest = ManagementRequest(ApfsControlCommands.ManagementApply,
            token: plan.ManagementToken, name: "Renamed", imagePath: TestImagePath);

        var apply = await executor.ExecuteAsync(applyRequest, CancellationToken.None);

        Assert.True(apply.Success, apply.Diagnostic);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, apply.Code);
        Assert.Equal("management-applied", apply.FinalStatus);
        Assert.Equal("absent", apply.MountProof);
        Assert.Equal("proven", apply.OwnershipProof);
        Assert.Equal("proven", apply.DurabilityProof);
        Assert.Equal(ApfsOperationFingerprint.Compute(applyRequest), apply.Fingerprint);
        Assert.Equal(ApfsManagementOperations.RenameVolume, apply.ManagementOperation);
        Assert.Equal(plan.ManagementToken, apply.ManagementToken);
        Assert.Equal(plan.ManagementPlanId, apply.ManagementPlanId);
        Assert.Equal("91", apply.ManagementObservedXid);
        Assert.Equal("Renamed", apply.ManagementName);
        Assert.Equal(TestImagePath, apply.ManagementImagePath);
        var call = Assert.Single(backend.KeeperCalls);
        Assert.Equal(TestImagePath, call.ImagePath);
        Assert.Equal(new string('a', 32), call.ContainerUuid);
        Assert.Equal(new string('b', 32), call.VolumeUuid);
        Assert.Equal("101", call.VolumeObjectId);
        Assert.Equal("90", call.PreimageXid);
        Assert.Equal("Renamed", call.NewLabel);
        Assert.Equal(TestJournalRoot, call.JournalRoot);
    }

    [Fact]
    public async Task ManagementApply_RenameKeeperStale_Conflicts()
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        backend.Enqueue(new ManagementKeeperRenameResult(false, 0, ManagementKeeperCodes.StalePreimage, "moved"));
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var apply = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken,
                name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);

        Assert.False(apply.Success);
        Assert.Equal(ApfsOperationCodes.OperationConflict, apply.Code);
        Assert.Equal("stale-checkpoint", apply.FinalStatus);
        Assert.Single(backend.KeeperCalls);
    }

    [Fact]
    public async Task ManagementApply_RenameKeeperRefused_Fails()
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        backend.Enqueue(new ManagementKeeperRenameResult(false, 0, ManagementKeeperCodes.Refused, "nope"));
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var apply = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken,
                name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);

        Assert.False(apply.Success);
        Assert.Equal(ApfsOperationCodes.OperationFailed, apply.Code);
        Assert.Equal("keeper-refused", apply.FinalStatus);
        Assert.Contains("nope", apply.Diagnostic, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ManagementApply_RenameUnprovenDispatchPreservesRecoveryUncertainty()
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        backend.Enqueue(new ManagementKeeperRenameResult(false, 0, ManagementKeeperCodes.Unproven, "Original dispatch boundary unknown"));
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker, managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);
        var request = ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken,
            name: "Renamed", imagePath: TestImagePath);
        var apply = await executor.ExecuteAsync(request, CancellationToken.None);
        Assert.False(apply.Success);
        Assert.Equal(ApfsOperationCodes.BlockedRecovery, apply.Code);
        Assert.Equal("management-outcome-unproven", apply.FinalStatus);
        Assert.True(apply.PendingDurability);
        Assert.Equal("not-proven", apply.OwnershipProof);
        Assert.Equal("not-proven", apply.DurabilityProof);
        Assert.Single(backend.KeeperCalls);
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult,
            apply, apply.OperationId, PipeSchemaVersions.Schema2)).IsValid);
        var spent = await executor.ExecuteAsync(request with { OperationId = Guid.NewGuid().ToString("D") }, CancellationToken.None);
        Assert.False(spent.Success);Assert.Single(backend.KeeperCalls);
    }

    [Fact]
    public async Task ManagementApply_RenameWithoutJournalRoot_KeeperUnavailableAndBurnsToken()
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        using var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var apply = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken,
                name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);

        Assert.False(apply.Success);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, apply.Code);
        Assert.Equal("keeper-unavailable", apply.FinalStatus);
        Assert.Empty(backend.KeeperCalls);

        var replay = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken,
                name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, replay.Code);
    }

    [Fact]
    public async Task ManagementApply_RenameWithoutKeeperBackend_KeeperUnavailable()
    {
        var backend = new ScenarioBackend { TopologyCheckpointXid = "90" };
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var apply = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken,
                name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);

        Assert.False(apply.Success);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, apply.Code);
        Assert.Equal("keeper-unavailable", apply.FinalStatus);
        Assert.Empty(backend.SnapshotCalls);
    }

    [Fact]
    public async Task ManagementApply_RenameMountedTarget_QuiesceBeforeKeeper()
    {
        var inner = new ScenarioBackend { TopologyCheckpointXid = "90" };
        inner.SetMounted(HealthyMount());
        var backend = new KeeperBackend(inner);
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);

        var apply = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: new string('a', 64),
                name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);

        Assert.False(apply.Success);
        Assert.Equal("quiesce-required", apply.FinalStatus);
        Assert.Empty(backend.KeeperCalls);
    }

    [Fact]
    public async Task ManagementApply_QuotaKeeperReportsUnavailable()
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        backend.EnqueueQuota(new ManagementKeeperQuotaResult(false, 0,
            ManagementKeeperCodes.KeeperUnavailable, "no quota endpoint"));
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan, ApfsManagementOperations.SetQuotaReserve),
            CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        var apply = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, ApfsManagementOperations.SetQuotaReserve,
                token: plan.ManagementToken, quotaBytes: "65536", reserveBytes: "20480",
                imagePath: TestImagePath),
            CancellationToken.None);

        Assert.False(apply.Success);
        Assert.Equal(ApfsOperationCodes.ServiceUnavailable, apply.Code);
        Assert.Equal("keeper-unavailable", apply.FinalStatus);
        Assert.Single(backend.QuotaCalls);
    }

    [Theory]
    [InlineData("backup")]
    [InlineData("system")]
    public async Task ManagementPlan_ProtectedRoleVolume_Refused(string role)
    {
        // Task 6 Step 5: protected roles are never management targets, on
        // the plan path or the apply path. Resolution succeeds (identity
        // and topology are valid); only the role gate refuses, before any
        // quiesce probe, checkpoint observation, or plan issuance.
        var backend = new KeeperBackend(new ScenarioBackend
        {
            TopologyCheckpointXid = "90",
            TopologyProtectedRole = role,
        });
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var result = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, result.Code);
        Assert.Equal("invalid", result.FinalStatus);
        Assert.Contains($"special-role:{role}", result.Diagnostic, StringComparison.Ordinal);
        Assert.Null(result.ManagementPlanId);
        Assert.Null(result.ManagementToken);
        Assert.Empty(backend.KeeperCalls);
        Assert.Empty(backend.QuotaCalls);
    }

    [Theory]
    [InlineData("backup")]
    [InlineData("system")]
    public async Task ManagementApply_ProtectedRoleVolume_RefusedBeforeToken(string role)
    {
        var backend = new KeeperBackend(new ScenarioBackend
        {
            TopologyCheckpointXid = "90",
            TopologyProtectedRole = role,
        });
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var result = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: new string('a', 64),
                name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, result.Code);
        Assert.Contains($"special-role:{role}", result.Diagnostic, StringComparison.Ordinal);
        Assert.Empty(backend.KeeperCalls);
        Assert.Empty(backend.QuotaCalls);
    }

    [Fact]
    public async Task ManagementApply_RoleFlipAfterPlan_RefusedAndTokenStaysLive()
    {
        // TOCTOU shape: a plan issued while ordinary must refuse after
        // the row flips to protected, without consuming the token; once
        // the row flips back, the same token still confirms.
        var inner = new ScenarioBackend { TopologyCheckpointXid = "90" };
        var backend = new KeeperBackend(inner);
        backend.Enqueue(new ManagementKeeperRenameResult(false, 0,
            ManagementKeeperCodes.KeeperUnavailable, "no keeper here"));
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);
        Assert.True(plan.Success, plan.Diagnostic);

        inner.TopologyProtectedRole = "backup";
        var refused = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken,
                name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);
        Assert.False(refused.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, refused.Code);
        Assert.Contains("special-role:backup", refused.Diagnostic, StringComparison.Ordinal);
        Assert.Empty(backend.KeeperCalls);

        inner.TopologyProtectedRole = null;
        var replay = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementApply, token: plan.ManagementToken,
                name: "Renamed", imagePath: TestImagePath),
            CancellationToken.None);
        Assert.Equal("keeper-unavailable", replay.FinalStatus);
        Assert.Single(backend.KeeperCalls);
    }

    [Fact]
    public async Task ManagementPlan_MountedProtectedVolume_RefusedByRoleBeforeQuiesce()
    {
        var inner = new ScenarioBackend { TopologyCheckpointXid = "90", TopologyProtectedRole = "backup" };
        inner.SetMounted(HealthyMount());
        var backend = new KeeperBackend(inner);
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker,
            managementJournalRoot: TestJournalRoot);
        var result = await executor.ExecuteAsync(
            ManagementRequest(ApfsControlCommands.ManagementPlan), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, result.Code);
        Assert.Equal("invalid", result.FinalStatus);
        Assert.Contains("special-role:backup", result.Diagnostic, StringComparison.Ordinal);
        Assert.Empty(backend.KeeperCalls);
    }

    [Fact]
    public async Task SnapshotRecover_Noop_SucceedsWithDistinctFinalStatus()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        backend.SnapshotResults.Enqueue(new SnapshotControlResult(true, "SnapshotRecoverNoOp"));
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            SnapshotRequest(ApfsControlCommands.SnapshotRecover),
            CancellationToken.None);

        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal("snapshot-recover-noop", result.FinalStatus);
        Assert.Equal("proven", result.OwnershipProof);
    }

    [Fact]
    public async Task SnapshotCreate_UnexpectedAcknowledgement_IsOperationFailed()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        backend.SnapshotResults.Enqueue(new SnapshotControlResult(true, "Bizarre"));
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            SnapshotRequest(ApfsControlCommands.SnapshotCreate, snapshotName: "backup"),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.OperationFailed, result.Code);
    }

    [Fact]
    public async Task SnapshotCreate_CancelledBeforeTerminalEvidence()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        backend.NeverCompleteSnapshot = true;
        using var worker = CreateWorker(backend);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        var result = await CreateExecutor(worker).ExecuteAsync(
            SnapshotRequest(ApfsControlCommands.SnapshotCreate, snapshotName: "backup"),
            cancellation.Token);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationStates.Cancelled, result.State);
        Assert.Equal(ApfsOperationCodes.OperationCancelled, result.Code);
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
    public async Task Fix_DegradedImageTargetPointsAtOfflineVerifyAndRepair()
    {
        const string imageDevice = @"D:\repair-image.apfs";
        const string imageVolume = @"D:\repair-image.apfs|Main";
        var backend = new ScenarioBackend
        {
            KeepDegradedAfterMount = true,
            ImageDeviceId = imageDevice,
            ImageVolumeId = imageVolume,
        };
        backend.SetMounted(DegradedMount() with { DeviceId = imageDevice, VolumeId = imageVolume });
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(imageDevice, imageVolume));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.BlockedRecovery, result.Code);
            Assert.Contains("APFSAccess.Cli.exe verify --help", result.Diagnostic);
            Assert.Contains(imageDevice, result.Diagnostic);
            Assert.Contains("separate repair command", result.Diagnostic);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_DegradedPhysicalTargetOmitsOfflineRepairPointer()
    {
        const string physicalDevice = @"\\.\PhysicalDrive2";
        const string physicalVolume = @"\\.\PhysicalDrive2|Main";
        var backend = new ScenarioBackend
        {
            KeepDegradedAfterMount = true,
            ImageDeviceId = physicalDevice,
            ImageVolumeId = physicalVolume,
        };
        backend.SetMounted(DegradedMount() with { DeviceId = physicalDevice, VolumeId = physicalVolume });
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(physicalDevice, physicalVolume));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);
            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.BlockedRecovery, result.Code);
            Assert.Contains("Fix did not prove the exact volume reached healthy read-write state.", result.Diagnostic);
            Assert.DoesNotContain("separate repair command", result.Diagnostic);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_VerifyCompleteHealthyMount_SucceedsWithVerifyNote()
    {
        // Task 10 Step 5: verify-first runs the read-only verifier on the
        // exact derived scope. Success also requires a fresh retained-image
        // owner and its complete live verification after the remount.
        const string imageDevice = @"D:\verify-image.apfs";
        const string imageVolume = @"D:\verify-image.apfs|Main";
        var inner = new ScenarioBackend
        {
            ImageDeviceId = imageDevice,
            ImageVolumeId = imageVolume,
            ImageTopologyXid = "90",
        };
        var backend = new VerifyBackend(inner);
        backend.Enqueue(new ImageVerifyResult(true, "Complete", 0, 0, null));
        var original = DegradedMount() with { DeviceId = imageDevice, VolumeId = imageVolume,
            HostProcessId = 6201, HostProcessCreationTimeFileTimeUtc = LiveFixOwnerCreationTime };
        inner.SetMounted(original);
        var liveBackend = new ImageFixBackend(inner, backend, advanceCheckpoints: false);
        var journalRoot = Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!, "fix-root-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(journalRoot);
        var worker = CreateWorker(liveBackend, journalRoot);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(imageDevice, imageVolume));

        try
        {
            var volume = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == imageDevice).Volumes.Single();
            liveBackend.FinalOwner = ImageFixProofOwner(volume, "90");
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.True(result.Success, result.Diagnostic);
            Assert.Equal(ApfsOperationCodes.OperationSucceeded, result.Code);
            Assert.Equal("healthy-rw", result.FinalStatus);
            Assert.Contains("verify:complete", result.Diagnostic);
            var call = Assert.Single(backend.VerifyCalls);
            Assert.Equal(imageDevice, call.ImagePath);
            Assert.Equal("apfs-container:" + new string('a', 32), call.ContainerId);
            Assert.Equal(new string('b', 32), call.VolumeUuid);
            Assert.Equal("101", call.VolumeObjectId);
            Assert.Equal("90", call.CheckpointXid);
            Assert.Equal("0", call.StoreOffsetBytes);
            Assert.Equal("100000000000", call.StoreSizeBytes);
            var live = Assert.Single(liveBackend.LiveCalls);
            Assert.Equal("retained-image", live.SourceKind);
            Assert.Equal(liveBackend.FinalOwner.VolumeVerificationScope, live);
            Assert.Equal(call.CheckpointXid, live.CheckpointXid);
            Assert.True(Assert.Single(liveBackend.Reports).Complete);
            Assert.True(liveBackend.FinalOwner.HostProcessCreationTimeFileTimeUtc > 0);
            Assert.NotEqual(original.HostProcessId, liveBackend.FinalOwner.HostProcessId);
            Assert.NotEqual(original.HostProcessCreationTimeFileTimeUtc, liveBackend.FinalOwner.HostProcessCreationTimeFileTimeUtc);
            Assert.Equal(new[] { "unmount", "offline", "mount", "live" }, liveBackend.Events);
            AssertWireResult(result);

            liveBackend.FinalOwner = liveBackend.FinalOwner with { HostProcessCreationTimeFileTimeUtc = 0 };
            backend.Enqueue(new ImageVerifyResult(true, "Complete", 0, 0, null));
            var missingIncarnation = await CreateExecutor(worker).ExecuteAsync(
                CreateRequest(ApfsControlCommands.Fix, request.Target), CancellationToken.None);
            Assert.False(missingIncarnation.Success);
            Assert.Equal(ApfsOperationCodes.BlockedRecovery, missingIncarnation.Code);
            Assert.Equal("verification-not-complete", missingIncarnation.FinalStatus);
            Assert.Equal("present", missingIncarnation.MountProof);
            Assert.Equal(ApfsControlModes.ReadWrite, missingIncarnation.EffectiveMode);
            Assert.Equal(2, backend.VerifyCalls.Count);
            Assert.Single(liveBackend.LiveCalls);
            AssertWireResult(missingIncarnation);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_VerifyFindingsDegradedMount_BlockedWithFindingsAndPointer()
    {
        // Findings do not change the mount-health verdict, but they must
        // surface with the exact count plus the offline repair pointer,
        // even though the mount gate already failed.
        const string imageDevice = @"D:\verify-image.apfs";
        const string imageVolume = @"D:\verify-image.apfs|Main";
        var inner = new ScenarioBackend
        {
            KeepDegradedAfterMount = true,
            ImageDeviceId = imageDevice,
            ImageVolumeId = imageVolume,
            ImageTopologyXid = "90",
        };
        var backend = new VerifyBackend(inner);
        backend.Enqueue(new ImageVerifyResult(true, "Incomplete", 3, 3, null));
        inner.SetMounted(DegradedMount() with { DeviceId = imageDevice, VolumeId = imageVolume });
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(imageDevice, imageVolume));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.BlockedRecovery, result.Code);
            Assert.Contains("verify:findings:3", result.Diagnostic);
            Assert.Contains("APFSAccess.Cli.exe verify --help", result.Diagnostic);
            Assert.Contains(imageDevice, result.Diagnostic);
            Assert.Single(backend.VerifyCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_VerifyFindings_BlockWithoutRemount()
    {
        // A retry that could mount healthily must not conceal verified damage.
        const string imageDevice = @"D:\verify-image.apfs";
        const string imageVolume = @"D:\verify-image.apfs|Main";
        var inner = new ScenarioBackend
        {
            ImageDeviceId = imageDevice,
            ImageVolumeId = imageVolume,
            ImageTopologyXid = "90",
        };
        var backend = new VerifyBackend(inner);
        backend.Enqueue(new ImageVerifyResult(true, "Incomplete", 3, 1, null));
        inner.SetMounted(DegradedMount() with { DeviceId = imageDevice, VolumeId = imageVolume });
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(imageDevice, imageVolume));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal("verification-not-complete", result.FinalStatus);
            Assert.Equal(0, inner.MountCalls);
            Assert.Empty(await inner.GetMountStateAsync(default));
            Assert.Contains("verify:findings:1", result.Diagnostic);
            Assert.Contains("APFSAccess.Cli.exe verify --help", result.Diagnostic);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_VerifyRefused_ReportsMountTruth()
    {
        const string imageDevice = @"D:\verify-image.apfs";
        const string imageVolume = @"D:\verify-image.apfs|Main";
        var inner = new ScenarioBackend
        {
            KeepDegradedAfterMount = true,
            ImageDeviceId = imageDevice,
            ImageVolumeId = imageVolume,
            ImageTopologyXid = "90",
        };
        var backend = new VerifyBackend(inner);
        backend.Enqueue(new ImageVerifyResult(true, "Refused", 4, 0, null));
        inner.SetMounted(DegradedMount() with { DeviceId = imageDevice, VolumeId = imageVolume });
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(imageDevice, imageVolume));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.BlockedRecovery, result.Code);
            Assert.Contains("verify:refused", result.Diagnostic);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_VerifySkippedIdentityIncompleteCannotWriteWithoutInspectedRoot()
    {
        // Missing scope cannot turn an uninspected image into RW access.
        const string imageDevice = @"D:\verify-image.apfs";
        const string imageVolume = @"D:\verify-image.apfs|Main";
        var inner = new ScenarioBackend
        {
            ImageDeviceId = imageDevice,
            ImageVolumeId = imageVolume,
        };
        var backend = new VerifyBackend(inner);
        inner.SetMounted(DegradedMount() with { DeviceId = imageDevice, VolumeId = imageVolume });
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(imageDevice, imageVolume));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.BlockedRecovery, result.Code);
            Assert.NotEqual(MountAccessMode.ReadWrite, inner.LastMountMode);
            Assert.Contains("verify:skipped:IdentityIncomplete", result.Diagnostic);
            Assert.Empty(backend.VerifyCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_VerifySkippedNoTopology_KeepsLegacyBehavior()
    {
        // The default device row carries catalog identity but no admitted
        // topology. "device-1" is not a local image path, so derivation
        // stops at NonImageTarget (checked before NoTopology; pinned by
        // VerifyScopeDerivationTests.Derive_NonImageTarget_Refused) and
        // fix proceeds.
        var inner = new ScenarioBackend();
        var backend = new VerifyBackend(inner);
        backend.Enqueue(new ImageVerifyResult(true, "Complete", 0, 0, null));
        inner.SetMounted(DegradedMount());
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(DeviceId, VolumeId));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.True(result.Success);
            Assert.Contains("verify:skipped:NonImageTarget", result.Diagnostic);
            Assert.Empty(backend.VerifyCalls);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_VerifyUnsupportedBackend_BlocksWithoutDisturbingMount()
    {
        var inner = new ScenarioBackend
        {
            ImageDeviceId = @"D:\verify-image.apfs",
            ImageVolumeId = @"D:\verify-image.apfs|Main",
            ImageTopologyXid = "90",
        };
        var backend = new NoVerifyBackend(inner);
        inner.SetMounted(DegradedMount() with { DeviceId = @"D:\verify-image.apfs", VolumeId = @"D:\verify-image.apfs|Main" });
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(@"D:\verify-image.apfs", @"D:\verify-image.apfs|Main"));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(0, inner.UnmountCalls);
            Assert.Equal(0, inner.MountCalls);
            Assert.Contains("verify:unsupported", result.Diagnostic);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_VerifyBackendError_BlocksWithoutRemount()
    {
        // Tool failure cannot authorize a mount-health retry for a covered image.
        const string imageDevice = @"D:\verify-image.apfs";
        const string imageVolume = @"D:\verify-image.apfs|Main";
        var inner = new ScenarioBackend
        {
            ImageDeviceId = imageDevice,
            ImageVolumeId = imageVolume,
            ImageTopologyXid = "90",
        };
        var backend = new VerifyBackend(inner);
        backend.EnqueueThrow(new IOException("observer exploded"));
        inner.SetMounted(DegradedMount() with { DeviceId = imageDevice, VolumeId = imageVolume });
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(imageDevice, imageVolume));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal("verification-not-complete", result.FinalStatus);
            Assert.Equal(0, inner.MountCalls);
            Assert.Contains("verify:error:IOException", result.Diagnostic);
        }
        finally
        {
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Fix_VerifyPhysicalTarget_SkipsWithoutPointer()
    {
        const string physicalDevice = @"\\.\PhysicalDrive2";
        const string physicalVolume = @"\\.\PhysicalDrive2|Main";
        var inner = new ScenarioBackend
        {
            KeepDegradedAfterMount = true,
            ImageDeviceId = physicalDevice,
            ImageVolumeId = physicalVolume,
        };
        var backend = new VerifyBackend(inner);
        inner.SetMounted(DegradedMount() with { DeviceId = physicalDevice, VolumeId = physicalVolume });
        var worker = CreateWorker(backend);
        var request = CreateRequest(
            ApfsControlCommands.Fix,
            new ApfsControlTarget(physicalDevice, physicalVolume));

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(request, CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.BlockedRecovery, result.Code);
            Assert.Contains("verify:skipped:PhysicalTarget", result.Diagnostic);
            Assert.DoesNotContain("separate repair command", result.Diagnostic);
            Assert.Empty(backend.VerifyCalls);
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

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Quit_SharedHostReproofReportsOwnershipAndDurabilityIndependently(bool terminalOwnershipReleased)
    {
        var backend = new ScenarioBackend();
        var owner = HealthyMount() with { HostProcessId = 1234, HostProcessCreationTimeFileTimeUtc = 134048736000000000 };
        backend.SetMounted(owner);
        backend.SetMounted(owner with { VolumeId = "device-1|Archive", MountPoint = "F:\\" });
        var safe = backend.UnmountResponse;
        backend.UnmountResponses.Enqueue(safe with { HostOwnershipReleased = false });
        backend.UnmountResponses.Enqueue(safe);
        backend.TerminalResponses.Enqueue(safe with { HostOwnershipReleased = terminalOwnershipReleased });
        using var worker = CreateWorker(backend);

        var result = await CreateExecutor(worker, _ => true).ExecuteAsync(
            CreateRequest(ApfsControlCommands.Quit, target: null), CancellationToken.None);

        Assert.Equal(2, backend.UnmountCalls);
        Assert.Equal(owner, Assert.Single(backend.TerminalQueries));
        Assert.Equal(terminalOwnershipReleased, result.Success);
        Assert.Equal(terminalOwnershipReleased ? "shutdown-complete" : "shutdown-incomplete", result.FinalStatus);
        Assert.Equal("no-mounts", result.MountProof);
        Assert.Equal(terminalOwnershipReleased ? "proven" : "not-proven", result.OwnershipProof);
        Assert.Equal("proven", result.DurabilityProof);
        Assert.False(result.PendingDurability);
        if (terminalOwnershipReleased) Assert.True(string.IsNullOrWhiteSpace(result.Diagnostic));
        else Assert.Contains("terminal proof", result.Diagnostic, StringComparison.OrdinalIgnoreCase);
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

    [Theory]
    [InlineData("volume-create")]
    [InlineData("volume-delete")]
    [InlineData("volume-format")]
    [InlineData("manage")]
    public async Task ExecuteAsync_RejectsUnimplementedManagementVerbs(string command)
    {
        // Topology mutations have no service operation until Task 11 lands
        // each keeper slice behind the management gate. Unknown verbs must
        // fail closed before touching any worker or mount.
        var backend = new ScenarioBackend();
        var worker = CreateWorker(backend);

        try
        {
            var result = await CreateExecutor(worker).ExecuteAsync(
                CreateRequest(command, new ApfsControlTarget(DeviceId, VolumeId)),
                CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.UnknownCommand, result.Code);
            Assert.Equal(0, backend.MountCalls);
            Assert.Equal(0, backend.UnmountCalls);
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

    private static readonly ApfsControlTarget ContainerTarget =
        new(DeviceId, string.Empty, null, null, new string('a', 32));

    private static readonly ApfsControlTarget DeviceTarget =
        new(DeviceId, string.Empty);

    [Theory]
    [InlineData(ApfsControlModes.ReadWrite, MountAccessMode.ReadWrite, false)]
    [InlineData(ApfsControlModes.ReadOnly, MountAccessMode.ReadOnly, false)]
    [InlineData(ApfsControlModes.ReadWrite, MountAccessMode.ReadWrite, true)]
    [InlineData(ApfsControlModes.ReadOnly, MountAccessMode.ReadOnly, true)]
    public async Task ContainerMount_ExplicitBatch_DispatchesOnlyExactContainerInRequestedMode(
        string mode, MountAccessMode expectedMode, bool autoMountEnabled)
    {
        var inner = new ScenarioBackend
        {
            TopologyCheckpointXid = "7",
            ImageDeviceId = "foreign-device",
            ImageVolumeId = "foreign-volume",
        };
        var backend = new BatchScenarioBackend(inner);
        using var worker = CreateWorker(backend, autoMountEnabled: autoMountEnabled);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.ContainerMount, ContainerTarget, mode), timeout.Token);

        Assert.True(result.Success, result.Diagnostic);
        var batch = Assert.Single(backend.Batches);
        Assert.Equal(2, batch.Count);
        Assert.Equal(new[] { "device-1|Archive", VolumeId }, batch.Select(x => x.VolumeId).Order());
        Assert.All(batch, request => Assert.Equal(expectedMode, request.AccessMode));
        Assert.Equal(2, batch.Select(x => x.DriveLetter).Distinct().Count());
        Assert.DoesNotContain(await inner.GetMountStateAsync(CancellationToken.None), x => x.DeviceId == "foreign-device");

        if (!autoMountEnabled)
        {
            await worker.RefreshAsync(false, CancellationToken.None);
            Assert.Single(backend.Batches);
            Assert.Equal(2, inner.MountCalls);
        }
    }

    [Fact]
    public async Task ContainerMount_ReobservedIdentityChanged_RefusesBeforeBatch()
    {
        var inner = new ScenarioBackend { TopologyCheckpointXid = "7" };
        var backend = new BatchScenarioBackend(inner)
        {
            BeforeInventory = call => { if (call == 3) inner.CurrentRecoveryIdentity = "changed-identity"; },
        };
        using var worker = CreateWorker(backend, autoMountEnabled: false);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.ContainerMount, ContainerTarget, ApfsControlModes.ReadWrite), timeout.Token);
        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.OperationFailed, result.Code);
        Assert.Contains("identity changed", result.Diagnostic);
        Assert.Empty(backend.Batches);
        Assert.Equal(0, inner.MountCalls);
    }

    [Fact]
    public async Task ContainerMount_CancelledAfterFirstMember_PreservesCommittedMount()
    {
        using var cancellation = new CancellationTokenSource();
        var inner = new ScenarioBackend { TopologyCheckpointXid = "7", CancelAfterMount = cancellation };
        var backend = new BatchScenarioBackend(inner);
        using var worker = CreateWorker(backend, autoMountEnabled: false);
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.ContainerMount, ContainerTarget, ApfsControlModes.ReadOnly), cancellation.Token);
        Assert.False(result.Success);
        Assert.Equal(ApfsOperationStates.Cancelled, result.State);
        Assert.Equal(1, inner.MountCalls);
        Assert.Equal(0, inner.UnmountCalls);
        var retained = Assert.Single(await inner.GetMountStateAsync(CancellationToken.None));
        Assert.Equal("device-1|Archive", retained.VolumeId);
        Assert.Equal(MountAccessMode.ReadOnly, retained.AccessMode);
        await worker.RefreshAsync(false, CancellationToken.None);
        Assert.Single(backend.Batches);
        Assert.Equal(1, inner.MountCalls);
        Assert.Single(await inner.GetMountStateAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ContainerMount_ExplicitRemountBypassesAutoReconnectPolicyAndPreservesForeignMount()
    {
        var inner = new ScenarioBackend { TopologyCheckpointXid = "7", ImageDeviceId = "foreign-device", ImageVolumeId = "foreign-volume" };
        inner.SetMounted(HealthyMount() with { DeviceId = "foreign-device", VolumeId = "foreign-volume", MountPoint = "Z:\\" });
        var backend = new BatchScenarioBackend(inner);
        using var worker = CreateWorker(backend, autoMountEnabled: false, autoRemount: false);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        for (var attempt = 0; attempt < 2; ++attempt)
        {
            var result = await CreateExecutor(worker).ExecuteAsync(
                CreateRequest(ApfsControlCommands.ContainerMount, ContainerTarget,
                    attempt == 0 ? ApfsControlModes.ReadWrite : ApfsControlModes.ReadOnly), timeout.Token);
            Assert.True(result.Success, result.Diagnostic);
        }
        Assert.Equal(2, backend.Batches.Count);
        Assert.Equal(4, inner.MountCalls);
        Assert.Equal(2, inner.UnmountCalls);
        Assert.Contains(await inner.GetMountStateAsync(CancellationToken.None), x => x.DeviceId == "foreign-device" && x.MountPoint == "Z:\\");
    }

    [Fact]
    public async Task ContainerMount_CancelledBatch_ReleasesWorkerAndDoesNotMountForeignVolume()
    {
        var inner = new ScenarioBackend { TopologyCheckpointXid = "7" };
        var backend = new BatchScenarioBackend(inner) { StallBatch = true };
        using var worker = CreateWorker(backend, autoMountEnabled: false);
        using var cancellation = new CancellationTokenSource();
        var pending = CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.ContainerMount, ContainerTarget, ApfsControlModes.ReadOnly), cancellation.Token);
        try
        {
            await backend.BatchStarted.Task.WaitAsync(TimeSpan.FromSeconds(3));
            cancellation.Cancel();
            var cancelled = await pending;
            Assert.False(cancelled.Success);
            Assert.Equal(ApfsOperationStates.Cancelled, cancelled.State);
            Assert.Equal(0, inner.MountCalls);
            backend.StallBatch = false;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var retry = await CreateExecutor(worker).ExecuteAsync(
                CreateRequest(ApfsControlCommands.ContainerMount, ContainerTarget, ApfsControlModes.ReadOnly), timeout.Token);
            Assert.True(retry.Success, retry.Diagnostic);
            Assert.Equal(2, inner.MountCalls);
        }
        finally
        {
            cancellation.Cancel();
            await pending;
        }
    }

    [Fact]
    public async Task ContainerMount_MountsEligibleMembersWithPerVolumeTokens()
    {
        // Idempotency fast path: the eligible member is already mounted in
        // the requested mode, so no worker mount call runs. The eject +
        // scoped batch + poll convergence path has separate regression
        // coverage above without requiring a background worker cycle.
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(
            ApfsControlCommands.ContainerMount, ContainerTarget, ApfsControlModes.ReadWrite),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, result.Code);
        Assert.Equal("container-mounted", result.FinalStatus);
        Assert.Equal(ApfsControlModes.ReadWrite, result.RequestedMode);
        Assert.Equal(ApfsControlModes.ReadWrite, result.EffectiveMode);
        Assert.Equal("present", result.MountProof);
        Assert.Contains("vol:device-1|Main=mounted", result.Diagnostic);
        Assert.Equal(0, backend.MountCalls);
    }

    [Fact]
    public async Task ContainerMount_SkipsIneligibleMemberButSucceeds()
    {
        var backend = new ScenarioBackend { IncludeBackupSameContainerMember = true };
        backend.SetMounted(HealthyMount());
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(
            ApfsControlCommands.ContainerMount, ContainerTarget, ApfsControlModes.ReadWrite),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("container-mounted", result.FinalStatus);
        Assert.Contains("skipped:device-1|Backup:ineligible", result.Diagnostic);
        Assert.Contains("vol:device-1|Main=mounted", result.Diagnostic);
        Assert.Equal(0, backend.MountCalls);
    }

    [Fact]
    public async Task ContainerMount_ReadOnlyVerifiesInspectableMembers()
    {
        var backend = new ScenarioBackend { IncludeBackupSameContainerMember = true };
        backend.SetMounted(HealthyMount() with { AccessMode = MountAccessMode.ReadOnly });
        backend.SetMounted(HealthyMount() with
        {
            VolumeId = "device-1|Backup",
            MountPoint = "F:\\",
            VolumeName = "Backup",
            AccessMode = MountAccessMode.ReadOnly,
        });
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(
            ApfsControlCommands.ContainerMount, ContainerTarget, ApfsControlModes.ReadOnly),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("container-mounted", result.FinalStatus);
        Assert.Equal(ApfsControlModes.ReadOnly, result.EffectiveMode);
        Assert.Equal(0, backend.MountCalls);
    }

    [Fact]
    public async Task ContainerMount_NoEligibleMembers_IsInvalidArgumentsWithoutAttempt()
    {
        var backend = new ScenarioBackend { ProtectedCatalog = true };
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(
            ApfsControlCommands.ContainerMount, ContainerTarget, ApfsControlModes.ReadWrite),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, result.Code);
        Assert.Equal(0, backend.MountCalls);
    }

    [Fact]
    public async Task ContainerMount_UnknownContainer_IsMissingVolumeWithoutAttempt()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var unknown = ContainerTarget with { ContainerUuid = new string('b', 32) };
        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(
            ApfsControlCommands.ContainerMount, unknown, ApfsControlModes.ReadWrite),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.MissingVolume, result.Code);
        Assert.Equal(0, backend.MountCalls);
    }

    [Fact]
    public async Task ContainerMount_VolumeIdPresent_IsAmbiguousTarget()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var mixed = new ApfsControlTarget(DeviceId, VolumeId, null, null, new string('a', 32));
        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(
            ApfsControlCommands.ContainerMount, mixed, ApfsControlModes.ReadWrite),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.AmbiguousTarget, result.Code);
        Assert.Equal(0, backend.MountCalls);
    }

    [Fact]
    public async Task ContainerMount_MissingMode_IsInvalidArguments()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.ContainerMount, ContainerTarget),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, result.Code);
        Assert.Equal(0, backend.MountCalls);
    }

    [Fact]
    public async Task ContainerUnmount_ReleasesMountedMembersAndKeepsOthers()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        backend.SetMounted(HealthyMount() with
        {
            VolumeId = "device-1|Archive",
            MountPoint = "F:\\",
            VolumeName = "Archive",
        });
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.ContainerUnmount, ContainerTarget),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, result.Code);
        Assert.Equal("container-unmounted", result.FinalStatus);
        Assert.Equal("absent", result.MountProof);
        Assert.Equal("proven", result.OwnershipProof);
        Assert.Equal("proven", result.DurabilityProof);
        Assert.Contains("vol:device-1|Main=detached", result.Diagnostic);
        Assert.Equal(1, backend.UnmountCalls);
        var remaining = await backend.GetMountStateAsync(CancellationToken.None);
        var leftover = Assert.Single(remaining);
        Assert.Equal("device-1|Archive", leftover.VolumeId);
    }

    [Fact]
    public async Task ContainerUnmount_NothingMounted_IsAlreadyAchieved()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.ContainerUnmount, ContainerTarget),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(ApfsOperationCodes.AlreadyAchieved, result.Code);
        Assert.Equal("container-unmounted", result.FinalStatus);
        Assert.Equal("absent", result.MountProof);
        Assert.Equal(0, backend.UnmountCalls);
    }

    [Fact]
    public async Task ContainerUnmount_MemberRefuses_IsUnsafeOwnership()
    {
        var backend = new ScenarioBackend
        {
            UnmountResponse = new UnmountResult(
                Success: true,
                MountPoint: "",
                Error: "busy",
                MountRemoved: false,
                HostOwnershipReleased: false,
                PendingDurabilityCleared: false),
        };
        backend.SetMounted(HealthyMount());
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.ContainerUnmount, ContainerTarget),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.UnsafeOwnership, result.Code);
        var remaining = await backend.GetMountStateAsync(CancellationToken.None);
        Assert.Single(remaining);
    }

    [Fact]
    public async Task DeviceEject_UnmountsContainerAndReportsTokens()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount());
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.DeviceEject, DeviceTarget),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, result.Code);
        Assert.Equal("device-ejected", result.FinalStatus);
        Assert.Equal("absent", result.MountProof);
        Assert.Equal("proven", result.OwnershipProof);
        Assert.Equal("proven", result.DurabilityProof);
        Assert.Contains("vol:device-1|Main=detached", result.Diagnostic);
        Assert.Equal(1, backend.UnmountCalls);
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
    }

    [Fact]
    public async Task DeviceEject_NothingMounted_IsAlreadyAchieved()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.DeviceEject, DeviceTarget),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(ApfsOperationCodes.AlreadyAchieved, result.Code);
        Assert.Equal("device-ejected", result.FinalStatus);
        Assert.Equal(0, backend.UnmountCalls);
    }

    [Fact]
    public async Task DeviceEject_MountedUnattributedVolume_FailsClosed()
    {
        var backend = new ScenarioBackend();
        backend.SetMounted(HealthyMount() with
        {
            VolumeId = "device-1|Archive",
            MountPoint = "F:\\",
            VolumeName = "Archive",
        });
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.DeviceEject, DeviceTarget),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.AmbiguousTarget, result.Code);
        Assert.Contains("device-1|Archive", result.Diagnostic);
        Assert.Equal(0, backend.UnmountCalls);
    }

    [Fact]
    public async Task DeviceEject_UnknownDevice_IsMissingVolume()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var unknown = DeviceTarget with { DeviceId = "device-9" };
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.DeviceEject, unknown),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.MissingVolume, result.Code);
        Assert.Equal(0, backend.UnmountCalls);
    }

    [Fact]
    public async Task DeviceEject_ScopedTarget_IsAmbiguousTarget()
    {
        var backend = new ScenarioBackend();
        using var worker = CreateWorker(backend);
        var scoped = new ApfsControlTarget(DeviceId, "device-1|Main", null, null, new string('a', 32));
        var result = await CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.DeviceEject, scoped),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.AmbiguousTarget, result.Code);
        Assert.Equal(0, backend.UnmountCalls);
    }

    private static ApfsMountWorker CreateWorker(IApfsBackend backend, string? managementJournalRoot = null, bool enableImageResizeFormat = false,
        bool? enableImageManagementMutations = null, bool autoMountEnabled = true, bool autoRemount = true)
        => new(
            NullLogger<ApfsMountWorker>.Instance,
            backend,
            new FixedMountPolicy(),
            new RuntimeStatusPublisher(),
            new FixedOptionsMonitor(new ServiceHostOptions
            {
                AutoMountEnabled = autoMountEnabled,
                NativeAutoRemountOnReconnect = autoRemount,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                WriteBackendMode = "Native",
                NativeWritePromotionPolicy = "ScaffoldOnly",
                ReadWriteMode = "RwWithRoFallback",
                NativeHostStopTimeoutSeconds = 1,
                ManagementJournalRoot = managementJournalRoot,
                EnableImageResizeFormat = enableImageResizeFormat,
                EnableImageManagementMutations = enableImageManagementMutations ?? managementJournalRoot is not null,
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
            RecoveryIdentity: RecoveryIdentity,
            SnapshotInventorySupported: true, SnapshotMutationSupported: true, SnapshotRecoverySupported: true);

    private static MountedVolumeState DegradedMount()
        => HealthyMount() with
        {
            AccessMode = MountAccessMode.ReadOnly,
            WriteBackend = "Disabled",
            NativeWriteReadiness = NativeWriteReadiness.Degraded,
            NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback,
            RecoveryActive = true,
            RecoveryReason = "CommitInvariantFailed",
            // Legacy offline/remount scenarios do not model a retained native owner.
            SnapshotRecoverySupported = false,
        };

    private sealed class FixedMountPolicy : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters)
        {
            _ = volume;
            // First free letter from E onward (E stays the single-mount
            // letter, so every existing single-mount scenario is unchanged;
            // container-wide tests need distinct letters per member).
            for (var letter = 'E'; letter <= 'Z'; letter++)
            {
                if (!usedLetters.Contains(letter))
                    return letter;
            }

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

    private sealed class BatchScenarioBackend(ScenarioBackend inner) : IApfsBackend, IContainerMountBackend
    {
        public List<IReadOnlyList<MountRequest>> Batches { get; } = [];
        public bool StallBatch { get; set; }
        public Action<int>? BeforeInventory { get; init; }
        private int _inventoryCalls;
        public TaskCompletionSource BatchStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => inner.ProbeDevicesAsync(token);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => inner.ProbeVolumesAsync(device, token);
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            BeforeInventory?.Invoke(++_inventoryCalls);
            return inner.ProbeInventoryAsync(authoritative, token);
        }
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token) => inner.MountAsync(request, token);
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token) => inner.UnmountAsync(point, token);
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token) => inner.GetMountStateAsync(token);
        public async Task<IReadOnlyList<MountResult>> MountContainerAsync(IReadOnlyList<MountRequest> requests, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Batches.Add(requests.ToArray());
            BatchStarted.TrySetResult();
            if (StallBatch) await Task.Delay(Timeout.Infinite, token);
            var results = new List<MountResult>();
            foreach (var request in requests) results.Add(await inner.MountAsync(request, token));
            return results;
        }
    }

    private sealed class ScenarioBackend : IApfsBackend, ISnapshotControlBackend, ILiveVolumeVerificationBackend,
        ApfsAccess.Backend.Native.IUnmountTerminalStateBackend
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
                    RecoveryIdentity: RecoveryIdentity,
                    CatalogContainerUuid: new string('a', 32),
                    CatalogVolumeObjectId: 101,
                    CatalogVolumeUuid: new string('b', 32)),
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
        public bool ProtectedCatalog { get; init; }
        public bool IncludeBackupSameContainerMember { get; init; }
        public bool KeepDegradedAfterMount { get; init; }
        public bool ReturnMismatchedVolumeDeviceId { get; init; }
        // Optional second device shaped like an image file (or any custom
        // IDs), served alongside the fixed device-1 inventory. Null by
        // default, so every existing scenario is byte-identical.
        public string? ImageDeviceId { get; init; }
        public string? ImageVolumeId { get; init; }
        public CancellationTokenSource? CancelAfterMount { get; init; }
        public CancellationTokenSource? CancelAfterUnmount { get; init; }
        public Action? AfterUnmountAction { get; init; }
        public UnmountResult UnmountResponse { get; init; } = new(
            Success: true,
            MountPoint: "",
            Error: null,
            MountRemoved: true,
            HostOwnershipReleased: true,
            PendingDurabilityCleared: true);

        public Queue<UnmountResult> UnmountResponses { get; } = new();
        public Queue<UnmountResult> TerminalResponses { get; } = new();
        public List<MountedVolumeState> TerminalQueries { get; } = [];

        public Task<UnmountResult> GetUnmountTerminalStateAsync(MountedVolumeState selected, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            TerminalQueries.Add(selected);
            return Task.FromResult(TerminalResponses.Count > 0
                ? TerminalResponses.Dequeue() with { MountPoint = selected.MountPoint }
                : new UnmountResult(false, selected.MountPoint, "No terminal proof was supplied.", false, false, false));
        }

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
            if (ImageDeviceId is null || ImageVolumeId is null) return Task.FromResult(_devices);
            return Task.FromResult<IReadOnlyList<DeviceInfo>>(
            [
                .._devices,
                new(ImageDeviceId, "Test image device", true),
            ]);
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

            if (ImageDeviceId is not null && ImageVolumeId is not null &&
                string.Equals(deviceId, ImageDeviceId, StringComparison.OrdinalIgnoreCase))
            {
                // Opt-in image topology for Task 10 verify-first tests: the
                // image row carries the same catalog identity the topology
                // snapshot binds, so scope derivation succeeds end to end.
                // Null (default) keeps the legacy identity-less image row.
                var imageVolume = new VolumeInfo(
                    ImageVolumeId,
                    ImageDeviceId,
                    "Main",
                    SupportsReadWrite: true,
                    SupportsNativeWrite: true);
                if (ImageTopologyXid is not null)
                {
                    // TopologyAdmission.Validate binds the row through
                    // CatalogVolumeId plus the catalog verdict trio, so the
                    // image row must carry the same complete verdict the
                    // fixed device-1 rows get from WithTopologyCatalog.
                    imageVolume = imageVolume with
                    {
                        CatalogVolumeId = TopologyVolumeId(101),
                        CatalogContainerUuid = TopologyContainerHex,
                        CatalogVolumeUuid = TopologyMainUuid,
                        CatalogVolumeObjectId = 101,
                        RecoveryIdentity = CurrentRecoveryIdentity,
                        CatalogDecision = ApfsCapabilityDecision.Writable,
                        CatalogReasons = [],
                        CatalogAutoMountAllowed = true,
                    };
                }

                return Task.FromResult<IReadOnlyList<VolumeInfo>>([imageVolume]);
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

            // Opt-in second member of the fixed container for Task 12
            // container-wide tests: readable special-role, so read-write
            // requests skip it while read-only requests attempt it. False by
            // default, so every existing scenario is byte-identical.
            if (IncludeBackupSameContainerMember)
            {
                volumes = [.. volumes, new VolumeInfo(
                    "device-1|Backup",
                    DeviceId,
                    "Backup",
                    SupportsReadWrite: true,
                    RecoveryIdentity: CurrentRecoveryIdentity,
                    CatalogDecision: ApfsCapabilityDecision.Readable,
                    CatalogReasons: ["special-role:backup"],
                    CatalogAutoMountAllowed: false,
                    CatalogContainerUuid: new string('a', 32))];
            }

            if (ProtectedCatalog)
                volumes = volumes.Select(volume => volume with
                {
                    CatalogDecision = ApfsCapabilityDecision.Readable,
                    CatalogReasons = ["special-role:system"],
                    CatalogAutoMountAllowed = false,
                }).ToArray();
            return Task.FromResult(volumes);
        }

        // Opt-in topology bearing the container checkpoint generation for
        // Task 11 management tests. Null by default, so every existing
        // scenario keeps the older topology-less inventory contract. When
        // set, the fixed rows are enriched with the catalog verdicts the
        // snapshot graph requires, and the snapshot is a complete valid
        // single-container graph (Validate-passing by construction).
        public string? TopologyCheckpointXid { get; set; }

        public string? TopologyProtectedRole { get; set; }

        // Opt-in topology for the image device (Task 10 verify-first).
        // Null (default) keeps the legacy topology-less image inventory.
        public string? ImageTopologyXid { get; set; }

        private const string TopologyContainerHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        private const string TopologyMainUuid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        private const string TopologyArchiveUuid = "cccccccccccccccccccccccccccccccc";
        private const string TopologyDiskId = "apfs-disk:test";
        private const string TopologyPartitionUuid = "11111111-2222-3333-4444-555555555555";

        private static string TopologyContainerId => "apfs-container:" + TopologyContainerHex;

        private static string TopologyStoreId => "apfs-store:" + TopologyPartitionUuid;

        private static string TopologyVolumeId(ulong oid)
            => $"apfs-vol:{TopologyContainerHex}:{oid.ToString(System.Globalization.CultureInfo.InvariantCulture)}";

        private ApfsTopologySnapshot BuildTopologySnapshot(string checkpointXid, string? diskDeviceId = null)
        {
            var partitionId = "apfs-part:" + TopologyPartitionUuid;
            var store = new ApfsStoreRecord(
                TopologyStoreId, TopologyContainerHex, partitionId, TopologyContainerId, 0, 100000000000, 4096, null, null);
            var container = new ApfsContainerRecord(
                TopologyContainerId, TopologyContainerHex, 4096,
                [TopologyStoreId],
                [TopologyVolumeId(101), TopologyVolumeId(102)],
                false, checkpointXid, [], [], []);
            ApfsVolumeRecord Volume(ulong oid, string uuid, string name, string superblockXid)
                => new(TopologyVolumeId(oid), uuid,
                    oid.ToString(System.Globalization.CultureInfo.InvariantCulture), TopologyContainerId,
                    name, true, ["data"], 64, null, "CaseSensitive", "none", false,
                    [], [], [], "7", superblockXid);
            return new ApfsTopologySnapshot(
                [new ApfsDiskRecord(TopologyDiskId, diskDeviceId ?? DeviceId, null, 200000000000)],
                [new ApfsPartitionRecord(partitionId, TopologyPartitionUuid, TopologyDiskId, 1, 0, 100000000000, "7C3457EF-0000-11AA-AA11-00306543ECAC", "Apple_APFS")],
                [store],
                [container],
                [Volume(101, TopologyMainUuid, "Main", checkpointXid),
                    Volume(102, TopologyArchiveUuid, "Archive", checkpointXid)],
                []);
        }

        private IReadOnlyList<VolumeInfo> WithTopologyCatalog(IReadOnlyList<VolumeInfo> volumes)
        {
            if (TopologyCheckpointXid is null) return volumes;
            // Opt-in protected role for the target row (Task 6 backup-role
            // safety): the row carries a proven-protected verdict while the
            // topology graph itself stays valid, so resolution succeeds and
            // only the role gate refuses. Null (default) keeps every
            // existing scenario on the ordinary eligible-Data contract.
            ApfsCapabilityDecision decision = ApfsCapabilityDecision.Writable;
            IReadOnlyList<string> reasons = [];
            bool? autoMount = true;
            if (TopologyProtectedRole is not null)
            {
                decision = ApfsCapabilityDecision.Readable;
                reasons = [$"special-role:{TopologyProtectedRole}"];
                autoMount = false;
            }

            return volumes.Select(volume => volume.VolumeId switch
            {
                VolumeId => volume with
                {
                    CatalogVolumeId = TopologyVolumeId(101),
                    CatalogContainerUuid = TopologyContainerHex,
                    CatalogVolumeUuid = TopologyMainUuid,
                    CatalogVolumeObjectId = 101,
                    CatalogDecision = decision,
                    CatalogReasons = reasons,
                    CatalogAutoMountAllowed = autoMount,
                },
                "device-1|Archive" => volume with
                {
                    CatalogVolumeId = TopologyVolumeId(102),
                    CatalogContainerUuid = TopologyContainerHex,
                    CatalogVolumeUuid = TopologyArchiveUuid,
                    CatalogVolumeObjectId = 102,
                    CatalogDecision = ApfsCapabilityDecision.Writable,
                    CatalogReasons = [],
                    CatalogAutoMountAllowed = true,
                },
                _ => volume,
            }).ToArray();
        }

        public async Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(
            bool authoritative,
            CancellationToken cancellationToken)
        {
            SnapshotInventoryProbeCalls++;
            var devices = await ProbeDevicesAsync(cancellationToken).ConfigureAwait(false);
            var inventory = new List<DeviceInventory>();
            foreach (var device in devices.Where(d => d.IsConnected))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var volumes = WithTopologyCatalog(
                    await ProbeVolumesAsync(device.DeviceId, cancellationToken).ConfigureAwait(false));
                ApfsDiscoveryTopology? topology = null;
                if (TopologyCheckpointXid is not null &&
                    string.Equals(device.DeviceId, DeviceId, StringComparison.OrdinalIgnoreCase))
                {
                    topology = new ApfsDiscoveryTopology(
                        1, device.DeviceId, [TopologyDiskId], BuildTopologySnapshot(TopologyCheckpointXid));
                }

                if (ImageTopologyXid is not null && ImageDeviceId is not null &&
                    string.Equals(device.DeviceId, ImageDeviceId, StringComparison.OrdinalIgnoreCase))
                {
                    // The image topology disk must be bound to the image
                    // device itself: reusing the fixed device-1 disk makes
                    // TopologyAdmission.Validate fail and the Task 12
                    // SelectedControlTarget gate correctly refuses with
                    // ambiguous-target before verify-first can run.
                    topology = new ApfsDiscoveryTopology(
                        1, device.DeviceId, [TopologyDiskId], BuildTopologySnapshot(ImageTopologyXid, device.DeviceId));
                }

                inventory.Add(new(device, volumes, topology));
            }

            cancellationToken.ThrowIfCancellationRequested();
            return inventory;
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
            // Record the true owning device for the mounted volume (looked
            // up from this backend's own inventory): exact-mount matching
            // is device-qualified, and a hardcoded device would make every
            // non-default device unmatchable after a successful remount.
            var deviceId = DeviceId;
            var recoveryIdentity = CurrentRecoveryIdentity;
            var deviceDisplayName = "Test APFS Device";
            if (ImageVolumeId is not null && ImageDeviceId is not null &&
                string.Equals(request.VolumeId, ImageVolumeId, StringComparison.OrdinalIgnoreCase))
            {
                deviceId = ImageDeviceId;
                deviceDisplayName = "Test image device";
            }
            else
            {
                foreach (var volumes in _volumesByDevice.Values)
                {
                    var match = volumes.FirstOrDefault(v =>
                        string.Equals(v.VolumeId, request.VolumeId, StringComparison.OrdinalIgnoreCase));
                    if (match is not null)
                    {
                        deviceId = match.DeviceId;
                        recoveryIdentity = match.RecoveryIdentity;
                        break;
                    }
                }
            }
            _mounts[mountPoint] = new MountedVolumeState(
                request.VolumeId,
                mountPoint,
                effectiveMode,
                VolumeName: "Main",
                DeviceId: deviceId,
                DeviceDisplayName: deviceDisplayName,
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
                RecoveryIdentity: recoveryIdentity);
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

            var result = (UnmountResponses.TryDequeue(out var response) ? response : UnmountResponse) with { MountPoint = mountPoint };
            if (result.MountRemoved)
            {
                _mounts.Remove(mountPoint);
            }
            CancelAfterUnmount?.Cancel();
            AfterUnmountAction?.Invoke();

            return result;
        }

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<MountedVolumeState>>(_mounts.Values.ToArray());
        }

        public List<(string ContainerUuid, ulong VolumeObjectId, SnapshotControlAction Action, IReadOnlyList<string>? Extras)> SnapshotCalls { get; } = [];
        public Queue<SnapshotControlResult> SnapshotResults { get; } = new();
        public Queue<LiveVolumeVerificationResult> LiveVerificationResults { get; } = new();
        public List<LiveVolumeVerificationScope> LiveVerificationCalls { get; } = [];
        public TaskCompletionSource? LiveVerificationGate { get; set; }
        public async Task<LiveVolumeVerificationResult> VerifyLiveVolumeAsync(LiveVolumeVerificationScope scope, CancellationToken token)
        {
            LiveVerificationCalls.Add(scope);
            if (LiveVerificationGate is not null) await LiveVerificationGate.Task.WaitAsync(token);
            return LiveVerificationResults.Count > 0 ? LiveVerificationResults.Dequeue() : new(false, "VolumeVerificationBusy");
        }
        public bool NeverCompleteSnapshot { get; set; }
        public TaskCompletionSource? SnapshotGate { get; set; }
        public int SnapshotInventoryProbeCalls { get; private set; }

        public async Task<SnapshotControlResult> SendSnapshotControlAsync(
            string containerUuid,
            ulong volumeObjectId,
            SnapshotControlAction action,
            IReadOnlyList<string>? extraLines,
            CancellationToken cancellationToken)
        {
            SnapshotCalls.Add((containerUuid, volumeObjectId, action, extraLines));
            if (SnapshotGate is not null) await SnapshotGate.Task.WaitAsync(cancellationToken);
            if (NeverCompleteSnapshot)
            {
                await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            }

            if (SnapshotResults.Count > 0)
            {
                return SnapshotResults.Dequeue();
            }

            return new SnapshotControlResult(true, action switch
            {
                SnapshotControlAction.Create => "SnapshotCreated",
                SnapshotControlAction.Delete => "SnapshotDeleted",
                _ => "SnapshotRecovered",
            });
        }

        private static TaskCompletionSource NewSignal()
            => new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed class NoSnapshotBackend : IApfsBackend
    {
        private readonly ScenarioBackend _inner;

        public NoSnapshotBackend(ScenarioBackend inner) => _inner = inner;

        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
            => _inner.ProbeDevicesAsync(cancellationToken);

        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken)
            => _inner.ProbeVolumesAsync(deviceId, cancellationToken);

        public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
            => _inner.GetMountStateAsync(cancellationToken);
    }

    // Scripted management keeper: forwards discovery to the scenario
    // backend (topology included) and answers keeper calls from a queue.
    private sealed class KeeperBackend(ScenarioBackend inner) : IApfsBackend, IManagementRenameKeeper, IManagementQuotaKeeper, IVerifyBackend
    {
        public Queue<ImageVerifyResult> VerifyResults { get; } = new();
        public List<VerifyScope> VerifyCalls { get; } = [];
        public async Task<ImageVerifyResult> VerifyImageAsync(VerifyScope scope, CancellationToken token)
        {
            Assert.Empty(await inner.GetMountStateAsync(token));
            VerifyCalls.Add(scope);
            return VerifyResults.Dequeue();
        }
        private readonly Queue<ManagementKeeperRenameResult> results = new();

        public void Enqueue(ManagementKeeperRenameResult result) => results.Enqueue(result);

        public List<ManagementKeeperRenameRequest> KeeperCalls { get; } = [];

        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
            => inner.ProbeDevicesAsync(cancellationToken);

        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken)
            => inner.ProbeVolumesAsync(deviceId, cancellationToken);

        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken cancellationToken)
            => inner.ProbeInventoryAsync(authoritative, cancellationToken);

        public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
            => inner.GetMountStateAsync(cancellationToken);

        public Task<ManagementKeeperRenameResult> RenameVolumeAsync(
            ManagementKeeperRenameRequest request, CancellationToken cancellationToken)
        {
            KeeperCalls.Add(request);
            return Task.FromResult(results.Dequeue());
        }

        private readonly Queue<ManagementKeeperQuotaResult> quotaResults = new();

        public void EnqueueQuota(ManagementKeeperQuotaResult result) => quotaResults.Enqueue(result);

        public List<ManagementKeeperQuotaRequest> QuotaCalls { get; } = [];

        public Task<ManagementKeeperQuotaResult> SetQuotaReserveAsync(
            ManagementKeeperQuotaRequest request, CancellationToken cancellationToken)
        {
            QuotaCalls.Add(request);
            return Task.FromResult(quotaResults.Dequeue());
        }
    }

    // Scripted verify backend: forwards discovery and mounts to the
    // scenario backend (topology included) and answers verify calls from
    // a queue, recording the exact derived scope each call carried.
    private sealed class VerifyBackend(ScenarioBackend inner) : IApfsBackend, IVerifyBackend
    {
        private readonly Queue<Func<VerifyScope, ImageVerifyResult>> results = new();

        public void Enqueue(ImageVerifyResult result) => results.Enqueue(_ => result);

        public void EnqueueThrow(Exception error) => results.Enqueue(_ => throw error);

        public List<VerifyScope> VerifyCalls { get; } = [];

        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
            => inner.ProbeDevicesAsync(cancellationToken);

        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken)
            => inner.ProbeVolumesAsync(deviceId, cancellationToken);

        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken cancellationToken)
            => inner.ProbeInventoryAsync(authoritative, cancellationToken);

        public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
            => inner.MountAsync(request, cancellationToken);

        public Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
            => inner.UnmountAsync(mountPoint, cancellationToken);

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
            => inner.GetMountStateAsync(cancellationToken);

        public async Task<ImageVerifyResult> VerifyImageAsync(VerifyScope scope, CancellationToken cancellationToken)
        {
            Assert.Empty(await inner.GetMountStateAsync(cancellationToken));
            VerifyCalls.Add(scope);
            return results.Dequeue()(scope);
        }
    }

    // Verify-capable backend without the endpoint: proves the
    // verify:unsupported path while keeping topology-bearing discovery.
    private sealed class NoVerifyBackend(ScenarioBackend inner) : IApfsBackend
    {
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
            => inner.ProbeDevicesAsync(cancellationToken);

        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken)
            => inner.ProbeVolumesAsync(deviceId, cancellationToken);

        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken cancellationToken)
            => inner.ProbeInventoryAsync(authoritative, cancellationToken);

        public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
            => inner.MountAsync(request, cancellationToken);

        public Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
            => inner.UnmountAsync(mountPoint, cancellationToken);

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
            => inner.GetMountStateAsync(cancellationToken);
    }
}
