using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExplicitContainerMountReconcilesInventoryOvertakeWithoutLosingSelection(bool changeEvidence)
    {
        using var route = await OpenImageFixContainerAsync();
        route.Backend.BeforeInventory = _ => route.Backend.BeforeMountState = async () =>
        {
            route.Backend.BeforeInventory = null;
            route.Backend.BeforeMountState = null;
            if (changeEvidence) route.Backend.ChangeEvidence("window");
            await route.Worker.GetInventoryAsync(CancellationToken.None);
        };
        var result = await route.Worker.MountContainerAsync(route.Target.DeviceId, route.Target.ContainerUuid!,
            route.Members, MountAccessMode.ReadOnly, CancellationToken.None);
        if (changeEvidence)
        {
            Assert.False(result.Success, result.Message);
            Assert.Empty(route.Backend.Owners);
            Assert.Empty(route.Backend.Batches);
        }
        else
        {
            Assert.True(result.Success, result.Message);
            Assert.Equal(2, route.Backend.Owners.Count);
            Assert.Single(route.Backend.Batches);
        }
    }

    [Theory]
    [InlineData("window", false, false)] [InlineData("window", true, false)]
    [InlineData("contract", false, false)] [InlineData("contract", true, false)]
    [InlineData("window", false, true)] [InlineData("window", true, true)]
    [InlineData("contract", false, true)] [InlineData("contract", true, true)]
    public async Task ImageFixContainerRaceStorageWaitRetainsSuppressionAfterContractDrift(
        string change, bool pollDuringWait, bool single)
    {
        using var storage = new ImageFixBlockedLetterStorage();
        using var route = await OpenImageFixContainerAsync(autoMountEnabled: true, policy: storage, single: single);
        route.Backend.SeedOwners(true);
        var baseline = await route.Backend.InventoryAsync();
        var fix = route.ExecuteAsync();
        OperationResultPayload result;
        string[] suppressedDuringWait;
        var launchesDuringWait = -1;
        try
        {
            await storage.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Empty(route.Backend.Owners);
            Assert.Single(route.Backend.OfflineCalls);
            suppressedDuringWait = ImageFixWorkerIds(route.Worker, "_userEjectedVolumeIds").ToArray();
            route.Backend.ChangeEvidence(change);
            var changed = await route.Backend.InventoryAsync();
            AssertImageFixEvidenceDrift(baseline, changed);
            Assert.All(changed.Volumes, v => Assert.True(CatalogMountPolicy.AllowsOrdinaryMount(v)));
            if (pollDuringWait)
                await route.CycleAsync().WaitAsync(TimeSpan.FromSeconds(10));
            launchesDuringWait = route.Backend.Batches.Count + route.Backend.SingleMounts.Count;
        }
        finally
        {
            storage.Release.Set();
            result = await fix.WaitAsync(TimeSpan.FromSeconds(10));
        }

        Assert.False(result.Success, result.Diagnostic);
        var suppressedAfterRefusal = ImageFixWorkerIds(route.Worker, "_userEjectedVolumeIds").ToArray();
        await route.CycleAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(0, launchesDuringWait);
        Assert.Empty(route.Backend.Batches);
        Assert.Empty(route.Backend.SingleMounts);
        Assert.Equal(route.Members.Select(v => v.VolumeId).Order(), suppressedDuringWait.Order());
        Assert.Equal(route.Members.Select(v => v.VolumeId).Order(), suppressedAfterRefusal.Order());
        Assert.Empty(route.Backend.Owners);
        Assert.Empty(route.Backend.LiveCalls);
        AssertImageFixSuppressed(route);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task ImageFixContainerRaceHealthyStorageWaitLaunchesCompleteGuardedCohort(bool single)
    {
        using var storage = new ImageFixBlockedLetterStorage();
        using var route = await OpenImageFixContainerAsync(autoMountEnabled: true, policy: storage, single: single);
        route.Backend.SeedOwners(true);
        var fix = route.ExecuteAsync();
        OperationResultPayload result;
        try
        {
            await storage.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Empty(route.Backend.Batches);
            Assert.Empty(route.Backend.SingleMounts);
            AssertImageFixSuppressed(route);
        }
        finally
        {
            storage.Release.Set();
            result = await fix.WaitAsync(TimeSpan.FromSeconds(10));
        }
        Assert.True(result.Success, result.Diagnostic);
        if (single)
        {
            Assert.Empty(route.Backend.Batches);
            Assert.Equal(route.Target.VolumeId, Assert.Single(route.Backend.SingleMounts).VolumeId);
            Assert.Equal(Assert.Single(route.Backend.Owners).VolumeVerificationScope, Assert.Single(route.Backend.LiveCalls));
            Assert.True(Assert.Single(route.Backend.Reports).Complete);
            Assert.Equal("healthy-rw", result.FinalStatus);
            AssertWireResult(result);
        }
        else AssertImageFixContainerCompleted(route, result);
        Assert.Empty(ImageFixWorkerIds(route.Worker, "_userEjectedVolumeIds"));
        Assert.Empty(ImageFixWorkerIds(route.Worker, "_unsafeUnmountedVolumeIds"));
        await route.CycleAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(single ? 0 : 1, route.Backend.Batches.Count);
        Assert.Equal(single ? 1 : 0, route.Backend.SingleMounts.Count);
    }

    [Fact]
    public async Task ImageFixContainerRacePartialPrimaryReceiptCannotLaunchReducedReadOnlyFallback()
    {
        using var route = await OpenImageFixContainerAsync(autoMountEnabled: true);
        route.Backend.ReturnPartialPrimaryReceipt = true;
        var result = await route.ExecuteAsync();
        var primary = Assert.Single(route.Backend.Batches);
        Assert.Equal(route.Members.Select(v => v.VolumeId).Order(), primary.Select(r => r.VolumeId).Order());
        Assert.All(primary, request => Assert.Equal(MountAccessMode.ReadWrite, request.AccessMode));
        Assert.Empty(route.Backend.SingleMounts);
        Assert.False(result.Success, result.Diagnostic);
        Assert.Empty(route.Backend.Owners);
        Assert.Empty(route.Backend.LiveCalls);
        AssertImageFixSuppressed(route);
        await route.CycleAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Single(route.Backend.Batches);
        Assert.Empty(route.Backend.SingleMounts);
        AssertImageFixSuppressed(route);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task ImageFixContainerRaceIncompleteOriginalMemberCannotShrinkLaunchCohort(bool thirdMember)
    {
        using var route = await OpenImageFixContainerAsync(autoMountEnabled: true, thirdMember: thirdMember);
        var incomplete = route.Members.Single(v => v.VolumeName == "Archive");
        ImageFixWorkerIds(route.Worker, "_incompleteAccessModeVolumeIds").Add(incomplete.VolumeId);
        Assert.Equal(thirdMember ? 3 : 2, route.Members.Count);
        var result = await route.ExecuteAsync();

        Assert.Empty(route.Backend.SingleMounts);
        Assert.Empty(route.Backend.Batches);
        Assert.False(result.Success, result.Diagnostic);
        Assert.Equal(new[] { incomplete.VolumeId }, ImageFixWorkerIds(route.Worker, "_incompleteAccessModeVolumeIds"));
        Assert.Single(route.Backend.OfflineCalls);
        Assert.Empty(route.Backend.LiveCalls);
        AssertImageFixSuppressed(route);
        await route.CycleAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Empty(route.Backend.SingleMounts);
        Assert.Empty(route.Backend.Batches);
        Assert.Empty(route.Backend.Owners);
        Assert.Contains(route.Publisher.Latest.Warnings!, warning => warning.Contains(incomplete.VolumeName) &&
            warning.Contains("incomplete container access mode transition"));
        Assert.Contains(incomplete.VolumeId, ImageFixWorkerIds(route.Worker, "_incompleteAccessModeVolumeIds"));
        AssertImageFixSuppressed(route);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData(true, false)] [InlineData(false, false)] [InlineData(false, true)]
    public async Task ImageFixContainerRaceCancellationAfterFirstSettleReproofPublishesRemainingDebt(
        bool firstProvesOwnership, bool throwOnReproof)
    {
        using var route = await OpenImageFixContainerAsync(autoMountEnabled: true);
        using var cancel = new CancellationTokenSource();
        route.Backend.SeedOwners(true);
        var original = route.Backend.Owners.ToArray();
        route.Backend.HoldDetachOwnershipProof = true;
        route.Backend.ReproofReleasesOwnership = firstProvesOwnership;
        route.Backend.AfterReproof = _ =>
        {
            cancel.Cancel();
            if (throwOnReproof) throw new OperationCanceledException(cancel.Token);
        };
        EjectOperationResult? result = null;
        var error = await Record.ExceptionAsync(async () => result = await route.Worker.EjectContainerAsync(
            ImageFixDevice, route.Members[0].CatalogContainerUuid!, cancel.Token).WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.True(cancel.IsCancellationRequested, "The first settle reproof was not reached.");
        Assert.Equal(new[] { "detach", "detach", "reproof" }, route.Backend.Events);
        var published = route.Publisher.Latest;
        var suppressed = ImageFixWorkerIds(route.Worker, "_userEjectedVolumeIds").ToArray();
        var unsafeIds = ImageFixWorkerIds(route.Worker, "_unsafeUnmountedVolumeIds").ToArray();
        await route.CycleAsync().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Empty(route.Backend.Batches);
        Assert.Empty(route.Backend.SingleMounts);
        Assert.Null(error);
        Assert.NotNull(result);
        Assert.False(result.Success, result.Message);
        Assert.Empty(result.RemainingMounts);
        Assert.Empty(published.MountedVolumes!);
        Assert.Equal(original.Select(m => m.VolumeId).Order(), suppressed.Order());
        var firstReproof = original.Single(m => m.MountPoint == route.Backend.UnmountCalls[2]);
        var debt = original.Where(m => !firstProvesOwnership || m.VolumeId != firstReproof.VolumeId).ToArray();
        Assert.Equal(debt.Select(m => m.VolumeId).Order(), unsafeIds.Order());
        foreach (var member in original)
        {
            var proof = result.UnmountResults[member.VolumeId];
            Assert.True(proof.MountRemoved);
            Assert.True(proof.PendingDurabilityCleared);
            Assert.Equal(firstProvesOwnership && member.VolumeId == firstReproof.VolumeId, proof.HostOwnershipReleased);
        }
        Assert.All(debt, member => Assert.Contains(published.Warnings!, warning =>
            warning.Contains(member.VolumeName!) && warning.Contains("use Fix to recover")));
        Assert.Equal(debt.Select(m => m.VolumeId).Order(),
            ImageFixWorkerIds(route.Worker, "_unsafeUnmountedVolumeIds").Order());
        AssertImageFixSuppressed(route);
    }

    private static HashSet<string> ImageFixWorkerIds(ApfsMountWorker worker, string field)
        => Assert.IsType<HashSet<string>>(typeof(ApfsMountWorker)
            .GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(worker));

    private static void AssertImageFixSuppressed(ImageFixContainerRoute route)
        => Assert.Equal(route.Members.Select(v => v.VolumeId).Order(),
            ImageFixWorkerIds(route.Worker, "_userEjectedVolumeIds").Order());

    private sealed class ImageFixBlockedLetterStorage : IMountPolicy, IDisposable
    {
        private int _selections;
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ManualResetEventSlim Release { get; } = new();
        public bool RequiresDriveLetterStorage => true;
        public bool ShouldAutoMount(VolumeInfo volume) => true;
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters)
        {
            if (Interlocked.Increment(ref _selections) == 1)
            {
                Entered.TrySetResult();
                Assert.True(Release.Wait(TimeSpan.FromSeconds(20)), "Letter storage was not released.");
            }
            return new FixedMountPolicy().SelectDriveLetter(volume, usedLetters);
        }
        public void Dispose() => Release.Dispose();
    }

    [Theory]
    [InlineData("window")] [InlineData("contract")]
    public async Task ImageFixContainerAdmissionLateDiscoveryRejectsFrozenContractDrift(string change)
    {
        using var route = await OpenImageFixContainerAsync();
        var baseline = await route.Backend.InventoryAsync();
        var injected = false;
        route.Backend.AfterOfflineInventory = count =>
        {
            if (count == 1)
                Assert.Equal(SelectedControlTarget.Create(baseline, baseline.Volumes[0]),
                    SelectedControlTarget.Create(route.Backend.InventoryAsync().GetAwaiter().GetResult(), baseline.Volumes[0]));
            if (count != 2) return;
            route.Backend.ChangeEvidence(change);
            AssertImageFixEvidenceDrift(baseline, route.Backend.InventoryAsync().GetAwaiter().GetResult());
            injected = true;
        };
        var result = await route.ExecuteAsync();
        Assert.True(injected, "The worker's discovery after the executor post-offline rebind was not reached.");
        Assert.Single(route.Backend.OfflineCalls);
        Assert.Empty(route.Backend.Batches);
        Assert.Empty(route.Backend.SingleMounts);
        Assert.False(result.Success, result.Diagnostic);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("capability")] [InlineData("window")]
    public async Task ImageFixContainerAdmissionFreshEvidenceRefusesBeforeFirstDetach(string change)
    {
        using var route = await OpenImageFixContainerAsync();
        route.Backend.SeedOwners(false);
        var original = route.Backend.Owners.ToArray();
        var baseline = await route.Backend.InventoryAsync();
        var injected = false;
        route.Backend.BeforeInventory = count =>
        {
            if (count != 2) return;
            route.Backend.ChangeEvidence(change);
            AssertImageFixEvidenceDrift(baseline, route.Backend.InventoryAsync().GetAwaiter().GetResult());
            injected = true;
        };
        var result = await route.ExecuteAsync();
        Assert.True(injected);
        Assert.Empty(route.Backend.UnmountCalls);
        Assert.Equal(original, route.Backend.Owners.ToArray());
        Assert.Empty(route.Backend.OfflineCalls);
        Assert.Empty(route.Backend.Batches);
        Assert.Empty(route.Backend.SingleMounts);
        Assert.False(result.Success, result.Diagnostic);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("other-container")] [InlineData("unexpected-member")] [InlineData("duplicate-original")]
    public async Task ImageFixContainerAdmissionAffectedOwnersRefuseBeforeFirstDetach(string change)
    {
        using var route = await OpenImageFixContainerAsync();
        route.Backend.SeedOwners(false);
        var peer = route.Backend.Owners[1];
        route.Backend.Owners.Add(change == "duplicate-original" ? peer with { MountPoint = "Z:\\" } : peer with
        {
            MountPoint = "Z:\\", VolumeId = ImageFixDevice + "|Unexpected", RecoveryIdentity = "unrelated-recovery",
            CatalogContainerUuid = change == "other-container" ? new string('d', 32) : peer.CatalogContainerUuid,
            CatalogVolumeId = "apfs-vol:" + (change == "other-container" ? new string('d', 32) : peer.CatalogContainerUuid) + ":103",
            CatalogVolumeObjectId = 103, CatalogVolumeUuid = new string('e', 32), HostProcessId = 7777,
        });
        var original = route.Backend.Owners.ToArray();
        Assert.Equal(3, original.Length);
        var result = await route.ExecuteAsync();
        Assert.Empty(route.Backend.UnmountCalls);
        Assert.Equal(original, route.Backend.Owners.ToArray());
        Assert.Empty(route.Backend.OfflineCalls);
        Assert.Empty(route.Backend.Batches);
        Assert.Empty(route.Backend.SingleMounts);
        Assert.False(result.Success, result.Diagnostic);
        AssertWireResult(result);
    }

    private static void AssertImageFixEvidenceDrift(DeviceInventory baseline, DeviceInventory current)
    {
        Assert.True(TopologyAdmission.Validate(current));
        Assert.Equal(baseline.Volumes.Select(v => (v.DeviceId, v.VolumeId, v.RecoveryIdentity,
            v.CatalogVolumeId, v.CatalogContainerUuid, v.CatalogVolumeUuid, v.CatalogVolumeObjectId)),
            current.Volumes.Select(v => (v.DeviceId, v.VolumeId, v.RecoveryIdentity,
                v.CatalogVolumeId, v.CatalogContainerUuid, v.CatalogVolumeUuid, v.CatalogVolumeObjectId)));
        Assert.NotEqual(SelectedControlTarget.Create(baseline, baseline.Volumes[0]),
            SelectedControlTarget.Create(current, current.Volumes[0]));
    }

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)]
    [InlineData(false, true)] [InlineData(true, true)]
    public async Task ImageFixContainerBootstrapMountsFullInventoryAndVerifiesSelectedOwner(bool legacy, bool selectArchive)
    {
        using var route = await OpenImageFixContainerAsync(legacy: legacy, selectArchive: selectArchive);
        var result = await route.ExecuteAsync();
        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal("healthy-rw", result.FinalStatus);
        AssertImageFixContainerCompleted(route, result);
        Assert.Empty(route.Backend.UnmountCalls);
        Assert.Equal(new[] { "offline", "batch", "live" }, route.Backend.Events);
    }

    [Fact]
    public async Task ImageFixContainerSingleMemberKeepsExactMountPath()
    {
        using var route = await OpenImageFixContainerAsync(single: true);
        var result = await route.ExecuteAsync();
        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal("healthy-rw", result.FinalStatus);
        Assert.Empty(route.Backend.Batches);
        Assert.Equal(route.Target.VolumeId, Assert.Single(route.Backend.SingleMounts).VolumeId);
        Assert.Single(route.Backend.Owners);
        Assert.Equal(Assert.Single(route.Backend.Owners).VolumeVerificationScope, Assert.Single(route.Backend.LiveCalls));
        Assert.Equal(new[] { "offline", "single", "live" }, route.Backend.Events);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("removed")] [InlineData("recovery")] [InlineData("uuid")]
    public async Task ImageFixContainerMembershipChangeAfterOfflineRefusesBeforeBatch(string change)
    {
        using var route = await OpenImageFixContainerAsync();
        route.Backend.AfterOffline = () => route.Backend.ChangeMembership(change);
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.BlockedRecovery, result.Code);
        Assert.Contains("ImageFixSelectionChangedAfterOfflineVerification", result.Diagnostic);
        Assert.Single(route.Backend.OfflineCalls);
        Assert.Empty(route.Backend.Batches);
        Assert.Empty(route.Backend.SingleMounts);
        Assert.Empty(route.Backend.Owners);
        Assert.Empty(route.Backend.LiveCalls);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("foreign", false)] [InlineData("foreign", true)]
    [InlineData("duplicate", false)] [InlineData("duplicate", true)]
    [InlineData("peer-pid", false)] [InlineData("peer-pid", true)]
    [InlineData("peer-pid-reuse", false)] [InlineData("peer-pid-reuse", true)]
    [InlineData("peer-source", false)] [InlineData("peer-source", true)]
    public async Task ImageFixContainerPostLiveOwnerChangeRevokesCompleteReport(string change, bool terminal)
    {
        using var route = await OpenImageFixContainerAsync();
        route.Backend.AfterLiveInventory = count =>
        {
            // The verifier rechecks inventory first; the next observation is terminal reconciliation.
            if (count == (terminal ? 2 : 1)) route.Backend.ChangeOwner(change, route.Target.VolumeId);
        };
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.BlockedRecovery, result.Code);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Equal("not-proven", result.MountProof);
        Assert.Equal("not-proven", result.OwnershipProof);
        Assert.True(Assert.Single(route.Backend.Reports).Complete);
        Assert.Single(route.Backend.LiveCalls);
        Assert.Equal(2, Assert.Single(route.Backend.Batches).Count);
        Assert.Empty(route.Backend.SingleMounts);
        Assert.Contains(terminal ? "verify-after:complete findings=0" : "ImageFixOwnerChanged", result.Diagnostic);
        Assert.Contains("ImageFixVerificationNotProven", result.Diagnostic);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task ImageFixContainerOriginalOwnersQuiesceAndRestoreFullBatch(bool readOnly)
    {
        using var route = await OpenImageFixContainerAsync();
        route.Backend.SeedOwners(readOnly);
        var original = route.Backend.Owners.ToArray();
        Assert.Equal(2, original.Length);
        var result = await route.ExecuteAsync();
        Assert.True(result.Success, result.Diagnostic);
        AssertImageFixContainerCompleted(route, result);
        Assert.Equal(3, route.Backend.UnmountCalls.Count);
        Assert.Equal(2, route.Backend.UnmountCalls.Distinct().Count());
        Assert.Single(route.Backend.UnmountResults, r => !r.HostOwnershipReleased);
        Assert.Equal(2, route.Backend.UnmountResults.Count(r => r.HostOwnershipReleased));
        Assert.Equal(new[] { "detach", "detach", "reproof", "offline", "batch", "live" }, route.Backend.Events);
        Assert.All(route.Backend.Owners, current => Assert.NotEqual(
            original[0].HostProcessCreationTimeFileTimeUtc, current.HostProcessCreationTimeFileTimeUtc));
    }

    [Theory]
    [InlineData("removed")] [InlineData("recovery")] [InlineData("uuid")]
    public async Task ImageFixContainerForeignMembershipBeforeQuiescePreservesOriginalOwners(string change)
    {
        using var route = await OpenImageFixContainerAsync();
        route.Backend.SeedOwners(false);
        var original = route.Backend.Owners.ToArray();
        // One fresh observation freezes Fix's selection, then quiesce takes its own observation.
        route.Backend.BeforeInventory = count =>
        {
            if (count == 2) route.Backend.ChangeMembership(change);
        };
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.Contains("changed before Fix", result.Diagnostic);
        Assert.Equal(original, route.Backend.Owners.ToArray());
        Assert.Empty(route.Backend.UnmountCalls);
        Assert.Empty(route.Backend.OfflineCalls);
        Assert.Empty(route.Backend.Batches);
        Assert.Empty(route.Backend.SingleMounts);
        Assert.Empty(route.Backend.LiveCalls);
        AssertWireResult(result);
    }

    private static void AssertImageFixContainerCompleted(ImageFixContainerRoute route, OperationResultPayload result)
    {
        var batch = Assert.Single(route.Backend.Batches);
        Assert.Equal(2, batch.Count);
        Assert.Equal(route.Members.Select(v => v.VolumeId).Order(), batch.Select(r => r.VolumeId).Order());
        Assert.Equal(2, batch.Select(r => r.DriveLetter).Distinct().Count());
        Assert.All(batch, request => Assert.Equal(MountAccessMode.ReadWrite, request.AccessMode));
        Assert.Empty(route.Backend.SingleMounts);
        Assert.Equal(route.Target.VolumeId == ImageFixVolume ? "101" : "102", Assert.Single(route.Backend.OfflineCalls).VolumeObjectId);
        Assert.Equal(2, route.Backend.Owners.Count);
        var selected = Assert.Single(route.Backend.Owners, m => m.VolumeId == route.Target.VolumeId);
        Assert.Equal(selected.VolumeVerificationScope, Assert.Single(route.Backend.LiveCalls));
        Assert.True(Assert.Single(route.Backend.Reports).Complete);
        foreach (var member in route.Members)
        {
            var owner = Assert.Single(route.Backend.Owners, m => m.VolumeId == member.VolumeId);
            Assert.Equal(member.RecoveryIdentity, owner.RecoveryIdentity);
            Assert.Equal(member.CatalogVolumeId, owner.CatalogVolumeId);
            Assert.Equal(member.CatalogVolumeUuid, owner.VolumeVerificationScope!.VolumeUuid);
            Assert.Equal(member.CatalogVolumeObjectId!.Value.ToString(), owner.VolumeVerificationScope.VolumeOid);
            Assert.Equal(selected.HostProcessId, owner.HostProcessId);
            Assert.Equal(selected.HostProcessCreationTimeFileTimeUtc, owner.HostProcessCreationTimeFileTimeUtc);
            Assert.Equal(selected.VolumeVerificationScope!.SourceIdentity, owner.VolumeVerificationScope.SourceIdentity);
            Assert.Equal(MountAccessMode.ReadWrite, owner.AccessMode);
        }
        Assert.Equal("present", result.MountProof);
        Assert.Contains("verify-after:complete findings=0", result.Diagnostic);
        AssertWireResult(result);
    }

    private static async Task<ImageFixContainerRoute> OpenImageFixContainerAsync(bool legacy = false,
        bool selectArchive = false, bool single = false, bool autoMountEnabled = false,
        IMountPolicy? policy = null, bool thirdMember = false)
    {
        var backend = new ImageFixContainerBackend(single, thirdMember);
        var inventory = await backend.InventoryAsync();
        Assert.True(TopologyAdmission.Validate(inventory));
        Assert.Equal(single ? 1 : thirdMember ? 3 : 2, inventory.Volumes.Count);
        Assert.Equal(inventory.Volumes.Count, inventory.Topology!.Snapshot.Volumes.Count);
        Assert.Equal(inventory.Volumes.Count, inventory.Topology.Snapshot.Containers.Single().VolumeIds.Count);
        Assert.All(inventory.Volumes, v =>
        {
            Assert.True(CatalogMountPolicy.AllowsOrdinaryMount(v));
            Assert.True(VerifyScopeDerivation.TryDerive(inventory, v).Ok);
            Assert.Null(v.RegisteredImage);
        });
        Assert.Equal(inventory.Volumes.Count, inventory.Volumes.Select(v => v.RecoveryIdentity).Distinct().Count());
        Assert.Empty(backend.Owners);
        var root = Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")
            ?? throw new InvalidOperationException("A D: test root is required."), "image-fix-container-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var publisher = new RuntimeStatusPublisher();
        var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, backend,
            policy ?? new FixedMountPolicy(), publisher, new FixedOptionsMonitor(new ServiceHostOptions
            {
                AutoMountEnabled = autoMountEnabled, NativeAutoRemountOnReconnect = autoMountEnabled,
                EnableNativeWrite = true, WriteRolloutChannel = "Enabled", WriteBackendMode = "Native",
                NativeWritePromotionPolicy = "ScaffoldOnly", ReadWriteMode = "RwWithRoFallback",
                NativeHostStopTimeoutSeconds = 1, ManagementJournalRoot = root,
                EnableImageManagementMutations = true,
            }));
        Assert.False(worker.VolumeIntentBlocks(ImageFixDevice));
        var admitted = Assert.Single(await worker.GetInventoryAsync(default));
        var selected = admitted.Volumes.Single(v => v.VolumeName == (selectArchive ? "Archive" : "Main"));
        backend.ResetInventoryCount();
        return new(backend, worker, legacy ? new(selected.DeviceId, selected.VolumeId) :
            SelectedControlTarget.Create(admitted, selected), admitted.Volumes, publisher);
    }

    private sealed class ImageFixContainerRoute(ImageFixContainerBackend backend, ApfsMountWorker worker,
        ApfsControlTarget target, IReadOnlyList<VolumeInfo> members, RuntimeStatusPublisher publisher) : IDisposable
    {
        public ImageFixContainerBackend Backend => backend;
        public ApfsMountWorker Worker => worker;
        public RuntimeStatusPublisher Publisher => publisher;
        public ApfsControlTarget Target => target;
        public IReadOnlyList<VolumeInfo> Members => members;
        public Task<OperationResultPayload> ExecuteAsync() => CreateExecutor(worker).ExecuteAsync(
            CreateRequest(ApfsControlCommands.Fix, target), default);
        public Task CycleAsync() => (Task)typeof(ApfsMountWorker)
            .GetMethod("RunCycleAsync", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(worker, [CancellationToken.None])!;
        public void Dispose() => worker.Dispose();
    }

    // Only catalog records are reused. Mounts, batch receipts and shared-host detach proofs are pure fakes.
    private sealed class ImageFixContainerBackend(bool single, bool thirdMember = false) : IApfsBackend, IContainerMountBackend,
        IVerifyBackend, ILiveVolumeVerificationBackend
    {
        private readonly ScenarioBackend _catalog = new()
            { ImageDeviceId = ImageFixDevice, ImageVolumeId = ImageFixVolume, ImageTopologyXid = "90" };
        public List<MountedVolumeState> Owners { get; } = [];
        public List<IReadOnlyList<MountRequest>> Batches { get; } = [];
        public List<MountRequest> SingleMounts { get; } = [];
        public List<string> UnmountCalls { get; } = [];
        public List<UnmountResult> UnmountResults { get; } = [];
        public List<VerifyScope> OfflineCalls { get; } = [];
        public List<LiveVolumeVerificationScope> LiveCalls { get; } = [];
        public List<LiveVolumeVerificationReport> Reports { get; } = [];
        public List<string> Events { get; } = [];
        public Action? AfterOffline { get; set; }
        public Action<int>? BeforeInventory { get; set; }
        public Action<int>? AfterLiveInventory { get; set; }
        public Action<int>? AfterOfflineInventory { get; set; }
        public bool HoldDetachOwnershipProof { get; set; }
        public bool ReproofReleasesOwnership { get; set; } = true;
        public Action<UnmountResult>? AfterReproof { get; set; }
        public bool ReturnPartialPrimaryReceipt { get; set; }
        private int _inventoryCalls, _afterLiveInventories;
        private int _afterOfflineInventories;
        private string? _membershipChange;
        private string? _evidenceChange;
        public void ResetInventoryCount() => _inventoryCalls = 0;
        public void ChangeMembership(string change) => _membershipChange = change;
        public void ChangeEvidence(string change) => _evidenceChange = change;

        public async Task<DeviceInventory> InventoryAsync()
        {
            var inventory = (await _catalog.ProbeInventoryAsync(true, default)).Single(d => d.Device.DeviceId == ImageFixDevice);
            var main = Assert.Single(inventory.Volumes);
            var archive = main with
            {
                VolumeId = ImageFixDevice + "|Archive", VolumeName = "Archive", RecoveryIdentity = "image-archive-recovery",
                CatalogVolumeId = "apfs-vol:" + main.CatalogContainerUuid + ":102",
                CatalogVolumeUuid = new string('c', 32), CatalogVolumeObjectId = 102,
            };
            if (_membershipChange == "recovery") archive = archive with { RecoveryIdentity = "replacement-archive" };
            if (_membershipChange == "uuid") archive = archive with { CatalogVolumeUuid = new string('d', 32) };
            var snapshot = inventory.Topology!.Snapshot;
            var members = new List<VolumeInfo> { main, archive };
            if (thirdMember)
            {
                var third = archive with { VolumeId = ImageFixDevice + "|Third", VolumeName = "Third",
                    RecoveryIdentity = "image-third-recovery", CatalogVolumeObjectId = 103,
                    CatalogVolumeId = "apfs-vol:" + main.CatalogContainerUuid + ":103", CatalogVolumeUuid = new string('e', 32) };
                members.Add(third);
                snapshot = snapshot with
                {
                    Volumes = [.. snapshot.Volumes, snapshot.Volumes.Single(v => v.ObjectId == "102") with
                        { Id = third.CatalogVolumeId!, ObjectId = "103", Uuid = third.CatalogVolumeUuid!, Name = third.VolumeName }],
                    Containers = snapshot.Containers.Select(c => c with
                        { VolumeIds = members.Select(v => v.CatalogVolumeId!).ToArray() }).ToArray(),
                };
            }
            if (single || _membershipChange == "removed")
                snapshot = snapshot with
                {
                    Containers = snapshot.Containers.Select(c => c with { VolumeIds = [main.CatalogVolumeId!] }).ToArray(),
                    Volumes = snapshot.Volumes.Where(v => v.ObjectId == "101").ToArray(),
                };
            if (_membershipChange == "uuid") snapshot = snapshot with
                { Volumes = snapshot.Volumes.Select(v => v.ObjectId == "102" ? v with { Uuid = archive.CatalogVolumeUuid! } : v).ToArray() };
            if (_evidenceChange == "window") snapshot = snapshot with
                { Stores = snapshot.Stores.Select(s => s with { OffsetBytes = 4096, SizeBytes = s.SizeBytes - 4096 }).ToArray() };
            if (_evidenceChange == "contract") snapshot = snapshot with
                { Volumes = snapshot.Volumes.Select(v => v.ObjectId == "101" ? v with { CaseMode = "CaseInsensitive" } : v).ToArray() };
            if (_evidenceChange == "capability") main = main with
                { CatalogDecision = ApfsCapabilityDecision.Readable, CatalogAutoMountAllowed = false,
                    CatalogReasons = ["special-role:system"], SupportsReadWrite = false, SupportsNativeWrite = false };
            members[0] = main;
            return inventory with { Volumes = single || _membershipChange == "removed" ? [main] : members,
                Topology = inventory.Topology with { Snapshot = snapshot } };
        }

        public async Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => [(await InventoryAsync()).Device];
        public async Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token)
            => device == ImageFixDevice ? (await InventoryAsync()).Volumes : [];
        public async Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            BeforeInventory?.Invoke(++_inventoryCalls);
            if (OfflineCalls.Count != 0) AfterOfflineInventory?.Invoke(++_afterOfflineInventories);
            if (LiveCalls.Count != 0) AfterLiveInventory?.Invoke(++_afterLiveInventories);
            return [await InventoryAsync()];
        }
        public Func<Task>? BeforeMountState { get; set; }
        public async Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
        {
            if (BeforeMountState is { } before) await before();
            return Owners.ToArray();
        }

        public async Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            SingleMounts.Add(request); Events.Add("single");
            return await MountMemberAsync(request);
        }
        public async Task<IReadOnlyList<MountResult>> MountContainerAsync(IReadOnlyList<MountRequest> requests, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Batches.Add(requests.ToArray()); Events.Add("batch");
            var members = (await InventoryAsync()).Volumes;
            Assert.Equal(members.Select(v => v.VolumeId).Order(), requests.Select(r => r.VolumeId).Order());
            Assert.Empty(Owners);
            // A successful receipt can outlive its owner; the next observation is empty.
            if (ReturnPartialPrimaryReceipt)
                return [new(true, requests[0].DriveLetter + ":\\", null, MountAccessMode.ReadWrite, WriteEnabled: true),
                    new(false, null, "The second primary member failed.", MountAccessMode.ReadOnly)];
            var results = new List<MountResult>();
            foreach (var request in requests) results.Add(await MountMemberAsync(request));
            return results;
        }
        private async Task<MountResult> MountMemberAsync(MountRequest request)
        {
            var member = (await InventoryAsync()).Volumes.Single(v => v.VolumeId == request.VolumeId);
            _catalog.ImageTopologyXid = "92";
            var owner = ImageFixProofOwner(member, "92") with { MountPoint = request.DriveLetter + ":\\", VolumeName = member.VolumeName };
            Owners.Add(owner);
            return new(true, owner.MountPoint, null, MountAccessMode.ReadWrite, WriteEnabled: true,
                NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);
        }
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            UnmountCalls.Add(point);
            var detached = Owners.FirstOrDefault(m => m.MountPoint == point);
            var removed = Owners.RemoveAll(m => m.MountPoint == point);
            Events.Add(removed == 0 ? "reproof" : "detach");
            // Detaching the first member cannot prove shared host exit while its peer still exists.
            var result = new UnmountResult(true, point, null, true,
                removed == 0 ? ReproofReleasesOwnership : !HoldDetachOwnershipProof &&
                    !Owners.Any(m => m.HostProcessId == (detached?.HostProcessId ?? 6201)), true);
            UnmountResults.Add(result);
            if (removed == 0) AfterReproof?.Invoke(result);
            return Task.FromResult(result);
        }
        public Task<ImageVerifyResult> VerifyImageAsync(VerifyScope scope, CancellationToken token)
        {
            Assert.Empty(Owners);
            Events.Add("offline"); OfflineCalls.Add(scope); AfterOffline?.Invoke();
            return Task.FromResult(new ImageVerifyResult(true, "Complete", 0, 0, null));
        }
        public Task<LiveVolumeVerificationResult> VerifyLiveVolumeAsync(LiveVolumeVerificationScope scope, CancellationToken token)
        {
            Assert.Equal(1, Owners.Count(m => m.VolumeVerificationScope == scope));
            Assert.Equal(single ? 1 : 2, Owners.Count);
            Events.Add("live"); LiveCalls.Add(scope);
            var result = LiveFixReport(scope); Reports.Add(result.Report!);
            return Task.FromResult(result);
        }
        public void SeedOwners(bool readOnly)
        {
            var inventory = InventoryAsync().GetAwaiter().GetResult();
            foreach (var member in inventory.Volumes)
            {
                var owner = ImageFixProofOwner(member, "90") with
                {
                    MountPoint = (member.VolumeName == "Main" ? "E" : "F") + ":\\",
                    HostProcessId = 6201, HostProcessCreationTimeFileTimeUtc = LiveFixOwnerCreationTime,
                    AccessMode = readOnly ? MountAccessMode.ReadOnly : MountAccessMode.ReadWrite,
                };
                Owners.Add(owner);
            }
        }
        public void ChangeOwner(string change, string selectedId)
        {
            var peerIndex = Owners.FindIndex(m => m.VolumeId != selectedId);
            var peer = Owners[peerIndex];
            switch (change)
            {
                case "foreign": Owners.Add(peer with { MountPoint = "Z:\\", VolumeId = ImageFixDevice + "|Foreign",
                    CatalogVolumeId = "apfs-vol:" + peer.CatalogContainerUuid + ":103", CatalogVolumeObjectId = 103,
                    CatalogVolumeUuid = new string('f', 32), RecoveryIdentity = "foreign" }); break;
                case "duplicate": Owners.Add(peer with { MountPoint = "Z:\\" }); break;
                case "peer-pid": Owners[peerIndex] = peer with { HostProcessId = peer.HostProcessId + 1 }; break;
                case "peer-pid-reuse": Owners[peerIndex] = peer with
                    { HostProcessCreationTimeFileTimeUtc = peer.HostProcessCreationTimeFileTimeUtc + 1 }; break;
                case "peer-source": Owners[peerIndex] = peer with { VolumeVerificationScope =
                    peer.VolumeVerificationScope! with { SourceIdentity = "image:replacement-peer" } }; break;
                default: throw new ArgumentException(change);
            }
        }
    }
}
