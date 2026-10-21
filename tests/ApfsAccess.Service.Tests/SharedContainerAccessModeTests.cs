using System.Reflection;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed class SharedContainerAccessModeTests
{
    private const string Device = @"\\.\PhysicalDrive91";
    private const string Container = "11111111222233334444555555555555";
    private static readonly VolumeInfo Alpha = Volume("Alpha", 201, "aaaaaaaa222233334444555555555555");
    private static readonly VolumeInfo Beta = Volume("Beta", 202, "bbbbbbbb222233334444555555555555");

    [Theory]
    [InlineData("clean")]
    [InlineData("invalid-recovery-state")]
    [InlineData("missing-drain")]
    public async Task DormantCatalogRoMetadataProjectionAdmitsOnlyKnownCleanDrain(string variant)
    {
        using var f = new Fixture();
        f.Options.CurrentValue.AutoMountEnabled = false;
        f.Backend.SetActive([new("Alpha", 'R', MountAccessMode.ReadOnly)]);
        f.Backend.Data["journal"] = "retained original journal exists; not runtime watermarks";
        var raw = new Dictionary<string, object>
        {
            ["volumeVerificationSupported"] = false,
        };
        if (variant != "missing-drain")
        {
            foreach (var field in new[] { "dirtyTransactionCount", "inFlightMutationCallbacks", "walAcceptedSequence",
                "walApfsDurableSequence", "walCleanupSequence", "payloadSpoolDirtyRangeCount" }) raw[field] = 0;
            foreach (var field in new[] { "closeCommitDeferred", "deferredCommitRequested", "deferredCommitInFlight",
                "shutdownDrainActive", "payloadSpoolIndexDirty", "payloadSpoolRecoveryRequired" }) raw[field] = false;
            raw["walRecoveryStateValid"] = variant == "clean";
        }
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(raw));
        var drain = (ContainerVolumeDrainStatus?)typeof(ContainerStatusReader)
            .GetMethod("ReadDrain", BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, [json.RootElement]);
        var child = new ContainerVolumeStatus(Alpha.CatalogVolumeObjectId!.Value, Alpha.CatalogVolumeId!,
            true, true, false, Alpha.RecoveryIdentity!, VolumeVerificationSupported: false, Drain: drain);
        var projection = typeof(ContainerStatusReader).Assembly.GetType("ApfsAccess.Backend.Native.ContainerRuntimeDiagnostics")!
            .GetMethod("ApplyWatermarks", BindingFlags.Static | BindingFlags.NonPublic)!;
        f.Backend.Mounts[0] = (MountedVolumeState)projection.Invoke(null, [f.Backend.Mounts[0], true, child])!;
        var ro = Assert.Single(f.Backend.Mounts);
        Assert.Equal(variant != "missing-drain", ro.RuntimeWatermarksKnown);
        Assert.Equal(variant != "clean", ro.RuntimeMutationPending);
        Assert.False(ro.VolumeVerificationSupported);
        Assert.Equal(NativeWriteCommitModel.ScaffoldCheckpoint, ro.CommitModel);
        var result = await f.Change(MountAccessMode.ReadWrite);
        Assert.Equal(variant == "clean", result.Success);
        Assert.Equal("Alpha", Assert.Single(f.Backend.Mounts).VolumeId);
        if (variant != "clean")
        {
            Assert.Equal(ro, Assert.Single(f.Backend.Mounts));
            Assert.Empty(f.Backend.Events);
            Assert.Empty(f.Backend.Batches);
        }
        Assert.Equal("retained original journal exists; not runtime watermarks", f.Backend.Data["journal"]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DormantCatalogAlphaReadOnlyUpgradesWithoutMountingBeta(bool betaUserEjected)
    {
        using var f = new Fixture();
        f.Options.CurrentValue.AutoMountEnabled = false;
        f.Backend.SetActive([new("Alpha", 'R', MountAccessMode.ReadOnly)]);
        f.Backend.Topology = Topology();
        if (betaUserEjected)
        {
            var choices = (HashSet<string>)typeof(ApfsMountWorker)
                .GetField("_userEjectedVolumeIds", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(f.Worker)!;
            Assert.True(choices.Add(Beta.VolumeId));
        }
        var original = Assert.Single(f.Backend.Mounts);
        Assert.False(original.VolumeVerificationSupported);
        Assert.Equal(NativeWriteCommitModel.ScaffoldCheckpoint, original.CommitModel);
        Assert.Equal(NativeWriteEngineState.Scaffold, original.NativeWriteEngineState);
        Assert.True(original.RuntimeWatermarksKnown);
        Assert.False(original.RuntimeMutationPending);
        Assert.Equal((0ul, 0ul, 0ul),
            (original.WalAcceptedSequence, original.WalApfsDurableSequence, original.WalCleanupSequence));
        var retainedJournal = f.Backend.Data["journal"] = "existing original journal: accepted=17 durable=17 cleaned=17";
        var beforeData = f.Backend.Data.ToArray();

        var result = await f.Change(MountAccessMode.ReadWrite);

        Assert.True(result.Success, result.Message);
        Assert.Equal(new MountRequest("Alpha", 'R', MountAccessMode.ReadWrite), Assert.Single(Assert.Single(f.Backend.Batches)));
        Assert.Equal(["stop:R:\\", "batch:Alpha"], f.Backend.Events);
        Assert.Equal([(original.HostProcessId, original.HostProcessCreationTimeFileTimeUtc)], f.Backend.ReleasedOwners);
        var current = Assert.Single(f.Backend.Mounts);
        Assert.Equal("Alpha", current.VolumeId);
        Assert.Equal("R:\\", current.MountPoint);
        Assert.Equal(MountAccessMode.ReadWrite, current.AccessMode);
        Assert.Equal(original.RecoveryIdentity, current.RecoveryIdentity);
        Assert.NotEqual((original.HostProcessId, original.HostProcessCreationTimeFileTimeUtc),
            (current.HostProcessId, current.HostProcessCreationTimeFileTimeUtc));
        Assert.Equal(1, f.Backend.MaxConcurrentOwners);
        Assert.Equal(0, f.Backend.SingleMountCalls);
        Assert.Equal(beforeData, f.Backend.Data.ToArray());
        Assert.Equal(retainedJournal, f.Backend.Data["journal"]);
        Assert.Equal("Alpha", Assert.Single(f.Publisher.Latest.MountedVolumes!).VolumeId);
        if (betaUserEjected)
        {
            f.Options.CurrentValue.AutoMountEnabled = true;
            await f.Cycle();
            Assert.Equal("Alpha", Assert.Single(f.Backend.Mounts).VolumeId);
            Assert.Single(f.Backend.Batches);
        }
    }

    [Theory]
    [InlineData(MountAccessMode.ReadOnly)]
    [InlineData(MountAccessMode.ReadWrite)]
    public async Task DormantCatalogTwoOfThreeRetainsActiveSiblingMode(MountAccessMode betaMode)
    {
        using var f = new Fixture();
        f.Options.CurrentValue.AutoMountEnabled = false;
        f.Backend.Volumes.Add(Volume("Gamma", 203, "dddddddd222233334444555555555555"));
        f.Backend.Topology = Topology(f.Backend.Volumes);
        f.Backend.SetActive([new("Alpha", 'R', MountAccessMode.ReadOnly), new("Beta", 'S', betaMode)]);
        var original = f.Backend.Mounts.ToArray();

        var result = await f.Change(MountAccessMode.ReadWrite);

        Assert.True(result.Success, result.Message);
        Assert.Equal([new("Alpha", 'R', MountAccessMode.ReadWrite), new MountRequest("Beta", 'S', betaMode)],
            Assert.Single(f.Backend.Batches));
        Assert.Equal(["stop:R:\\", "stop:S:\\", "proof:R:\\", "batch:Alpha,Beta"], f.Backend.Events);
        Assert.Equal([(original[0].HostProcessId, original[0].HostProcessCreationTimeFileTimeUtc)], f.Backend.ReleasedOwners);
        Assert.Equal(2, f.Backend.Mounts.Count);
        var alpha = f.Backend.Mounts.Single(m => m.VolumeId == "Alpha");
        var beta = f.Backend.Mounts.Single(m => m.VolumeId == "Beta");
        Assert.Equal(MountAccessMode.ReadWrite, alpha.AccessMode);
        Assert.Equal(betaMode, beta.AccessMode);
        Assert.Equal("R:\\", alpha.MountPoint);
        Assert.Equal("S:\\", beta.MountPoint);
        Assert.Equal((alpha.HostProcessId, alpha.HostProcessCreationTimeFileTimeUtc),
            (beta.HostProcessId, beta.HostProcessCreationTimeFileTimeUtc));
        Assert.NotEqual(original[0].HostProcessId, alpha.HostProcessId);
        Assert.DoesNotContain(f.Backend.Mounts, m => m.VolumeId == "Gamma");
        Assert.Equal(0, f.Backend.SingleMountCalls);
        Assert.Equal(1, f.Backend.MaxConcurrentOwners);
    }

    [Theory]
    [InlineData("missing-active-catalog")]
    [InlineData("foreign-active")]
    [InlineData("duplicate-active")]
    [InlineData("unknown-watermarks")]
    [InlineData("ro-unknown-watermarks")]
    [InlineData("ro-pending-recovery-state")]
    [InlineData("wal-debt")]
    [InlineData("cleanup-debt")]
    [InlineData("dirty")]
    [InlineData("callbacks")]
    [InlineData("drain")]
    [InlineData("wrong-rid")]
    [InlineData("wrong-oid")]
    [InlineData("wrong-uuid")]
    [InlineData("zero-birth")]
    [InlineData("changed-birth")]
    [InlineData("changed-pid")]
    [InlineData("duplicate-letter")]
    public async Task DormantCatalogUnsafeActiveSubsetRefusesBeforeDetach(string variant)
    {
        using var f = new Fixture();
        f.Options.CurrentValue.AutoMountEnabled = false;
        f.Backend.Volumes.Add(Volume("Gamma", 203, "dddddddd222233334444555555555555"));
        f.Backend.SetActive([new("Alpha", 'R', MountAccessMode.ReadOnly), new("Beta", 'S', MountAccessMode.ReadWrite)]);
        var beta = f.Backend.Mounts[1];
        if (variant == "missing-active-catalog") f.Backend.Volumes.RemoveAt(1);
        else if (variant == "duplicate-active") f.Backend.Mounts.Add(beta with { MountPoint = "T:\\" });
        else if (variant == "ro-unknown-watermarks") f.Backend.Mounts[0] = f.Backend.Mounts[0] with { RuntimeWatermarksKnown = null };
        else if (variant == "ro-pending-recovery-state") f.Backend.Mounts[0] = f.Backend.Mounts[0] with { RuntimeMutationPending = true };
        else f.Backend.Mounts[1] = variant switch
        {
            "foreign-active" => beta with { VolumeId = "Foreign", CatalogVolumeId = ApfsTopology.BuildVolumeId(Container, 999), CatalogVolumeObjectId = 999 },
            "unknown-watermarks" => beta with { RuntimeWatermarksKnown = false },
            "wal-debt" => beta with { WalAcceptedSequence = 18 },
            "cleanup-debt" => beta with { WalCleanupSequence = 16 },
            "dirty" => beta with { DirtyTransactionCount = 1 },
            "callbacks" => beta with { InFlightMutationCallbacks = 1 },
            "drain" => beta with { ShutdownDrainActive = true },
            "wrong-rid" => beta with { RecoveryIdentity = "foreign-rid" },
            "wrong-oid" => beta with { CatalogVolumeObjectId = 999 },
            "wrong-uuid" => beta with { CatalogVolumeUuid = Alpha.CatalogVolumeUuid },
            "zero-birth" => beta with { HostProcessCreationTimeFileTimeUtc = 0 },
            "changed-birth" => beta with { HostProcessCreationTimeFileTimeUtc = beta.HostProcessCreationTimeFileTimeUtc + 1 },
            "changed-pid" => beta with { HostProcessId = beta.HostProcessId + 1 },
            "duplicate-letter" => beta with { MountPoint = "R:\\" },
            _ => throw new ArgumentException(variant),
        };
        var before = f.Backend.Mounts.ToArray();
        var result = await f.Change(MountAccessMode.ReadWrite);
        Assert.False(result.Success);
        Assert.Empty(f.Backend.Events);
        Assert.Empty(f.Backend.Batches);
        Assert.Empty(f.Backend.ReleasedOwners);
        Assert.Equal(before, f.Backend.Mounts);
    }

    [Theory]
    [InlineData("source")]
    [InlineData("rid")]
    [InlineData("membership")]
    public async Task DormantCatalogSourceIsRevalidatedEvenWhenOnlyAlphaIsActive(string variant)
    {
        using var f = new Fixture();
        f.Options.CurrentValue.AutoMountEnabled = false;
        f.Backend.SetActive([new("Alpha", 'R', MountAccessMode.ReadOnly)]);
        f.Policy.OnSelect = () =>
        {
            if (variant == "source") f.Backend.Volumes[1] = Beta with { NativeVolumePath = @"\\.\PhysicalDrive92|Beta" };
            if (variant == "rid") f.Backend.Volumes[1] = Beta with { RecoveryIdentity = "replacement-rid" };
            if (variant == "membership") f.Backend.Volumes.RemoveAt(1);
        };
        var original = Assert.Single(f.Backend.Mounts);
        var result = await f.Change(MountAccessMode.ReadWrite);
        Assert.False(result.Success);
        Assert.Equal(1, f.Policy.Selections);
        Assert.Equal(original, Assert.Single(f.Backend.Mounts));
        Assert.Empty(f.Backend.Events);
        Assert.Empty(f.Backend.Batches);
    }

    [Fact]
    public async Task ReadOnlyThenFixRebuildsOneCompleteCohortWithExactLettersAndSiblingMode()
    {
        using var f = new Fixture();
        var data = f.Backend.Data;
        var original = f.Backend.Mounts.ToArray();
        var ro = await f.Change(MountAccessMode.ReadOnly);
        Assert.True(ro.Success, ro.Message);
        AssertPlan(Assert.Single(f.Backend.Batches), MountAccessMode.ReadOnly);
        Assert.Equal(["stop:R:\\", "stop:S:\\", "proof:R:\\", "batch:Alpha,Beta"], f.Backend.Events);
        AssertCohort(f.Backend.Mounts, MountAccessMode.ReadOnly);
        Assert.NotEqual(original[0].HostProcessId, f.Backend.Mounts[0].HostProcessId);
        Assert.Equal(1, f.Backend.MaxConcurrentOwners);
        Assert.Equal(0, f.Backend.SingleMountCalls);
        Assert.Same(data, f.Backend.Data);
        Assert.Equal("alpha payload", data["Alpha"]);
        Assert.Equal("beta payload", data["Beta"]);
        Assert.Equal("snapshot-84.2MB", data["snapshot"]);
        Assert.Equal(0ul, f.Backend.Mounts.Single(m => m.VolumeId == "Alpha").WalCleanupSequence);
        Assert.Equal(17ul, f.Backend.Mounts.Single(m => m.VolumeId == "Beta").WalCleanupSequence);
        Assert.All(f.Backend.Mounts, m => Assert.Equal(original.Single(o => o.VolumeId == m.VolumeId).RecoveryIdentity, m.RecoveryIdentity));
        Assert.Equal(f.Backend.Mounts.Select(m => m.AccessMode), f.Publisher.Latest.MountedVolumes!.Select(m => m.AccessMode));

        await f.Cycle();
        var refresh = await f.Worker.RefreshAsync(true, CancellationToken.None);
        Assert.True(refresh.Success, refresh.Message);
        Assert.Single(f.Backend.Batches);
        AssertCohort(f.Backend.Mounts, MountAccessMode.ReadOnly);

        var fix = await f.Change(MountAccessMode.ReadWrite);
        Assert.True(fix.Success, fix.Message);
        Assert.Equal(2, f.Backend.Batches.Count);
        AssertPlan(f.Backend.Batches[1], MountAccessMode.ReadWrite);
        AssertCohort(f.Backend.Mounts, MountAccessMode.ReadWrite);
        Assert.Equal(1, f.Backend.MaxConcurrentOwners);
        Assert.Same(data, f.Backend.Data);
    }

    [Fact]
    public async Task ExplicitTransitionWorksWithBackgroundAutoMountDisabled()
    {
        using var f = new Fixture();
        f.Options.CurrentValue.AutoMountEnabled = false;
        Assert.True((await f.Change(MountAccessMode.ReadOnly)).Success);
        AssertCohort(f.Backend.Mounts, MountAccessMode.ReadOnly);
    }

    [Fact]
    public async Task NonBatchBackendRetainsExistingIndependentOwnerMountPath()
    {
        using var f = new Fixture();
        f.Backend.Mounts.RemoveAt(1);
        var legacy = new IndependentBackend(f.Backend);
        using var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, legacy, f.Policy, f.Publisher, f.Options);
        var result = await worker.EnsureMountedExactAsync(Device, Alpha.VolumeId, MountAccessMode.ReadOnly, default, Alpha.RecoveryIdentity);
        Assert.True(result.Success, result.Message);
        Assert.Equal(1, legacy.MountCalls);
        Assert.Equal(MountAccessMode.ReadOnly, Assert.Single(f.Backend.Mounts).AccessMode);
    }

    [Fact]
    public async Task SelectedTypedTopologyCompletesTheSameCohortTransition()
    {
        using var f = new Fixture();
        f.Backend.Topology = Topology();
        var inventory = Assert.Single(await f.Worker.GetInventoryAsync(default));
        Assert.True(TopologyAdmission.Validate(inventory));
        var selected = SelectedControlTarget.Create(inventory, inventory.Volumes[0]);
        var result = await f.Worker.EnsureMountedExactAsync(Device, Alpha.VolumeId, MountAccessMode.ReadOnly, default, Alpha.RecoveryIdentity, selected);
        Assert.True(result.Success, result.Message);
        AssertPlan(Assert.Single(f.Backend.Batches), MountAccessMode.ReadOnly);
    }

    [Fact]
    public async Task ChangedTopologySourceWindowRefusesBeforeStop()
    {
        using var f = new Fixture();
        f.Backend.Topology = Topology();
        f.Backend.OnProbe = _ =>
        {
            if (f.Policy.Selections != 2) return;
            var topology = f.Backend.Topology!;
            f.Backend.Topology = topology with { Snapshot = topology.Snapshot with
            {
                Stores = topology.Snapshot.Stores.Select(s => s with { OffsetBytes = s.OffsetBytes + 4096 }).ToArray(),
                Partitions = topology.Snapshot.Partitions.Select(p => p with { StartByte = p.StartByte + 4096 }).ToArray(),
            } };
        };
        var result = await f.Change(MountAccessMode.ReadOnly);
        Assert.False(result.Success);
        Assert.Empty(f.Backend.Events);
        AssertCohort(f.Backend.Mounts, MountAccessMode.ReadWrite);
    }

    [Fact]
    public async Task SelectedSiblingReadOnlyModeIsPreserved()
    {
        using var f = new Fixture(betaMode: MountAccessMode.ReadOnly);
        var result = await f.Change(MountAccessMode.ReadOnly);
        Assert.True(result.Success, result.Message);
        Assert.Equal([MountAccessMode.ReadOnly, MountAccessMode.ReadOnly], Assert.Single(f.Backend.Batches).Select(r => r.AccessMode));
        Assert.Equal(MountAccessMode.ReadOnly, f.Backend.Mounts.Single(m => m.VolumeId == "Beta").AccessMode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReadOnlyMemberWithoutCompleteRuntimeStatusDoesNotInheritPersistentWalProof(bool afterManualTransition)
    {
        using var f = new Fixture();
        if (afterManualTransition) Assert.True((await f.Change(MountAccessMode.ReadOnly)).Success);
        var alpha = f.Backend.Mounts.Single(m => m.VolumeId == "Alpha");
        var index = f.Backend.Mounts.IndexOf(alpha);
        f.Backend.Mounts[index] = alpha with { AccessMode = MountAccessMode.ReadOnly, WriteBackend = "Disabled",
            NativeWriteReadiness = NativeWriteReadiness.Unavailable, NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback,
            RuntimeWatermarksKnown = false, RuntimeMutationPending = true, WalAcceptedSequence = 0,
            WalApfsDurableSequence = 0, WalCleanupSequence = 0 };
        f.Backend.Events.Clear();
        f.Backend.Batches.Clear();
        var original = f.Backend.Mounts.ToArray();
        var result = await f.Change(MountAccessMode.ReadWrite);
        Assert.False(result.Success);
        Assert.Empty(f.Backend.Events);
        Assert.Empty(f.Backend.Batches);
        Assert.Equal(original, f.Backend.Mounts);
    }

    [Theory]
    [InlineData("missing-active-catalog")]
    [InlineData("extra-owner")]
    [InlineData("zero-pid")]
    [InlineData("zero-creation")]
    [InlineData("different-creation")]
    [InlineData("different-pid")]
    [InlineData("wrong-rid")]
    [InlineData("wrong-uuid")]
    [InlineData("wrong-oid")]
    [InlineData("missing-catalog")]
    [InlineData("invalid-mount-point")]
    [InlineData("protected-sibling")]
    [InlineData("encrypted-sibling")]
    [InlineData("blocked-sibling-write")]
    [InlineData("unknown-watermarks")]
    [InlineData("recovery")]
    [InlineData("dirty")]
    [InlineData("pending")]
    [InlineData("wal-debt")]
    [InlineData("cleanup-debt")]
    [InlineData("drain")]
    [InlineData("callbacks")]
    public async Task IncompleteOrUnsafeCohortRefusesBeforeAnyDetach(string variant)
    {
        using var f = new Fixture();
        var beta = f.Backend.Mounts[1];
        if (variant == "missing-active-catalog") f.Backend.Volumes.RemoveAt(1);
        else if (variant == "extra-owner") f.Backend.Mounts.Add(beta with { VolumeId = "Ghost", MountPoint = "T:\\" });
        else if (variant == "protected-sibling") f.Backend.Volumes[1] = Beta with { CatalogDecision = ApfsCapabilityDecision.Readable, CatalogReasons = ["special-role:system"], CatalogAutoMountAllowed = false };
        else if (variant == "encrypted-sibling") f.Backend.Volumes[1] = Beta with { IsEncrypted = true };
        else if (variant == "blocked-sibling-write") f.Backend.Volumes[1] = Beta with { NativeWriteAdmissionBlockReason = "source admission changed" };
        else f.Backend.Mounts[1] = variant switch
        {
            "zero-pid" => beta with { HostProcessId = 0 },
            "zero-creation" => beta with { HostProcessCreationTimeFileTimeUtc = 0 },
            "different-creation" => beta with { HostProcessCreationTimeFileTimeUtc = beta.HostProcessCreationTimeFileTimeUtc + 1 },
            "different-pid" => beta with { HostProcessId = beta.HostProcessId + 1 },
            "wrong-rid" => beta with { RecoveryIdentity = "stale" },
            "wrong-uuid" => beta with { CatalogVolumeUuid = Alpha.CatalogVolumeUuid },
            "wrong-oid" => beta with { CatalogVolumeObjectId = 999 },
            "missing-catalog" => beta with { CatalogVolumeId = null },
            "invalid-mount-point" => beta with { MountPoint = "S:\\folder" },
            "unknown-watermarks" => beta with { RuntimeWatermarksKnown = null },
            "recovery" => beta with { RecoveryActive = true, SnapshotRecoverySupported = true },
            "dirty" => beta with { DirtyTransactionCount = 1 },
            "pending" => beta with { RuntimeMutationPending = true },
            "wal-debt" => beta with { WalAcceptedSequence = 18 },
            "cleanup-debt" => beta with { WalCleanupSequence = 16 },
            "drain" => beta with { ShutdownDrainActive = true },
            "callbacks" => beta with { InFlightMutationCallbacks = 1 },
            _ => throw new ArgumentException(variant),
        };
        var before = f.Backend.Mounts.ToArray();
        var result = await f.Change(MountAccessMode.ReadOnly);
        Assert.False(result.Success);
        Assert.Empty(f.Backend.Events);
        Assert.Empty(f.Backend.Batches);
        Assert.Equal(before, f.Backend.Mounts);
        Assert.Equal(before.Select(m => m.MountPoint), f.Publisher.Latest.MountPoints);
    }

    [Theory]
    [InlineData("source")]
    [InlineData("rid")]
    [InlineData("membership")]
    [InlineData("owner")]
    [InlineData("debt")]
    [InlineData("write-policy")]
    [InlineData("write-capability")]
    public async Task FreshInventoryAndOwnerAreRecheckedAfterLetterPreparation(string variant)
    {
        using var f = new Fixture();
        f.Backend.OnProbe = count =>
        {
            if (count != 3) return;
            if (variant == "source") f.Backend.Volumes[1] = Beta with { NativeVolumePath = @"\\.\PhysicalDrive92|Beta" };
            if (variant == "rid") f.Backend.Volumes[1] = Beta with { RecoveryIdentity = "replacement" };
            if (variant == "membership") f.Backend.Volumes.RemoveAt(1);
            if (variant == "owner") f.Backend.Mounts[1] = f.Backend.Mounts[1] with { HostProcessCreationTimeFileTimeUtc = 999 };
            if (variant == "debt") f.Backend.Mounts[1] = f.Backend.Mounts[1] with { RuntimeMutationPending = true };
            if (variant == "write-policy") f.Options.CurrentValue.EnableNativeWrite = false;
            if (variant == "write-capability") f.Backend.Volumes[1] = Beta with { WriteUnsupportedFeatures = ["changed feature admission"] };
        };
        var result = await f.Change(MountAccessMode.ReadOnly);
        Assert.False(result.Success);
        Assert.True(f.Backend.Probes >= 3);
        Assert.Empty(f.Backend.Events);
        Assert.Empty(f.Backend.Batches);
        Assert.Equal(2, f.Policy.Selections);
        if (variant is "source" or "rid" or "membership")
            Assert.Equal(f.Backend.Volumes.ToArray(), Assert.Single(f.Publisher.Latest.ConnectedInventory!).Volumes);
    }

    [Fact]
    public async Task LetterPreferenceThatCannotRetainOriginalRefusesBeforeStop()
    {
        using var f = new Fixture();
        f.Policy.ReturnWrongLetter = true;
        Assert.False((await f.Change(MountAccessMode.ReadOnly)).Success);
        Assert.Empty(f.Backend.Events);
        Assert.Empty(f.Backend.Batches);
    }

    [Fact]
    public async Task CancellationDuringPreparationPreservesOriginalCohort()
    {
        using var f = new Fixture();
        using var cancel = new CancellationTokenSource();
        f.Policy.OnSelect = () => cancel.Cancel();
        Assert.False((await f.Change(MountAccessMode.ReadOnly, cancel.Token)).Success);
        Assert.Empty(f.Backend.Events);
        AssertCohort(f.Backend.Mounts, MountAccessMode.ReadWrite);
    }

    [Fact]
    public async Task NewInventoryWhileStorageSelectionReleasesLockSupersedesTheWholePlan()
    {
        using var f = new Fixture();
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Policy.RequiresStorage = true;
        f.Policy.OnSelect = () => { entered.TrySetResult(); Assert.True(release.Wait(TimeSpan.FromSeconds(5))); };
        var change = f.Change(MountAccessMode.ReadOnly);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            await f.Worker.GetInventoryAsync(default).WaitAsync(TimeSpan.FromSeconds(3));
        }
        finally { release.Set(); }
        Assert.False((await change.WaitAsync(TimeSpan.FromSeconds(5))).Success);
        Assert.Empty(f.Backend.Events);
        AssertCohort(f.Backend.Mounts, MountAccessMode.ReadWrite);
    }

    [Fact]
    public async Task CancellationAfterDetachPublishesRemainingOwnerAndDoesNotOpenAnother()
    {
        using var f = new Fixture();
        using var cancel = new CancellationTokenSource();
        f.Backend.AfterDetach = _ => cancel.Cancel();
        var result = await f.Change(MountAccessMode.ReadOnly, cancel.Token);
        Assert.False(result.Success);
        Assert.Equal("Beta", Assert.Single(f.Backend.Mounts).VolumeId);
        Assert.Equal("Beta", Assert.Single(f.Publisher.Latest.MountedVolumes!).VolumeId);
        Assert.Empty(f.Backend.Batches);
        await f.Cycle();
        Assert.Empty(f.Backend.Batches);
        Assert.Equal("Beta", Assert.Single(f.Backend.Mounts).VolumeId);
        Assert.Equal("Beta", Assert.Single(f.Publisher.Latest.MountedVolumes!).VolumeId);
        Assert.Equal(0, f.Backend.SingleMountCalls);
        Assert.Equal(1, f.Backend.MaxConcurrentOwners);
    }

    [Fact]
    public async Task PartialStopRestoresOnlyDetachedMemberIntoExactOriginalOwner()
    {
        using var f = new Fixture();
        var pid = f.Backend.Mounts[0].HostProcessId;
        f.Backend.FailStop = "S:\\";
        var result = await f.Change(MountAccessMode.ReadOnly);
        Assert.False(result.Success);
        Assert.Contains("exact prior cohort was restored", result.Message);
        var restore = Assert.Single(Assert.Single(f.Backend.Batches));
        Assert.Equal(new MountRequest("Alpha", 'R', MountAccessMode.ReadWrite), restore);
        AssertCohort(f.Backend.Mounts, MountAccessMode.ReadWrite);
        Assert.All(f.Backend.Mounts, m => Assert.Equal(pid, m.HostProcessId));
        Assert.Equal(1, f.Backend.MaxConcurrentOwners);
    }

    [Theory]
    [InlineData("source")]
    [InlineData("owner")]
    [InlineData("durability")]
    [InlineData("restore-refused")]
    [InlineData("restore-receipt-mismatch")]
    public async Task PartialStopRecoveryRequiresExactSourceOwnerAndDetachProof(string variant)
    {
        using var f = new Fixture();
        f.Backend.FailStop = "S:\\";
        if (variant == "durability") f.Backend.OmitDetachDurability = true;
        if (variant == "restore-refused") f.Backend.FailBatch = true;
        if (variant == "restore-receipt-mismatch") f.Backend.BatchFailure = "receipt-mode";
        f.Backend.AfterDetach = point =>
        {
            if (point != "R:\\") return;
            if (variant == "source") f.Backend.Volumes[1] = Beta with { NativeVolumePath = @"\\.\PhysicalDrive92|Beta" };
            if (variant == "owner") f.Backend.Mounts[0] = f.Backend.Mounts[0] with { HostProcessCreationTimeFileTimeUtc = 999 };
        };
        Assert.False((await f.Change(MountAccessMode.ReadOnly)).Success);
        if (variant == "restore-receipt-mismatch")
        {
            AssertCohort(f.Backend.Mounts, MountAccessMode.ReadWrite);
            Assert.Equal(2, f.Publisher.Latest.MountedVolumes!.Count);
        }
        else
        {
            Assert.Equal("Beta", Assert.Single(f.Backend.Mounts).VolumeId);
            Assert.Equal("Beta", Assert.Single(f.Publisher.Latest.MountedVolumes!).VolumeId);
        }
        var batchCount = variant.StartsWith("restore-", StringComparison.Ordinal) ? 1 : 0;
        Assert.Equal(batchCount, f.Backend.Batches.Count);
        var final = f.Backend.Mounts.ToArray();
        await f.Cycle();
        Assert.Equal(batchCount, f.Backend.Batches.Count);
        Assert.Equal(final, f.Backend.Mounts);
        Assert.Equal(1, f.Backend.MaxConcurrentOwners);
    }

    [Fact]
    public async Task OwnershipReproofCannotBeReplacedByEmptyMountObservation()
    {
        using var f = new Fixture();
        f.Backend.OmitTerminalOwnership = true;
        var result = await f.Change(MountAccessMode.ReadOnly);
        Assert.False(result.Success);
        Assert.Empty(f.Backend.Mounts);
        Assert.Empty(f.Backend.Batches);
        Assert.Empty(f.Publisher.Latest.MountPoints);
        Assert.Contains("owner", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("partial")]
    [InlineData("exception")]
    [InlineData("wrong-mode")]
    [InlineData("unknown-creation")]
    [InlineData("result-count")]
    public async Task FailedMountBatchNeverUsesOldReleaseProofToRetryOrClaimSuccess(string variant)
    {
        using var f = new Fixture();
        f.Backend.BatchFailure = variant;
        var result = await f.Change(MountAccessMode.ReadOnly);
        Assert.False(result.Success);
        Assert.Single(f.Backend.Batches);
        Assert.Equal(f.Backend.Mounts.Select(m => m.MountPoint), f.Publisher.Latest.MountPoints);
        var observed = f.Backend.Mounts.ToArray();
        await f.Cycle();
        Assert.Single(f.Backend.Batches);
        Assert.Equal(observed, f.Backend.Mounts);
        Assert.Equal(0, f.Backend.SingleMountCalls);
        Assert.Equal(1, f.Backend.MaxConcurrentOwners);
    }

    [Fact]
    public async Task SourceChangeAfterLastStopRefusesBatchAndPriorReattach()
    {
        using var f = new Fixture();
        f.Backend.AfterDetach = point =>
        {
            if (point == "S:\\") f.Backend.Volumes[1] = Beta with { RecoveryIdentity = "replacement" };
        };
        Assert.False((await f.Change(MountAccessMode.ReadOnly)).Success);
        Assert.Empty(f.Backend.Batches);
        Assert.Empty(f.Backend.Mounts);
    }

    [Fact]
    public async Task FinalObservationRevokesSuccessIfTheOwnerChangesAfterTheBatch()
    {
        using var f = new Fixture();
        f.Backend.OnProbe = _ =>
        {
            if (f.Backend.Batches.Count == 1)
                f.Backend.Mounts[1] = f.Backend.Mounts[1] with { HostProcessCreationTimeFileTimeUtc = 999 };
        };
        var result = await f.Change(MountAccessMode.ReadOnly);
        Assert.False(result.Success);
        Assert.Single(f.Backend.Batches);
        Assert.Equal(f.Backend.Mounts.Select(m => m.AccessMode), f.Publisher.Latest.MountedVolumes!.Select(m => m.AccessMode));
        var final = f.Backend.Mounts.ToArray();
        await f.Cycle();
        Assert.Equal(final, f.Backend.Mounts);
    }

    [Fact]
    public async Task MountVolume_AfterAllVolumesEjected_CoMountsAutoMountableSiblingDataVolumeAndClearsEjectedSuppression()
    {
        using var f = new Fixture(betaMode: MountAccessMode.ReadOnly);
        f.Backend.Topology = Topology();
        f.Backend.SetActive([new("Alpha", 'R', MountAccessMode.ReadOnly), new("Beta", 'S', MountAccessMode.ReadOnly)]);

        var userEjected = (HashSet<string>)typeof(ApfsMountWorker)
            .GetField("_userEjectedVolumeIds", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(f.Worker)!;
        var unsafeUnmounted = (HashSet<string>)typeof(ApfsMountWorker)
            .GetField("_unsafeUnmountedVolumeIds", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(f.Worker)!;

        // 1. Initial state: 2 active volumes sharing the same container owner process.
        Assert.Equal(2, f.Backend.Mounts.Count);
        var initialPid = f.Backend.Mounts[0].HostProcessId;
        var initialBirth = f.Backend.Mounts[0].HostProcessCreationTimeFileTimeUtc;
        Assert.Equal(initialPid, f.Backend.Mounts[1].HostProcessId);
        Assert.Equal(initialBirth, f.Backend.Mounts[1].HostProcessCreationTimeFileTimeUtc);
        var initialBatches = f.Backend.Batches.Count;
        var initialReleasedOwners = f.Backend.ReleasedOwners.Count;

        // 2. Per-volume unmount when sibling remains active: does NOT restart the container owner.
        var ejectAlpha = await f.Worker.EjectExactAsync(Device, "Alpha", CancellationToken.None, Alpha.RecoveryIdentity);
        Assert.True(ejectAlpha.Success, ejectAlpha.Message);
        Assert.Single(f.Backend.Mounts);
        Assert.Equal("Beta", f.Backend.Mounts[0].VolumeId);
        Assert.Equal(initialPid, f.Backend.Mounts[0].HostProcessId);
        Assert.Equal(initialBirth, f.Backend.Mounts[0].HostProcessCreationTimeFileTimeUtc);
        Assert.Equal(initialBatches, f.Backend.Batches.Count);
        Assert.Equal(initialReleasedOwners, f.Backend.ReleasedOwners.Count);
        Assert.Contains("Alpha", userEjected);
        Assert.DoesNotContain("Beta", userEjected);

        // 3. Eject remaining sibling Beta: all volumes of the 2-volume container are now ejected.
        var ejectBeta = await f.Worker.EjectExactAsync(Device, "Beta", CancellationToken.None, Beta.RecoveryIdentity);
        Assert.True(ejectBeta.Success, ejectBeta.Message);
        Assert.Empty(f.Backend.Mounts);
        Assert.Equal(initialReleasedOwners + 1, f.Backend.ReleasedOwners.Count);
        Assert.Contains("Alpha", userEjected);
        Assert.Contains("Beta", userEjected);

        // 4. Calling mount on one volume (Alpha):
        // co-mounts auto-mountable sibling Data volume (Beta) in the initial container batch
        // and clears ejected suppression state for container peers.
        var executor = new AgentControlCommandExecutor(f.Worker);
        var mountRequest = new ControlOperationRequestPayload(
            Guid.NewGuid().ToString("D"),
            ApfsControlCommands.Mount,
            new ApfsControlTarget(Device, "Alpha", Alpha.RecoveryIdentity),
            RequestedMode: ApfsControlModes.ReadOnly,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2));
        var mountResult = await executor.ExecuteAsync(mountRequest, CancellationToken.None);
        Assert.True(mountResult.Success, mountResult.Diagnostic);
        Assert.Equal("present", mountResult.MountProof);

        // Verify ejected suppression state was cleared for both container peers.
        Assert.DoesNotContain("Alpha", userEjected);
        Assert.DoesNotContain("Beta", userEjected);
        Assert.DoesNotContain("Alpha", unsafeUnmounted);
        Assert.DoesNotContain("Beta", unsafeUnmounted);

        // Verify initial container batch co-mounted both Alpha and auto-mountable sibling Beta.
        var latestBatch = f.Backend.Batches.Last();
        Assert.Equal(2, latestBatch.Length);
        Assert.Equal(["Alpha", "Beta"], latestBatch.Select(r => r.VolumeId).OrderBy(id => id).ToArray());

        // Verify active mount state contains both volumes under a single new container owner.
        Assert.Equal(2, f.Backend.Mounts.Count);
        var mountedAlpha = f.Backend.Mounts.Single(m => m.VolumeId == "Alpha");
        var mountedBeta = f.Backend.Mounts.Single(m => m.VolumeId == "Beta");
        Assert.Equal(mountedAlpha.HostProcessId, mountedBeta.HostProcessId);
        Assert.NotEqual(initialPid, mountedAlpha.HostProcessId);
        Assert.Equal(MountAccessMode.ReadOnly, mountedAlpha.AccessMode);
        Assert.Equal(MountAccessMode.ReadOnly, mountedBeta.AccessMode);
    }

    private static ApfsDiscoveryTopology Topology(IReadOnlyList<VolumeInfo>? catalog = null)
    {
        var disk = ApfsTopology.BuildDiskId("physical91");
        var partUuid = Guid.Parse("cccccccc-2222-3333-4444-555555555555");
        var partition = ApfsTopology.BuildPartitionId(partUuid);
        var store = ApfsTopology.BuildStoreId(partUuid);
        var container = ApfsTopology.BuildContainerId(Container);
        var volumes = (catalog ?? [Alpha, Beta]).Select(v => new ApfsVolumeRecord(v.CatalogVolumeId!, v.CatalogVolumeUuid!,
            v.CatalogVolumeObjectId!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), container, v.VolumeName,
            true, ["data"], 0, null, "sensitive", "none", false, [], [], [], "4", "20", [])).ToArray();
        return new(1, Device, [disk], new(
            [new(disk, Device, null, 4 * 1024 * 1024)],
            [new(partition, partUuid.ToString("D"), disk, 1, 1024 * 1024, 2 * 1024 * 1024, "7c3457ef-0000-11aa-aa11-00306543ecac", "apfs")],
            [new(store, partUuid.ToString("D"), partition, container, 1024 * 1024, 2 * 1024 * 1024)],
            [new(container, Container, 4096, [store], volumes.Select(v => v.Id).ToArray(), false, "20", [], [], [], [])], volumes, []));
    }

    private static VolumeInfo Volume(string name, ulong oid, string uuid)
        => new(name, Device, name, true, NativeVolumePath: Device + "|" + name,
            SupportsNativeWrite: true, RecoveryIdentity: "rid-" + name,
            CatalogVolumeId: ApfsTopology.BuildVolumeId(Container, oid), CatalogContainerUuid: Container,
            CatalogVolumeObjectId: oid, CatalogDecision: ApfsCapabilityDecision.Writable,
            CatalogReasons: [], CatalogAutoMountAllowed: true, CatalogVolumeUuid: uuid);

    private static void AssertPlan(IReadOnlyList<MountRequest> plan, MountAccessMode alpha)
        => Assert.Equal([new("Alpha", 'R', alpha), new MountRequest("Beta", 'S', MountAccessMode.ReadWrite)], plan);

    private static void AssertCohort(IReadOnlyList<MountedVolumeState> mounts, MountAccessMode alpha)
    {
        Assert.Equal(2, mounts.Count);
        var a = mounts.Single(m => m.VolumeId == "Alpha");
        var b = mounts.Single(m => m.VolumeId == "Beta");
        Assert.Equal("R:\\", a.MountPoint);
        Assert.Equal("S:\\", b.MountPoint);
        Assert.Equal(alpha, a.AccessMode);
        Assert.Equal(MountAccessMode.ReadWrite, b.AccessMode);
        Assert.True(a.HostProcessId > 0);
        Assert.True(a.HostProcessCreationTimeFileTimeUtc > 0);
        Assert.Equal(a.HostProcessId, b.HostProcessId);
        Assert.Equal(a.HostProcessCreationTimeFileTimeUtc, b.HostProcessCreationTimeFileTimeUtc);
    }

    private sealed class Fixture : IDisposable
    {
        public Backend Backend { get; }
        public RuntimeStatusPublisher Publisher { get; } = new();
        public Options Options { get; } = new();
        public Letters Policy { get; } = new();
        public ApfsMountWorker Worker { get; }
        public Fixture(MountAccessMode betaMode = MountAccessMode.ReadWrite)
        {
            Backend = new(betaMode);
            Worker = new(NullLogger<ApfsMountWorker>.Instance, Backend, Policy, Publisher, Options);
        }
        public Task<(bool Success, string Message)> Change(MountAccessMode mode, CancellationToken token = default)
            => Worker.EnsureMountedExactAsync(Device, "Alpha", mode, token, Alpha.RecoveryIdentity);
        public Task Cycle() => (Task)typeof(ApfsMountWorker).GetMethod("RunCycleAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(Worker, [CancellationToken.None])!;
        public void Dispose() => Worker.Dispose();
    }

    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new()
        {
            AutoMountEnabled = true, EnableNativeWrite = true, WriteRolloutChannel = "Enabled",
            NativeWriteAllowRawPhysicalDevices = true, NativeWritePromotionPolicy = "Pilot",
            WriteBackendMode = "Native", NativeAutoRemountOnReconnect = true,
        };
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }

    private sealed class Letters : IMountPolicy
    {
        public int Selections;
        public bool ReturnWrongLetter;
        public bool RequiresStorage;
        public bool RequiresDriveLetterStorage => RequiresStorage;
        public Action? OnSelect;
        public bool ShouldAutoMount(VolumeInfo volume) => true;
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters)
        {
            ++Selections;
            OnSelect?.Invoke();
            var letter = volume.VolumeId == "Alpha" ? 'R' : 'S';
            Assert.DoesNotContain(letter, usedLetters);
            return ReturnWrongLetter ? 'T' : letter;
        }
    }

    // Models the public contract: a detach leaves its launch-bound member in the
    // live owner; terminal receipts are available only after the last clean stop.
    private sealed class Backend : IApfsBackend, IContainerMountBackend
    {
        public List<VolumeInfo> Volumes { get; } = [Alpha, Beta];
        public ApfsDiscoveryTopology? Topology;
        public List<MountedVolumeState> Mounts { get; } = [];
        public List<MountRequest[]> Batches { get; } = [];
        public List<string> Events { get; } = [];
        public List<(int Pid, long Birth)> ReleasedOwners { get; } = [];
        public Dictionary<string, string> Data { get; } = new() { ["Alpha"] = "alpha payload", ["Beta"] = "beta payload", ["snapshot"] = "snapshot-84.2MB" };
        private readonly Dictionary<string, UnmountResult> _terminal = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, MountRequest> _launched = new(StringComparer.OrdinalIgnoreCase);
        private int _owner = 100;
        private int _nextOwner = 100;
        public int MaxConcurrentOwners { get; private set; } = 1;
        public int SingleMountCalls;
        public int Probes;
        public Action<int>? OnProbe;
        public Action<string>? AfterDetach;
        public string? FailStop;
        public bool OmitDetachDurability;
        public bool OmitTerminalOwnership;
        public bool FailBatch;
        public string? BatchFailure;

        public Backend(MountAccessMode betaMode)
        {
            SetActive([new("Alpha", 'R', MountAccessMode.ReadWrite), new("Beta", 'S', betaMode)]);
        }

        public void SetActive(IReadOnlyList<MountRequest> requests)
        {
            Mounts.Clear();
            _launched.Clear();
            foreach (var request in requests)
            {
                _launched.Add(request.VolumeId, request);
                Mounts.Add(State(request));
            }
        }

        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token)
            => Task.FromResult<IReadOnlyList<DeviceInfo>>([new(Device, "Fake ordinary container", true)]);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken token)
            => Task.FromResult<IReadOnlyList<VolumeInfo>>(Volumes.ToArray());
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            Assert.True(authoritative);
            token.ThrowIfCancellationRequested();
            OnProbe?.Invoke(++Probes);
            return Task.FromResult<IReadOnlyList<DeviceInventory>>([new(new(Device, "Fake ordinary container", true), Volumes.ToArray(), Topology)]);
        }
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<MountedVolumeState>>(Mounts.ToArray());
        }
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            ++SingleMountCalls;
            throw new InvalidOperationException("Shared transition must use the container batch contract.");
        }
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var member = Mounts.SingleOrDefault(m => m.MountPoint == point);
            if (member is null)
            {
                Events.Add("proof:" + point);
                return Task.FromResult(_terminal.Remove(point, out var proof) ? proof : new(false, point, "No terminal owner proof"));
            }
            Events.Add("stop:" + point);
            if (FailStop == point) return Task.FromResult(new UnmountResult(false, point, "Detach refused"));
            Mounts.Remove(member);
            var last = Mounts.Count == 0;
            if (last)
            {
                if (!OmitTerminalOwnership) ReleasedOwners.Add((member.HostProcessId, member.HostProcessCreationTimeFileTimeUtc));
                _owner = 0;
                foreach (var request in _launched.Values)
                    _terminal[request.DriveLetter + ":\\"] = new(true, request.DriveLetter + ":\\", null, true, !OmitTerminalOwnership, true);
            }
            AfterDetach?.Invoke(point);
            return Task.FromResult(new UnmountResult(true, point, null, true, last && !OmitTerminalOwnership, !OmitDetachDurability)
            {
                ContainerMemberDetached = !last,
            });
        }
        public Task<IReadOnlyList<MountResult>> MountContainerAsync(IReadOnlyList<MountRequest> requests, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Events.Add("batch:" + string.Join(",", requests.Select(r => r.VolumeId)));
            Batches.Add(requests.ToArray());
            if (FailBatch || BatchFailure == "empty")
                return Task.FromResult<IReadOnlyList<MountResult>>(requests.Select(r => new MountResult(false, null, "Batch refused", r.AccessMode)).ToArray());
            if (BatchFailure == "exception") throw new IOException("Batch launch failed with unproven owner cleanup");
            if (_owner != 0)
            {
                Assert.All(requests, r => Assert.Equal(_launched[r.VolumeId], r));
                Assert.DoesNotContain(Mounts, m => requests.Any(r => r.VolumeId == m.VolumeId));
            }
            else
            {
                Assert.Empty(Mounts);
                _owner = ++_nextOwner;
                _launched.Clear();
                foreach (var r in requests) _launched.Add(r.VolumeId, r);
            }
            MaxConcurrentOwners = Math.Max(MaxConcurrentOwners, 1);
            var results = new List<MountResult>();
            foreach (var r in requests)
            {
                if (BatchFailure == "partial" && r.VolumeId == "Beta") { results.Add(new(false, null, "Partial failure", r.AccessMode)); continue; }
                var state = State(r);
                if (BatchFailure == "wrong-mode" && r.VolumeId == "Alpha") state = state with { AccessMode = MountAccessMode.ReadWrite };
                if (BatchFailure == "unknown-creation") state = state with { HostProcessCreationTimeFileTimeUtc = 0 };
                Mounts.Add(state);
                results.Add(new(true, state.MountPoint, null, BatchFailure == "receipt-mode" ? MountAccessMode.ReadOnly : state.AccessMode));
            }
            if (BatchFailure == "result-count") results.RemoveAt(results.Count - 1);
            return Task.FromResult<IReadOnlyList<MountResult>>(results);
        }
        private MountedVolumeState State(MountRequest request)
        {
            var volume = Volumes.Single(v => v.VolumeId == request.VolumeId);
            return new(volume.VolumeId, request.DriveLetter + ":\\", request.AccessMode, volume.VolumeName, volume.DeviceId,
                WriteBackend: request.AccessMode == MountAccessMode.ReadWrite ? "Native" : "Disabled",
                CommitModel: request.AccessMode == MountAccessMode.ReadWrite ? NativeWriteCommitModel.CanonicalApfsCheckpoint : NativeWriteCommitModel.ScaffoldCheckpoint,
                NativeWriteReadiness: request.AccessMode == MountAccessMode.ReadWrite ? NativeWriteReadiness.CommitReady : NativeWriteReadiness.Unavailable,
                NativeWriteSafetyState: request.AccessMode == MountAccessMode.ReadWrite ? NativeWriteSafetyState.PilotReadWrite : NativeWriteSafetyState.ReadOnlyFallback,
                RecoveryIdentity: volume.RecoveryIdentity, MountReady: true, HostProcessId: _owner,
                HostProcessCreationTimeFileTimeUtc: _owner * 1000L, RuntimeWatermarksKnown: true,
                WalAcceptedSequence: request.AccessMode == MountAccessMode.ReadOnly ? 0ul : 17ul,
                WalApfsDurableSequence: request.AccessMode == MountAccessMode.ReadOnly ? 0ul : 17ul,
                WalCleanupSequence: request.AccessMode == MountAccessMode.ReadOnly ? 0ul : 17ul,
                CatalogVolumeId: volume.CatalogVolumeId, CatalogContainerUuid: volume.CatalogContainerUuid,
                CatalogVolumeObjectId: volume.CatalogVolumeObjectId, CatalogVolumeUuid: volume.CatalogVolumeUuid);
        }
    }

    private sealed class IndependentBackend(Backend inner) : IApfsBackend
    {
        public int MountCalls;
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => inner.ProbeDevicesAsync(token);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => inner.ProbeVolumesAsync(device, token);
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token) => inner.ProbeInventoryAsync(authoritative, token);
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token) => inner.GetMountStateAsync(token);
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token) => inner.UnmountAsync(point, token);
        public async Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            ++MountCalls;
            return Assert.Single(await inner.MountContainerAsync([request], token));
        }
    }
}
