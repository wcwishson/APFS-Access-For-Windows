using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.TestFixtures;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.Reflection;

namespace ApfsAccess.Service.Tests;

public sealed class PhysicalWritePermissionCommandTests
{
    [Theory]
    [InlineData(ApfsControlCommands.Mount)]
    [InlineData(ApfsControlCommands.Fix)]
    public async Task ExplicitRwAndPhysicalFixUpgradeInitialRoAndPersistExactChoice(string command)
    {
        using var route = new Route();
        var ro = await route.Execute(ApfsControlCommands.Mount, ApfsControlModes.ReadOnly);
        Assert.True(ro.Success, ro.Diagnostic);
        Assert.False(File.Exists(route.Fixture.StorePath));
        Assert.Equal(MountAccessMode.ReadOnly, route.Backend.Owner!.AccessMode);
        var oldOwner = route.Backend.Owner.HostProcessId;
        var result = await route.Execute(command, command == ApfsControlCommands.Mount ? ApfsControlModes.ReadWrite : null);
        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal("healthy-rw", result.FinalStatus);
        Assert.Equal(MountAccessMode.ReadWrite, route.Backend.Owner!.AccessMode);
        Assert.NotEqual(oldOwner, route.Backend.Owner.HostProcessId);
        Assert.Equal(1, route.Backend.Unmounts);
        Assert.Equal(command == ApfsControlCommands.Fix ? 2 : 0, route.Backend.Verifies);
        Assert.True(route.Fixture.Manager().Resolve(route.Fixture.Options,
            PhysicalWritePermissionFixture.Mask(route.Fixture.Volume)).Options.NativeWriteAllowRawPhysicalDevices);
        Assert.False(route.Fixture.Options.NativeWriteAllowRawPhysicalDevices);
        Assert.Empty(route.Fixture.Options.NativeWriteHardwarePilotDeviceAllowList);
    }

    [Theory]
    [InlineData(ApfsControlCommands.Mount, true, true)]
    [InlineData(ApfsControlCommands.Fix, true, true)]
    [InlineData(ApfsControlCommands.Mount, false, true)]
    [InlineData(ApfsControlCommands.Fix, false, true)]
    [InlineData(ApfsControlCommands.Mount, true, false)]
    [InlineData(ApfsControlCommands.Fix, true, false)]
    [InlineData(ApfsControlCommands.Mount, false, false)]
    [InlineData(ApfsControlCommands.Fix, false, false)]
    public async Task PaddedConfiguredHardwareRestrictionPreservesExplicitRwAndFixRoutes(
        string command, bool rawAllowed, bool matching)
    {
        using var route = new Route();
        var options = route.Fixture.Options;
        options.NativeWriteAllowRawPhysicalDevices = rawAllowed;
        var entry = " \t" + (matching ? route.Fixture.Volume.DeviceId : @"\\.\PhysicalDrive901") + "\r\n ";
        options.NativeWriteHardwarePilotDeviceAllowList = [entry];
        Assert.Equal(rawAllowed && matching, WriteGatePolicy.EvaluateForVolume(options, route.Fixture.Volume).AllowWrite);
        Assert.True((await route.Execute(ApfsControlCommands.Mount, ApfsControlModes.ReadOnly)).Success);
        Assert.False(File.Exists(route.Fixture.StorePath));
        var result = await route.Execute(command, command == ApfsControlCommands.Mount ? ApfsControlModes.ReadWrite : null);
        Assert.Equal(matching, result.Success);
        Assert.Equal(matching ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly, route.Backend.Owner!.AccessMode);
        Assert.Equal(matching ? 1 : 0, route.Backend.Unmounts);
        Assert.Equal(matching && !rawAllowed, File.Exists(route.Fixture.StorePath));
        Assert.Equal(rawAllowed && matching, PhysicalWritePermissions.HasConfiguredRawPermission(options, route.Fixture.Volume.DeviceId));
        Assert.False(PhysicalWritePermissions.HasConfiguredRawPermission(options, " " + route.Fixture.Volume.DeviceId + " "));
        Assert.Null(PhysicalWritePermissions.NormalizeDevice(" " + route.Fixture.Volume.DeviceId + " "));
        Assert.Equal(entry, Assert.Single(options.NativeWriteHardwarePilotDeviceAllowList));
        Assert.Equal(rawAllowed, options.NativeWriteAllowRawPhysicalDevices);
        if (matching)
        {
            Assert.Equal("healthy-rw", result.FinalStatus);
            Assert.Equal(command == ApfsControlCommands.Fix ? 2 : 0, route.Backend.Verifies);
        }
        else
        {
            Assert.Contains("PhysicalWritePermissionRefused", result.Diagnostic);
            Assert.Same(options, route.Fixture.Manager().Resolve(options, route.Fixture.Volume).Options);
        }
    }

    [Fact]
    public async Task BackgroundInventoryAndOwnerEnforcementCannotInheritPendingAdmissionOrDemoteOwner()
    {
        using var route = new Route();
        route.Backend.AfterRwMount = async () =>
        {
            Task background;
            using (ExecutionContext.SuppressFlow())
                background = Task.Run(async () =>
                {
                    var inventory = await route.Worker.GetInventoryAsync(default);
                    Assert.False(inventory[0].Volumes[0].SupportsNativeWrite);
                    var owner = Assert.Single(await route.Backend.GetMountStateAsync(default));
                    Assert.Equal(MountAccessMode.ReadWrite, owner.AccessMode);
                    Assert.True(owner.MountReady);
                    Assert.Equal(0, route.Backend.Unmounts);
                    Assert.Same(route.Fixture.Options, route.Manager.Resolve(route.Fixture.Options, inventory[0].Volumes[0]).Options);
                    Assert.Same(route.Fixture.Options, route.Fixture.Manager().Resolve(route.Fixture.Options, inventory[0].Volumes[0]).Options);
                });
            await background;
        };
        var result = await route.Execute(ApfsControlCommands.Mount, ApfsControlModes.ReadWrite);
        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal(0, route.Backend.Unmounts);
    }

    [Theory]
    [InlineData("cancel")] [InlineData("recovery")] [InlineData("store")]
    [InlineData("verification")]
    public async Task FailedOrCancelledCompletionDetachesNormallyAndPendingRecordCannotAuthorizeLaterRequest(string failure)
    {
        using var route = new Route();
        using var cancellation = new CancellationTokenSource();
        route.Backend.AfterRwMount = () =>
        {
            switch (failure)
            {
                case "cancel": cancellation.Cancel(); break;
                case "recovery": route.Backend.Owner = route.Backend.Owner! with { RecoveryActive = true, DirtyTransactionCount = 1 }; break;
                case "store": File.SetAttributes(route.Fixture.StorePath, FileAttributes.ReadOnly); break;
            }
            return Task.CompletedTask;
        };
        route.Backend.BadVerification = failure == "verification";
        try
        {
            var result = await route.Execute(failure == "verification" ? ApfsControlCommands.Fix : ApfsControlCommands.Mount,
                failure == "verification" ? null : ApfsControlModes.ReadWrite, cancellation.Token);
            Assert.False(result.Success);
            Assert.Equal(1, route.Backend.Unmounts);
            Assert.Null(route.Backend.Owner);
            Assert.Equal("absent", result.MountProof);
            if (failure == "store") Assert.Contains("PhysicalWritePermissionNotCommitted", result.Diagnostic);
        }
        finally { if (File.Exists(route.Fixture.StorePath)) File.SetAttributes(route.Fixture.StorePath, FileAttributes.Normal); }
        Assert.Same(route.Fixture.Options, route.Fixture.Manager().Resolve(route.Fixture.Options, route.Fixture.Volume).Options);
        Assert.Same(route.Fixture.Options, route.Manager.Resolve(route.Fixture.Options, route.Fixture.Volume).Options);
    }

    [Fact]
    public async Task SourceIdentityChangeRefusesGrantAndPreservesOwnerWhenExactDetachCannotBeRevalidated()
    {
        using var route = new Route();
        route.Backend.AfterRwMount = () => { route.Backend.ChangeRecoveryAfterMount = true; return Task.CompletedTask; };
        var result = await route.Execute(ApfsControlCommands.Mount, ApfsControlModes.ReadWrite);
        Assert.False(result.Success);
        Assert.Equal(0, route.Backend.Unmounts);
        Assert.NotNull(route.Backend.Owner);
        Assert.Contains("PhysicalWritePermissionGracefulDetachNotProven", result.Diagnostic);
        Assert.Same(route.Fixture.Options, route.Fixture.Manager().Resolve(route.Fixture.Options, route.Fixture.Volume).Options);
        Assert.Same(route.Fixture.Options, route.Manager.Resolve(route.Fixture.Options, route.Fixture.Volume).Options);
    }

    [Fact]
    public async Task ReplacementHealthyOwnerCannotConfirmPendingGrantOrReceiveAnUnrelatedDetach()
    {
        using var route = new Route();
        route.Backend.AfterRwMount = () =>
        {
            route.Backend.Owner = route.Backend.Owner! with { HostProcessId = route.Backend.Owner!.HostProcessId + 100 };
            return Task.CompletedTask;
        };
        var result = await route.Execute(ApfsControlCommands.Mount, ApfsControlModes.ReadWrite);
        Assert.False(result.Success);
        Assert.Equal(0, route.Backend.Unmounts);
        Assert.NotNull(route.Backend.Owner);
        Assert.Contains("PhysicalWritePermissionFinalHealthyOwnerNotProven", result.Diagnostic);
        Assert.Contains("PhysicalWritePermissionCleanupOwnerChanged", result.Diagnostic);
        Assert.Same(route.Fixture.Options, route.Fixture.Manager().Resolve(route.Fixture.Options, route.Fixture.Volume).Options);
    }

    [Theory]
    [InlineData("pid")] [InlineData("birth")] [InlineData("mount")] [InlineData("unchanged")]
    public async Task FailedPermissionCleanupPinsAdmittedOwnerAcrossOperationLockWait(string change)
    {
        using var route = new Route();
        var inventory = Assert.Single(await route.Worker.GetInventoryAsync(default));
        var target = SelectedControlTarget.Create(inventory, inventory.Volumes[0]);
        using var permission = route.Manager.Begin(route.Fixture.Options, route.Fixture.Volume, default);
        Assert.True((await route.Backend.MountAsync(new(route.Fixture.Volume.VolumeId, 'V', MountAccessMode.ReadWrite), default)).Success);
        var original = route.Backend.Owner!;
        Assert.True(permission.RetainsOwner(original.HostProcessId, original.HostProcessCreationTimeFileTimeUtc, original.MountPoint));
        var gate = (SemaphoreSlim)typeof(ApfsMountWorker).GetField("_mountOperationLock", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(route.Worker)!;
        await gate.WaitAsync();
        Task<(bool Success, string? Diagnostic)> cleanup;
        try
        {
            cleanup = CompleteFailedPermission(route, permission, target);
            Assert.False(cleanup.IsCompleted);
            Assert.Equal(0, route.Backend.Unmounts);
            route.Backend.Owner = ChangedOwner(original, change);
        }
        finally { gate.Release(); }
        var result = await cleanup;
        AssertCleanupOwnerResult(route, permission, result, change);
    }

    [Theory]
    [InlineData("pid")] [InlineData("birth")] [InlineData("mount")] [InlineData("unchanged")]
    public async Task FailedPermissionCleanupRechecksOwnerAfterSelectedTargetValidation(string change)
    {
        using var route = new Route();
        var inventory = Assert.Single(await route.Worker.GetInventoryAsync(default));
        var target = SelectedControlTarget.Create(inventory, inventory.Volumes[0]);
        using var permission = route.Manager.Begin(route.Fixture.Options, route.Fixture.Volume, default);
        Assert.True((await route.Backend.MountAsync(new(route.Fixture.Volume.VolumeId, 'V', MountAccessMode.ReadWrite), default)).Success);
        var original = route.Backend.Owner!;
        var interleaved = false;
        // Return the admitted owner's validation snapshot, then publish its replacement.
        route.Backend.AfterNextInventory = () => route.Backend.AfterNextMountStateSnapshot = () =>
        {
            interleaved = true;
            route.Backend.Owner = ChangedOwner(original, change);
        };
        var result = await CompleteFailedPermission(route, permission, target);
        Assert.True(interleaved);
        AssertCleanupOwnerResult(route, permission, result, change);
    }

    private static Task<(bool Success, string? Diagnostic)> CompleteFailedPermission(Route route,
        PhysicalWritePermissions.RequestPermission permission, ApfsControlTarget target)
        => (Task<(bool Success, string? Diagnostic)>)typeof(AgentControlCommandExecutor)
            .GetMethod("CompletePhysicalWritePermissionAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(new AgentControlCommandExecutor(route.Worker), [permission, target, false, CancellationToken.None])!;

    private static MountedVolumeState ChangedOwner(MountedVolumeState original, string change)
        => change switch
        {
            "pid" => original with { HostProcessId = original.HostProcessId + 100 },
            "birth" => original with { HostProcessCreationTimeFileTimeUtc = original.HostProcessCreationTimeFileTimeUtc + 100 },
            "mount" => original with { MountPoint = "W:\\" },
            _ => original,
        };

    private static void AssertCleanupOwnerResult(Route route, PhysicalWritePermissions.RequestPermission permission,
        (bool Success, string? Diagnostic) result, string change)
    {
        Assert.False(result.Success);
        Assert.Equal(change == "unchanged" ? 1 : 0, route.Backend.Unmounts);
        if (change == "unchanged")
        {
            Assert.Null(route.Backend.Owner);
            Assert.Contains("PhysicalWritePermissionGracefulDetach: True", result.Diagnostic);
        }
        else
        {
            var owner = Assert.IsType<MountedVolumeState>(route.Backend.Owner);
            Assert.False(permission.RetainsOwner(owner.HostProcessId, owner.HostProcessCreationTimeFileTimeUtc, owner.MountPoint));
            Assert.Contains("PhysicalWritePermissionCleanupOwnerChanged", result.Diagnostic);
        }
        Assert.Same(route.Fixture.Options, route.Fixture.Manager().Resolve(route.Fixture.Options, route.Fixture.Volume).Options);
    }

    [Fact]
    public async Task DiscoveryDefaultMountAndExplicitRoNeverEnroll()
    {
        using var route = new Route();
        await route.Worker.GetInventoryAsync(default);
        var result = await route.Execute(ApfsControlCommands.Mount, null);
        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal(MountAccessMode.ReadOnly, route.Backend.Owner!.AccessMode);
        Assert.False(File.Exists(route.Fixture.StorePath));
        result = await route.Execute(ApfsControlCommands.Mount, ApfsControlModes.ReadOnly);
        Assert.True(result.Success, result.Diagnostic);
        Assert.False(File.Exists(route.Fixture.StorePath));
    }

    [Theory]
    [InlineData("uuid")] [InlineData("oid")] [InlineData("recovery")] [InlineData("device")]
    public async Task StaleOrUnrelatedTargetCannotEnrollOrStartOwner(string changed)
    {
        using var route = new Route();
        var inventory = Assert.Single(await route.Worker.GetInventoryAsync(default));
        var target = SelectedControlTarget.Create(inventory, inventory.Volumes[0]);
        target = changed switch
        {
            "uuid" => target with { VolumeUuid = new string('e', 32) },
            "oid" => target with { VolumeObjectId = 102 },
            "recovery" => target with { RecoveryIdentity = "stale" },
            _ => target with { DeviceId = @"\\.\PhysicalDrive901" },
        };
        var result = await new AgentControlCommandExecutor(route.Worker).ExecuteAsync(
            new(Guid.NewGuid().ToString(), ApfsControlCommands.Mount, target, ApfsControlModes.ReadWrite, DateTime.UtcNow.AddMinutes(1)), default);
        Assert.False(result.Success);
        Assert.Null(route.Backend.Owner);
        Assert.False(File.Exists(route.Fixture.StorePath));
    }

    private sealed class Route : IDisposable
    {
        public PhysicalWritePermissionFixture Fixture { get; } = new();
        public PhysicalWritePermissions Manager { get; }
        public PermissionBackend Backend { get; }
        public ApfsMountWorker Worker { get; }

        public Route()
        {
            Manager = Fixture.Manager();
            Backend = new(Fixture, Manager);
            Worker = new(NullLogger<ApfsMountWorker>.Instance, Backend, new Policy(), new RuntimeStatusPublisher(), new Monitor(Fixture.Options), Manager);
        }

        public async Task<OperationResultPayload> Execute(string command, string? mode, CancellationToken token = default)
        {
            var inventory = Assert.Single(await Worker.GetInventoryAsync(default));
            var target = SelectedControlTarget.Create(inventory, inventory.Volumes[0]);
            return await new AgentControlCommandExecutor(Worker).ExecuteAsync(
                new(Guid.NewGuid().ToString(), command, target, mode, DateTime.UtcNow.AddMinutes(1)), token);
        }

        public void Dispose() { Worker.Dispose(); Fixture.Dispose(); }
    }

    private sealed class Policy : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> occupied) => 'V';
        public bool ShouldAutoMount(VolumeInfo volume) => true;
    }

    private sealed class Monitor(ServiceHostOptions options) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => options;
        public ServiceHostOptions Get(string? name) => options;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }

    private sealed class PermissionBackend(PhysicalWritePermissionFixture f, PhysicalWritePermissions manager)
        : IApfsBackend, ILiveVolumeVerificationBackend
    {
        public MountedVolumeState? Owner { get; set; }
        public Func<Task>? AfterRwMount { get; set; }
        public Action? AfterNextInventory { get; set; }
        public Action? AfterNextMountStateSnapshot { get; set; }
        public int Unmounts { get; private set; }
        public int Verifies { get; private set; }
        public bool BadVerification { get; set; }
        public bool ChangeRecoveryAfterMount { get; set; }
        private int _nextPid = 12340;

        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token)
            => Task.FromResult<IReadOnlyList<DeviceInfo>>([new(f.Volume.DeviceId, "Unit projection", true)]);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token)
            => Task.FromResult<IReadOnlyList<VolumeInfo>>([InventoryVolume()]);
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            var inventory = new DeviceInventory[] { new(new(f.Volume.DeviceId, "Unit projection", true), [InventoryVolume()], f.Topology) };
            var after = AfterNextInventory;
            AfterNextInventory = null;
            after?.Invoke();
            return Task.FromResult<IReadOnlyList<DeviceInventory>>(inventory);
        }

        private VolumeInfo InventoryVolume()
        {
            var volume = ChangeRecoveryAfterMount ? f.Volume with { RecoveryIdentity = "changed" } : f.Volume;
            manager.Observe(volume, f.Topology);
            return manager.ResolveForDiscovery(f.Options, SourcePolicyVolume(volume)).Volume;
        }

        private VolumeInfo SourcePolicyVolume(VolumeInfo volume)
            => WriteGatePolicy.EvaluateForVolume(f.Options, volume).AllowWrite ? volume : PhysicalWritePermissionFixture.Mask(volume);

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
        {
            if (Owner is null) return Task.FromResult<IReadOnlyList<MountedVolumeState>>([]);
            var current = Owner;
            if (current.AccessMode == MountAccessMode.ReadWrite)
            {
                var policy = manager.ResolveForOwner(f.Options, SourcePolicyVolume(f.Volume),
                    current.HostProcessId, current.HostProcessCreationTimeFileTimeUtc, current.MountPoint);
                if (!WriteGatePolicy.EvaluateForVolume(policy.Options, policy.Volume).AllowWrite)
                    current = current with { AccessMode = MountAccessMode.ReadOnly, NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback };
            }
            var after = AfterNextMountStateSnapshot;
            AfterNextMountStateSnapshot = null;
            after?.Invoke();
            return Task.FromResult<IReadOnlyList<MountedVolumeState>>([current]);
        }

        public async Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (request.AccessMode == MountAccessMode.ReadWrite)
            {
                var admission = manager.Resolve(f.Options, SourcePolicyVolume(f.Volume));
                Assert.True(WriteGatePolicy.EvaluateForVolume(admission.Options, admission.Volume).AllowWrite);
            }
            var rw = request.AccessMode == MountAccessMode.ReadWrite;
            var scope = new LiveVolumeVerificationScope("raw:unit-owned", "retained-admitted-raw", f.Volume.CatalogContainerUuid!,
                f.Volume.CatalogVolumeUuid!, "101", "20", "1048576", "33554432");
            Owner = new(f.Volume.VolumeId, request.DriveLetter + ":\\", request.AccessMode, f.Volume.VolumeName, f.Volume.DeviceId,
                WriteBackend: rw ? "Native" : "Disabled", NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                NativeWriteSafetyState: rw ? NativeWriteSafetyState.PilotReadWrite : NativeWriteSafetyState.ReadOnlyFallback,
                RecoveryIdentity: f.Volume.RecoveryIdentity, MountReady: true, HostProcessId: ++_nextPid,
                WalAcceptedSequence: 2, WalApfsDurableSequence: 2, WalCleanupSequence: 2, CatalogVolumeId: f.Volume.CatalogVolumeId,
                CatalogContainerUuid: f.Volume.CatalogContainerUuid, CatalogVolumeObjectId: f.Volume.CatalogVolumeObjectId,
                CatalogDecision: f.Volume.CatalogDecision, CatalogReasons: [], CatalogAutoMountAllowed: true,
                CatalogVolumeUuid: f.Volume.CatalogVolumeUuid, VolumeVerificationSupported: true, VolumeVerificationScope: scope,
                RuntimeWatermarksKnown: true, HostProcessCreationTimeFileTimeUtc: 134369000000000000 + _nextPid);
            if (rw)
            {
                manager.RetainOwner(f.Volume, Owner.HostProcessId, Owner.HostProcessCreationTimeFileTimeUtc, Owner.MountPoint);
                if (AfterRwMount is not null) await AfterRwMount();
            }
            return new(true, Owner.MountPoint, null, request.AccessMode, IsReadOnly: !rw, WriteEnabled: rw,
                WriteBackend: rw ? "Native" : "Disabled", NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                NativeWriteSafetyState: rw ? NativeWriteSafetyState.PilotReadWrite : NativeWriteSafetyState.ReadOnlyFallback,
                MountReady: true, HostProcessId: Owner.HostProcessId);
        }

        public Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken token)
        {
            Unmounts++;
            Owner = null;
            return Task.FromResult(new UnmountResult(true, mountPoint, null, true, true, true));
        }

        public Task<LiveVolumeVerificationResult> VerifyLiveVolumeAsync(LiveVolumeVerificationScope scope, CancellationToken token)
        {
            Verifies++;
            var report = LiveVolumeVerificationReport.Parse(LiveVerificationFixture.Element(LiveVerificationFixture.Report(scope, BadVerification)));
            return Task.FromResult(new LiveVolumeVerificationResult(true, "VolumeVerificationReport", report));
        }
    }
}
