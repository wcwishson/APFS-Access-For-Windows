using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class RawRuntimeStatusTests
{
    [Theory]
    [InlineData("healthy", true)]
    [InlineData("degraded", true)]
    [InlineData("wrong-pid", false)]
    [InlineData("wrong-start", false)]
    [InlineData("wrong-rid", false)]
    [InlineData("lease-released", false)]
    [InlineData("not-ready", false)]
    [InlineData("not-mounted", false)]
    [InlineData("member-detached", false)]
    [InlineData("missing-original-start", false)]
    [InlineData("missing-peer", false)]
    [InlineData("wrong-container", false)]
    [InlineData("missing", false)]
    [InlineData("malformed", false)]
    [InlineData("stale", false)]
    public async Task OriginalContainerStatusPublishesOrClearsIncarnation(string vector, bool ownerKnown)
    {
        await using var fixture = new OwnerFixture();
        fixture.WriteStatus();
        fixture.Refresh();
        Assert.Equal(fixture.Creation, fixture.Mount.HostProcessCreationTimeFileTimeUtc);
        if (vector == "member-detached") fixture.Member.GetType().GetProperty("Attached")!.SetValue(fixture.Member, false);
        if (vector == "missing-original-start") fixture.Owner.GetType()
            .GetField("<ProcessCreationTimeFileTimeUtc>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(fixture.Owner, null);
        fixture.WriteStatus(vector);
        var read = ContainerStatusReader.TryRead(fixture.StatusPath, OwnerFixture.Container);
        if (vector is "wrong-pid" or "wrong-rid" or "lease-released" or "degraded") Assert.True(read.IsKnown);
        if (vector == "wrong-pid") Assert.NotEqual(fixture.ProcessId, read.OwnerPid);
        fixture.Refresh();
        Assert.Equal(ownerKnown ? fixture.Creation : 0, fixture.Mount.HostProcessCreationTimeFileTimeUtc);
        if (vector == "healthy") Assert.Equal(OwnerFixture.Scope, fixture.Mount.VolumeVerificationScope);
        // An incarnation is an ownership fact, not synthetic raw admission.
        Assert.False(fixture.Mount.SnapshotInventorySupported);
        Assert.False(fixture.Mount.SnapshotMutationSupported);
        if (vector == "degraded")
        {
            Assert.Equal(MountAccessMode.ReadOnly, fixture.Mount.AccessMode);
            Assert.Null(fixture.Mount.VolumeVerificationScope);
        }
    }

    [Fact]
    public async Task IncarnationOnlyChangeIsPublishedAndUnchangedRefreshIsStable()
    {
        await using var fixture = new OwnerFixture();
        fixture.WriteStatus();
        fixture.Refresh();
        var known = fixture.Mount;
        fixture.Mount = known with { HostProcessCreationTimeFileTimeUtc = 0 };
        var version = fixture.Version;
        fixture.Refresh();
        Assert.Equal(known, fixture.Mount);
        Assert.Equal(version + 1, fixture.Version);
        fixture.Refresh();
        Assert.Equal(version + 1, fixture.Version);
    }

    [Theory]
    [InlineData("observer")]
    [InlineData("stop-requested")]
    [InlineData("exited-retained")]
    [InlineData("poisoned-already-readonly")]
    public async Task RetainedOrStoppedOwnerCannotKeepAnEarlierPin(string path)
    {
        await using var fixture = new OwnerFixture();
        fixture.WriteStatus();
        fixture.Refresh();
        Assert.True(fixture.Mount.HostProcessCreationTimeFileTimeUtc > 0);
        var version = fixture.Version;
        if (path is "observer" or "exited-retained") fixture.ClaimObserver();
        if (path == "stop-requested") fixture.Owner.GetType().GetField("StopRequestedTimestamp")!
            .SetValue(fixture.Owner, Stopwatch.GetTimestamp());
        if (path == "exited-retained")
        {
            fixture.Guardian.TryTerminate(13);
            await fixture.Process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(SpinWait.SpinUntil(() => fixture.Guardian.IsSettled, TimeSpan.FromSeconds(5)));
        }
        if (path == "poisoned-already-readonly")
        {
            fixture.Mount = fixture.Mount with { MountReady = false, AccessMode = MountAccessMode.ReadOnly, WriteBackend = "Disabled" };
            Invoke(fixture.Backend, "PoisonContainerGroup_NoLock", fixture.Group, "OfflineOwnershipLost");
        }
        else fixture.Refresh();
        Assert.Equal(0, fixture.Mount.HostProcessCreationTimeFileTimeUtc);
        Assert.True(fixture.Version > version);
        Assert.True(fixture.HasRetainedGroup);
        Assert.True(File.Exists(fixture.StatusPath));
    }

    [Fact]
    public async Task UnexpectedStopProjectionClearsPin()
    {
        await using var fixture = new OwnerFixture();
        fixture.WriteStatus();
        fixture.Refresh();
        var type = typeof(NativeApfsBackend).GetNestedType("HostStopResult", BindingFlags.NonPublic)!;
        var stop = Activator.CreateInstance(type, [true, false, 9])!;
        var marked = (MountedVolumeState)typeof(NativeApfsBackend).GetMethod("MarkUnexpectedHostStop",
            BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [fixture.Mount, stop])!;
        Assert.Equal(0, marked.HostProcessCreationTimeFileTimeUtc);
        Assert.True(marked.RecoveryActive);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProducedOwnerAndNativeScopeSurviveProjectionAndWire(bool unknown)
    {
        await using var fixture = new OwnerFixture();
        fixture.WriteStatus();
        fixture.Refresh();
        if (unknown)
        {
            fixture.WriteStatus("missing");
            fixture.Refresh();
        }
        var mount = fixture.Mount;
        var status = new StatusChangedPayload(RuntimeState.MountedRw, [OwnerFixture.Point], null, DateTime.UtcNow,
            [], false, [], MountedVolumes: MountedStatusProjection.FromMounts([mount]));
        var wire = PipeMessageCodec.Serialize(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status));
        Assert.True(PipeMessageCodec.TryDeserialize(wire, out var envelope));
        Assert.True(PipeMessageCodec.TryGetPayload<StatusChangedPayload>(envelope!, out var received));
        var display = Assert.Single(received!.MountedVolumes!);
        Assert.Equal(mount.HostProcessId, display.HostProcessId);
        Assert.Equal(mount.HostProcessCreationTimeFileTimeUtc, display.HostProcessCreationTimeFileTimeUtc);
        Assert.Equal(mount.RecoveryIdentity, display.RecoveryIdentity);
        Assert.Equal(mount.VolumeVerificationScope, display.VolumeVerificationScope);
        Assert.Equal(!unknown, wire.Contains("hostProcessCreationTimeFileTimeUtc", StringComparison.Ordinal));
    }

    private static object? Invoke(object target, string method, params object?[] args)
        => target.GetType().GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(target, args);

    private sealed class OwnerFixture : IAsyncDisposable
    {
        public const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        public const string Point = "R:\\";
        private const string Rid = "offline-rec-101";
        private const string RawShape = @"\\.\PhysicalDrive987654";
        public static readonly LiveVolumeVerificationScope Scope = new("offline-native-status-shape", "retained-admitted-raw",
            Container, new string('b', 32), "101", "91", "8192", "134217728");
        private readonly string _root = Path.Combine(Path.GetTempPath(), "RawRuntimeStatus", Guid.NewGuid().ToString("N"));
        private readonly IDictionary _groups;
        private readonly IDictionary _observers;
        private readonly ConcurrentDictionary<string, MountedVolumeState> _mounts;
        private Process? _otherProcess;
        private HostProcessGuardian? _otherGuardian;
        public NativeApfsBackend Backend { get; }
        public Process Process { get; }
        public HostProcessGuardian Guardian { get; }
        public object Owner { get; }
        public object Group { get; }
        public object Member { get; }
        public string StatusPath => Path.Combine(_root, "status.json");
        public int ProcessId => checked((int)Guardian.ProcessId);
        public long Creation => Guardian.CreationTimeFileTimeUtc;
        public bool HasRetainedGroup => _groups.Count == 1;
        public long Version => (long)typeof(NativeApfsBackend).GetField("_mountStateVersion", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(Backend)!;
        public MountedVolumeState Mount { get => _mounts[Point]; set => _mounts[Point] = value; }

        public OwnerFixture()
        {
            Directory.CreateDirectory(_root);
            Process = StartChild("original");
            Guardian = HostProcessGuardian.Create(Process);
            Backend = new NativeApfsBackend(new ServiceHostOptions
            {
                WriteBackendMode = "Native", EnableRawSnapshots = false, EnableImageSnapshots = false,
                NativeWriteEvidenceStorePath = Path.Combine(_root, "evidence.json"),
            }, new HostProcessLifecycleTestHooks { QueryDosDevice = (_, _) => (0u, 2) });
            var ownerType = typeof(NativeApfsBackend).GetNestedType("HostProcessState", BindingFlags.NonPublic)!;
            Owner = ownerType.GetConstructors().Single(c => c.GetParameters().Length == 8).Invoke(
                [Process, Guardian, null, Path.Combine(_root, "alive"), Path.Combine(_root, "gate"), StatusPath, MountAccessMode.ReadWrite, "Native"]);
            ownerType.GetProperty("OriginalMountPoints")!.SetValue(Owner, new[] { Point });
            var groupType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupState", BindingFlags.NonPublic)!;
            Group = Activator.CreateInstance(groupType, [Container, RawShape, 8192UL, Path.Combine(_root, "manifest"), Owner, true])!;
            var memberType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupMember", BindingFlags.NonPublic)!;
            Member = Activator.CreateInstance(memberType, [$"apfs-vol:{Container}:101", Point, 101UL, true, Rid, true, true, DateTime.UtcNow])!;
            ((IDictionary)groupType.GetProperty("Members")!.GetValue(Group)!).Add(Point, Member);
            _groups = (IDictionary)Field("_containerGroups");
            _groups.Add(Container, Group);
            _observers = (IDictionary)Field("_hostExitObservers");
            _mounts = (ConcurrentDictionary<string, MountedVolumeState>)Field("_mounts");
            Mount = new($"apfs-vol:{Container}:101", Point, MountAccessMode.ReadOnly, DeviceId: RawShape, RecoveryIdentity: Rid);
        }

        private object Field(string name) => typeof(NativeApfsBackend).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(Backend)!;
        public void Refresh() => Invoke(Backend, "RefreshContainerGroupMounts_NoLock");
        public void ClaimObserver() => _observers.Add(Owner.GetType().GetProperty("TrackingKey")!.GetValue(Owner)!, new TaskCompletionSource().Task);

        private Process StartChild(string name)
        {
            var executable = Environment.GetEnvironmentVariable("APFSACCESS_RAW_RUNTIME_TEST_CHILD");
            var guardianFallback = string.IsNullOrWhiteSpace(executable);
            if (guardianFallback) executable = Environment.GetEnvironmentVariable("APFSACCESS_GUARDIAN_TEST_CHILD");
            Assert.True(!string.IsNullOrWhiteSpace(executable) && File.Exists(executable), "Dedicated offline child is required.");
            var ready = Path.Combine(_root, name + ".ready");
            var start = new ProcessStartInfo(executable!) { UseShellExecute = false, CreateNoWindow = true };
            if (guardianFallback) start.ArgumentList.Add("--ready");
            start.ArgumentList.Add(ready);
            var process = System.Diagnostics.Process.Start(start)!;
            Assert.True(SpinWait.SpinUntil(() => File.Exists(ready), TimeSpan.FromSeconds(5)));
            return process;
        }

        public void WriteStatus(string vector = "healthy")
        {
            if (vector == "missing") { File.Delete(StatusPath); return; }
            if (vector == "malformed") { File.WriteAllText(StatusPath, "{"); return; }
            var pid = ProcessId;
            var start = Creation;
            if (vector == "wrong-pid")
            {
                _otherProcess = StartChild("independently-owned-row");
                _otherGuardian = HostProcessGuardian.Create(_otherProcess);
                pid = checked((int)_otherGuardian.ProcessId);
                start = _otherGuardian.CreationTimeFileTimeUtc;
            }
            var lease = vector != "lease-released";
            var mounted = vector != "not-mounted";
            var ready = mounted && vector != "not-ready";
            var degraded = vector == "degraded";
            var capable = lease && ready && !degraded;
            var row = new
            {
                objectId = "101", canonicalId = $"apfs-vol:{Container}:101", mounted, ready, writable = capable,
                recoveryIdentity = vector == "wrong-rid" ? "replacement" : Rid,
                recoveryActive = false, writeDegraded = degraded, recoveryReason = "",
                snapshotInventorySupported = capable, snapshotMutationSupported = capable,
                volumeVerificationSupported = capable,
                volumeVerificationScope = capable ? new { sourceIdentity = Scope.SourceIdentity, sourceKind = Scope.SourceKind,
                    containerUuid = Container, volumeUuid = Scope.VolumeUuid, volumeOid = "101", checkpointXid = "91",
                    storeOffsetBytes = "8192", storeSizeBytes = "134217728" } : null,
                dirtyTransactionCount = 0, inFlightMutationCallbacks = 0, shutdownDrainActive = false,
                closeCommitDeferred = false, deferredCommitRequested = false, deferredCommitInFlight = false,
                walRecoveryStateValid = true, walAcceptedSequence = "1", walApfsDurableSequence = "1", walCleanupSequence = "1",
                payloadSpoolDirtyRangeCount = "0", payloadSpoolIndexDirty = false, payloadSpoolRecoveryRequired = false,
            };
            File.WriteAllText(StatusPath, JsonSerializer.Serialize(new
            {
                containerUuid = vector == "wrong-container" ? new string('c', 32) : Container, ownerPid = pid,
                ownerStartFileTimeUtc = start + (vector == "wrong-start" ? 1 : 0), leaseHeld = lease, checkpointXid = "91",
                recoveryRequired = false, recoveryVolumeObjectId = (string?)null, recoveryReason = "",
                volumes = vector == "missing-peer" ? Array.Empty<object>() : new object[] { row },
            }));
            if (vector == "stale") File.SetLastWriteTimeUtc(StatusPath, DateTime.UtcNow.AddMinutes(-2));
        }

        public async ValueTask DisposeAsync()
        {
            _groups.Clear(); _observers.Clear(); _mounts.Clear();
            Backend.Dispose();
            Guardian.Dispose();
            await Guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            Process.Dispose();
            if (_otherGuardian is not null)
            {
                _otherGuardian.Dispose();
                await _otherGuardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
                _otherProcess!.Dispose();
            }
            Directory.Delete(_root, true);
        }
    }
}
