using System.Collections;
using System.Diagnostics;
using System.Reflection;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

// Real command/coordinator/worker/native-cache flow with synthetic terminal facts.
// No process, device, namespace probe, or native executable is used.
public sealed class ShutdownReconciliationTests
{
    private const BindingFlags All = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;

    [Fact]
    public async Task QuitRetry_UsesLateOriginalProofAndPreservesFailedReceipt()
    {
        using var f = new Fixture();
        var firstRequest = Quit();
        var failed = await f.Operations.ExecuteOrReplayAsync(firstRequest);
        Assert.False(failed.Success);
        Assert.Equal("shutdown-incomplete", failed.FinalStatus);
        var failedBytes = File.ReadAllBytes(failed.EvidencePath!);
        var partial = await f.Worker.PrepareForShutdownAsync(CancellationToken.None);
        Assert.True(partial.UnmountResultsOrEmpty[f.Backend.First.VolumeId].PendingDurabilityCleared);
        Assert.False(partial.HostOwnershipReleased);

        f.Backend.PublishTerminal();
        var completed = await f.Operations.ExecuteOrReplayAsync(Quit());

        Assert.True(completed.Success, completed.Diagnostic);
        Assert.Equal("shutdown-complete", completed.FinalStatus);
        Assert.Equal("proven", completed.OwnershipProof);
        Assert.Equal("proven", completed.DurabilityProof);
        Assert.Equal(2, f.Backend.UnmountCalls);
        Assert.Equal(failedBytes, File.ReadAllBytes(failed.EvidencePath!));
        Assert.Equal(failed, await f.Operations.ExecuteOrReplayAsync(firstRequest));
        Assert.True((await f.Backend.Native.GetUnmountTerminalStateAsync(f.Backend.First, CancellationToken.None)).Success);
        Assert.True((await f.Backend.Native.GetUnmountTerminalStateAsync(f.Backend.First, CancellationToken.None)).Success);
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("forced")]
    [InlineData("nonzero")]
    [InlineData("durability")]
    [InlineData("native-terminal")]
    public async Task QuitRetry_AbsenceCannotReplaceFailedOrUnknownOriginalProof(string vector)
    {
        using var f = new Fixture();
        Assert.False((await f.Operations.ExecuteOrReplayAsync(Quit())).Success);
        if (vector != "unknown") f.Backend.PublishTerminal(vector);

        var retry = await f.Operations.ExecuteOrReplayAsync(Quit());

        Assert.False(retry.Success);
        Assert.Equal("not-proven", retry.OwnershipProof);
        Assert.Equal("not-proven", retry.DurabilityProof);
        Assert.Equal(2, f.Backend.UnmountCalls);
        var proof = await f.Worker.PrepareForShutdownAsync(CancellationToken.None);
        Assert.Equal("Original control timed out; preserve recovery evidence.",
            proof.UnmountResultsOrEmpty[f.Backend.Last.VolumeId].Error);
        Assert.True(proof.UnmountResultsOrEmpty[f.Backend.First.VolumeId].PendingDurabilityCleared);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task QuitRetry_RejectsDifferentSelectedPidOrCreationTime(bool samePid)
    {
        using var f = new Fixture();
        Assert.False((await f.Operations.ExecuteOrReplayAsync(Quit())).Success);
        f.Backend.PublishTerminal();
        f.Backend.Replacement = samePid
            ? f.Backend.First with { HostProcessCreationTimeFileTimeUtc = f.Backend.First.HostProcessCreationTimeFileTimeUtc + 1 }
            : f.Backend.First with { HostProcessId = f.Backend.First.HostProcessId + 1 };

        var retry = await f.Operations.ExecuteOrReplayAsync(Quit());

        Assert.False(retry.Success);
        Assert.Contains("owner changed", retry.Diagnostic, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, f.Backend.UnmountCalls);
        var retained = await f.Worker.PrepareForShutdownAsync(CancellationToken.None);
        Assert.True(retained.UnmountResultsOrEmpty[f.Backend.First.VolumeId].PendingDurabilityCleared);
        var foreign = await f.Backend.Native.GetUnmountTerminalStateAsync(f.Backend.Replacement, CancellationToken.None);
        Assert.False(foreign.Success);
        Assert.False(foreign.PendingDurabilityCleared);
    }

    [Theory]
    [InlineData("pid")]
    [InlineData("creation")]
    [InlineData("volume")]
    [InlineData("recovery")]
    [InlineData("container")]
    [InlineData("object")]
    [InlineData("uuid")]
    public async Task NativeTerminalQuery_RejectsUnknownOrDifferentOwnerScope(string vector)
    {
        using var f = new Fixture();
        f.Backend.PublishTerminal();
        var selected = vector switch
        {
            "pid" => f.Backend.First with { HostProcessId = 0 },
            "creation" => f.Backend.First with { HostProcessCreationTimeFileTimeUtc = 0 },
            "volume" => f.Backend.First with { VolumeId = "another-volume" },
            "recovery" => f.Backend.First with { RecoveryIdentity = "another-recovery" },
            "container" => f.Backend.First with { CatalogContainerUuid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
            "object" => f.Backend.First with { CatalogVolumeObjectId = 999 },
            _ => f.Backend.First with { CatalogVolumeUuid = "another-uuid" },
        };
        var proof = await f.Backend.Native.GetUnmountTerminalStateAsync(selected, CancellationToken.None);
        Assert.False(proof.Success);
        Assert.False(proof.HostOwnershipReleased);
        Assert.False(proof.PendingDurabilityCleared);
    }

    [Fact]
    public async Task QuitRetry_UnknownSelectedOwnerCannotUseNominalCompleteProof()
    {
        using var f = new Fixture();
        f.Backend.First = f.Backend.First with { HostProcessId = 0, HostProcessCreationTimeFileTimeUtc = 0 };
        f.Backend.Last = f.Backend.Last with { HostProcessId = 0, HostProcessCreationTimeFileTimeUtc = 0 };
        f.Backend.OfferUnscopedSuccess = true;
        Assert.False((await f.Operations.ExecuteOrReplayAsync(Quit())).Success);
        Assert.False((await f.Operations.ExecuteOrReplayAsync(Quit())).Success);
        Assert.Equal(0, f.Backend.TerminalCalls);
        Assert.Equal(2, f.Backend.UnmountCalls);
    }

    [Fact]
    public async Task NativeTerminalCache_BoundsCompletedCyclesAndPreservesUnresolvedOriginal()
    {
        using var f = new Fixture();
        const int capacity = 256;
        for (var cycle = 0; cycle < capacity * 3; cycle++)
        {
            f.Backend.CompleteCycle(cycle);
            Assert.InRange(f.Backend.RetainedCount, 2, capacity + 2);
        }

        Assert.False((await f.Backend.Native.GetUnmountTerminalStateAsync(f.Backend.First, CancellationToken.None)).Success);
        var evicted = f.Backend.First with
        {
            HostProcessCreationTimeFileTimeUtc = f.Backend.First.HostProcessCreationTimeFileTimeUtc + 1,
        };
        Assert.False((await f.Backend.Native.GetUnmountTerminalStateAsync(evicted, CancellationToken.None)).Success);
        var newest = f.Backend.First with
        {
            HostProcessCreationTimeFileTimeUtc = f.Backend.First.HostProcessCreationTimeFileTimeUtc + capacity * 3,
        };
        Assert.True((await f.Backend.Native.GetUnmountTerminalStateAsync(newest, CancellationToken.None)).Success);

        f.Backend.PublishTerminal();
        Assert.True((await f.Backend.Native.GetUnmountTerminalStateAsync(f.Backend.First, CancellationToken.None)).Success);
        Assert.True((await f.Backend.Native.GetUnmountTerminalStateAsync(f.Backend.Last, CancellationToken.None)).Success);
        Assert.InRange(f.Backend.RetainedCount, 2, capacity);
        Assert.False((await f.Backend.Native.GetUnmountTerminalStateAsync(
            f.Backend.First with { HostProcessId = 0 }, CancellationToken.None)).Success);
        Assert.False((await f.Backend.Native.GetUnmountTerminalStateAsync(
            f.Backend.First with { HostProcessCreationTimeFileTimeUtc = newest.HostProcessCreationTimeFileTimeUtc + 1 },
            CancellationToken.None)).Success);
    }

    private static ControlOperationRequestPayload Quit()
        => new(Guid.NewGuid().ToString("D"), ApfsControlCommands.Quit, null, ExpiresAtUtc: DateTime.UtcNow.AddMinutes(1));

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(
            "D:\\ApfsAccessScratch\\WindowsClosure\\shutdown-reconcile-20261014\\results\\fixtures",
            Guid.NewGuid().ToString("N"));
        public readonly RetainedBackend Backend;
        public readonly ApfsMountWorker Worker;
        public readonly AgentControlOperationService Operations;
        public Fixture()
        {
            Directory.CreateDirectory(_root);
            Backend = new(_root);
            Worker = new(NullLogger<ApfsMountWorker>.Instance, Backend, new Policy(), new RuntimeStatusPublisher(),
                new Options(new ServiceHostOptions { NativeHostStopTimeoutSeconds = 1 }));
            var executor = new AgentControlCommandExecutor(Worker, _ => true);
            Operations = new(executor.ExecuteAsync, Path.Combine(_root, "operations"));
        }
        public void Dispose()
        {
            Worker.Dispose();
            Backend.Native.Dispose();
            Backend.Process.Dispose();
        }
    }

    private sealed class RetainedBackend : IApfsBackend, IUnmountTerminalStateBackend
    {
        public readonly NativeApfsBackend Native;
        public readonly Process Process = new();
        private readonly object _owner;
        public MountedVolumeState First;
        public MountedVolumeState Last;
        public MountedVolumeState? Replacement;
        public bool OfferUnscopedSuccess;
        public int UnmountCalls;
        public int TerminalCalls;
        public int RetainedCount => ((IDictionary)typeof(NativeApfsBackend)
            .GetField("_unmountTerminalOwners", All)!.GetValue(Native)!).Count;
        public RetainedBackend(string root)
        {
            Native = new(new ServiceHostOptions { NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json") },
                new HostProcessLifecycleTestHooks
                {
                    IsMountVisible = _ => throw new InvalidOperationException("No namespace probe allowed."),
                    ProbeSystemProcessPresence = _ => throw new InvalidOperationException("No process probe allowed."),
                });
            First = Row("Alpha", Path.Combine(root, "alpha"), 101);
            Last = Row("Beta", Path.Combine(root, "beta"), 102);
            var type = typeof(NativeApfsBackend).GetNestedType("HostProcessState", BindingFlags.NonPublic)!;
            _owner = type.GetConstructors(All).Single(c => c.GetParameters().Length == 8)
                .Invoke([Process, null, null, Path.Combine(root, "lifetime"), "", Path.Combine(root, "status"), MountAccessMode.ReadWrite, "Native"]);
            type.GetField("<ProcessId>k__BackingField", All)!.SetValue(_owner, First.HostProcessId);
            type.GetField("<ProcessCreationTimeFileTimeUtc>k__BackingField", All)!
                .SetValue(_owner, (long?)First.HostProcessCreationTimeFileTimeUtc);
            var mounts = (IDictionary)typeof(NativeApfsBackend).GetField("_mounts", All)!.GetValue(Native)!;
            var groups = (IDictionary)typeof(NativeApfsBackend).GetField("_containerGroups", All)!.GetValue(Native)!;
            var groupType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupState", BindingFlags.NonPublic)!;
            var group = Activator.CreateInstance(groupType,
                [First.CatalogContainerUuid!, "offline-device", 0UL, Path.Combine(root, "manifest"), _owner, true])!;
            var members = (IDictionary)groupType.GetProperty("Members")!.GetValue(group)!;
            var memberType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupMember", BindingFlags.NonPublic)!;
            foreach (var row in new[] { First, Last })
            {
                mounts.Add(row.MountPoint, row);
                members.Add(row.MountPoint, Activator.CreateInstance(memberType,
                    [row.VolumeId, row.MountPoint, row.CatalogVolumeObjectId!.Value, true,
                        row.RecoveryIdentity!, true, true, DateTime.UtcNow])!);
            }
            groups.Add(First.CatalogContainerUuid!, group);
            typeof(NativeApfsBackend).GetMethod("RetainUnmountTerminalOwners_NoLock", All)!.Invoke(Native, null);
            mounts.Clear();
            groups.Clear();
        }

        public void PublishTerminal(string vector = "clean")
            => PublishTerminal(_owner, vector);

        private void PublishTerminal(object owner, string vector = "clean")
        {
            var type = typeof(NativeApfsBackend).GetNestedType("HostStopResult", BindingFlags.NonPublic)!;
            var stop = Activator.CreateInstance(type, [true, vector == "forced", vector == "nonzero" ? 10 : 0])!;
            foreach (var name in new[] { "GuardianSettled", "MountAbsent", "OwnershipReleased", "NativeTerminalProven", "PendingDurabilityCleared" })
                type.GetProperty(name)!.SetValue(stop, name switch
                {
                    "PendingDurabilityCleared" => vector != "durability",
                    "NativeTerminalProven" => vector != "native-terminal",
                    _ => true,
                });
            owner.GetType().GetProperty("CompletedStopResult")!.SetValue(owner, stop);
            typeof(NativeApfsBackend).GetMethod("PublishUnmountTerminalProof", All)?.Invoke(Native, [owner]);
        }

        public void CompleteCycle(int cycle)
        {
            var selected = First with { HostProcessCreationTimeFileTimeUtc = First.HostProcessCreationTimeFileTimeUtc + cycle + 1 };
            using var process = new Process();
            var type = _owner.GetType();
            var owner = type.GetConstructors(All).Single(c => c.GetParameters().Length == 8)
                .Invoke([process, null, null, "", "", "", MountAccessMode.ReadWrite, "Native"]);
            type.GetField("<ProcessId>k__BackingField", All)!.SetValue(owner, selected.HostProcessId);
            type.GetField("<ProcessCreationTimeFileTimeUtc>k__BackingField", All)!
                .SetValue(owner, (long?)selected.HostProcessCreationTimeFileTimeUtc);
            var mounts = (IDictionary)typeof(NativeApfsBackend).GetField("_mounts", All)!.GetValue(Native)!;
            var hosts = (IDictionary)typeof(NativeApfsBackend).GetField("_hosts", All)!.GetValue(Native)!;
            mounts.Add(selected.MountPoint, selected);
            hosts.Add(selected.MountPoint, owner);
            typeof(NativeApfsBackend).GetMethod("RetainUnmountTerminalOwners_NoLock", All)!.Invoke(Native, null);
            mounts.Clear();
            hosts.Clear();
            PublishTerminal(owner);
        }
        private static MountedVolumeState Row(string name, string point, ulong oid)
            => new("offline|" + name, point, MountAccessMode.ReadWrite, name, "offline-device",
                RecoveryIdentity: "recovery-" + name, HostProcessId: 424242,
                HostProcessCreationTimeFileTimeUtc: 134364468045847446,
                CatalogContainerUuid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CatalogVolumeObjectId: oid, CatalogVolumeUuid: "uuid-" + name);
        public Task<UnmountResult> GetUnmountTerminalStateAsync(MountedVolumeState selected, CancellationToken token)
        {
            TerminalCalls++;
            return OfferUnscopedSuccess
                ? Task.FromResult(new UnmountResult(true, selected.MountPoint, null, true, true, true))
                : Native.GetUnmountTerminalStateAsync(selected, token);
        }
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token)
        {
            UnmountCalls++;
            if (UnmountCalls > 2) return Task.FromResult(new UnmountResult(false, point, "Mount point is not mounted."));
            return Task.FromResult(UnmountCalls == 1
                ? new UnmountResult(true, point, null, true, false, true)
                : new UnmountResult(false, point, "Original control timed out; preserve recovery evidence.", MountRemoved: true));
        }
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
            => Task.FromResult<IReadOnlyList<MountedVolumeState>>(Replacement is not null ? [Replacement] : UnmountCalls == 0 ? [First, Last] : []);
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string id, CancellationToken token) => throw new NotSupportedException();
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token) => throw new NotSupportedException();
    }

    private sealed class Policy : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> used) => 'Z';
        public bool ShouldAutoMount(VolumeInfo volume) => false;
    }
    private sealed class Options(ServiceHostOptions value) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => value;
        public ServiceHostOptions Get(string? name) => value;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
}
