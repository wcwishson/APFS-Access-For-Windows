using System.Collections;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class RawSnapshotContractTests
{
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Volume = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static LiveVolumeVerificationScope Scope => new("raw:gpt-held-window", "retained-admitted-raw",
        Container, Volume, "101", "91", "8192", "134217728");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NativeProvenRecoveryForwardsAcceptedDebtWithoutWritableOrInventory(bool retainedInventory)
    {
        using var route = new Route(debt: true, retainedInventory: retainedInventory);
        var mount = Assert.Single(await route.Backend.GetMountStateAsync(default));
        Assert.Equal(MountAccessMode.ReadOnly, mount.AccessMode);
        Assert.True(mount.RecoveryActive);
        Assert.True(mount.SnapshotRecoverySupported);
        Assert.False(mount.SnapshotInventorySupported);
        Assert.False(mount.SnapshotMutationSupported);
        var pending = route.Send(SnapshotControlAction.Recover);
        var lines = await route.Request(pending);
        Assert.Equal("snapshot-recover", lines[3]);
        Assert.Equal(5, lines.Length);
        await route.Reply(lines);
        Assert.True((await pending).Success);
        Assert.False((await route.Send(SnapshotControlAction.Create, ["blocked"])).Success);
        Assert.False(File.Exists(route.Control));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RuntimeMutationAndScopedListForwardToSameOwnerWithInventoryCoexistence(bool retainedInventory)
    {
        using var route = new Route(retainedInventory: retainedInventory);
        var mount = Assert.Single(await route.Backend.GetMountStateAsync(default));
        Assert.True(mount.SnapshotInventorySupported);
        Assert.True(mount.SnapshotMutationSupported);
        Assert.True(mount.SnapshotRecoverySupported);
        var pending = route.Send(SnapshotControlAction.Create, ["raw-check"]);
        var lines = await route.Request(pending);
        Assert.Equal("snapshot-create", lines[3]);
        Assert.Equal("raw-check", lines[5]);
        await route.Reply(lines);
        Assert.True((await pending).Success);
        pending = route.Send(SnapshotControlAction.List, Scope.RequestLines);
        lines = await route.Request(pending);
        Assert.Equal("snapshot-list", lines[3]);
        Assert.Equal(Scope.RequestLines, lines.Skip(5));
        var inventory = new LiveSnapshotInventory(Container, Volume, "101", "92", "8192", "134217728", []);
        await route.Reply(lines, inventory);
        Assert.True((await pending).Success);
    }

    [Theory]
    [InlineData("option-disabled")]
    [InlineData("not-launched")]
    [InlineData("missing-qualification")]
    [InlineData("missing-retained-qualification")]
    [InlineData("native-write-disabled")]
    [InlineData("raw-disabled")]
    [InlineData("noncanonical")]
    [InlineData("overlay")]
    [InlineData("manifest-missing")]
    [InlineData("missing-peer")]
    [InlineData("wrong-peer-identity")]
    [InlineData("detached-peer")]
    [InlineData("readonly-peer")]
    [InlineData("not-enrolled-peer")]
    [InlineData("owner-start")]
    [InlineData("stale")]
    [InlineData("native-refused")]
    [InlineData("credential-missing")]
    public async Task UnprovedRecoveryRefusesBeforePublicationAndProjection(string failure)
    {
        using var route = new Route(failure, debt: true);
        var result = await route.Send(SnapshotControlAction.Recover);
        Assert.False(result.Success, failure);
        Assert.False(File.Exists(route.Control), failure);
        // Credential availability is checked by dispatch; status capabilities describe the runtime.
        if (failure != "credential-missing")
            Assert.False(Assert.Single(await route.Backend.GetMountStateAsync(default)).SnapshotRecoverySupported);
    }

    [Fact]
    public async Task OptionAndLaunchFlagCannotInventNativeCapabilities()
    {
        using var route = new Route("all-native-refused");
        var mount = Assert.Single(await route.Backend.GetMountStateAsync(default));
        Assert.False(mount.SnapshotInventorySupported);
        Assert.False(mount.SnapshotMutationSupported);
        Assert.False(mount.SnapshotRecoverySupported);
        foreach (var action in new[] { SnapshotControlAction.Create, SnapshotControlAction.List, SnapshotControlAction.Recover })
        {
            Assert.False((await route.Send(action, action == SnapshotControlAction.Create ? ["blocked"] :
                action == SnapshotControlAction.List ? Scope.RequestLines : null)).Success);
            Assert.False(File.Exists(route.Control));
        }
    }

    [Theory]
    [InlineData("removed")]
    [InlineData("bus")]
    [InlineData("vendor")]
    [InlineData("product")]
    [InlineData("serial")]
    [InlineData("serial-case")]
    [InlineData("scheme")]
    [InlineData("vpd-type")]
    [InlineData("replacement")]
    [InlineData("mixed")]
    [InlineData("native-write")]
    [InlineData("raw-admission")]
    [InlineData("canonical")]
    [InlineData("backend")]
    public async Task ChangedPolicyOnSameRetainedGroupRefusesProjectionAndDispatch(string change)
    {
        using var route = new Route(vpdType: change == "vpd-type" ? 2u : null);
        Assert.True(Assert.Single(await route.Backend.GetMountStateAsync(default)).SnapshotRecoverySupported);
        var qualification = route.Options.RawSnapshotHardwareQualification!;
        switch (change)
        {
            case "removed": route.Options.RawSnapshotHardwareQualification = null; break;
            case "bus": qualification.BusType = 6; break;
            case "vendor": qualification.Vendor = "Other Devices"; break;
            case "product": qualification.Product = "Other Test Unit"; break;
            case "serial": qualification.QualifiedSerial = "TEST-UNIT-C8D2"; break;
            case "serial-case": qualification.QualifiedSerial = "test-unit-a7b9"; break;
            case "scheme": qualification.Scheme = RawSnapshotHardwareQualificationScheme.QualifiedDeviceVpd;
                qualification.QualifiedSerial = null; qualification.QualifiedVpdType = 2; break;
            case "vpd-type": qualification.QualifiedVpdType = 3; break;
            case "replacement": route.Options.RawSnapshotHardwareQualification = RawSnapshotLaunchTests.TestQualification();
                route.Options.RawSnapshotHardwareQualification.Product = "Replacement Test Unit"; break;
            case "mixed": qualification.QualifiedVpdType = 2; break;
            case "native-write": route.Options.EnableNativeWrite = false; break;
            case "raw-admission": route.Options.NativeWriteAllowRawPhysicalDevices = false; break;
            case "canonical": route.Options.NativeWriteRequireCanonicalCommit = false; break;
            case "backend": route.Options.WriteBackendMode = "Overlay"; break;
        }
        var mount = Assert.Single(await route.Backend.GetMountStateAsync(default));
        Assert.False(mount.SnapshotInventorySupported);
        Assert.False(mount.SnapshotMutationSupported);
        Assert.False(mount.SnapshotRecoverySupported);
        foreach (var action in new[] { SnapshotControlAction.Create, SnapshotControlAction.Recover })
        {
            Assert.False((await route.Send(action, action == SnapshotControlAction.Create ? ["blocked"] : null)).Success);
            Assert.False(File.Exists(route.Control));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData(2u)]
    [InlineData(3u)]
    public async Task EqualPrivateConfigReplacementPreservesRetainedQualification(uint? vpdType)
    {
        using var route = new Route(debt: true, vpdType: vpdType);
        route.Options.RawSnapshotHardwareQualification = JsonSerializer.Deserialize<RawSnapshotHardwareQualification>(
            JsonSerializer.Serialize(route.Options.RawSnapshotHardwareQualification));
        Assert.True(Assert.Single(await route.Backend.GetMountStateAsync(default)).SnapshotRecoverySupported);
        var pending = route.Send(SnapshotControlAction.Recover);
        var lines = await route.Request(pending);
        await route.Reply(lines);
        Assert.True((await pending).Success);
    }

    // Synthetic managed contract only. No native host, mount, device lease, or recovery is created.
    private sealed class Route : IDisposable
    {
        private const BindingFlags Flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        private readonly DTempDirectory _temp = DTempDirectory.Create("raw-snapshot-contract");
        private readonly Process _process = Process.GetCurrentProcess();
        private readonly IDictionary _groups, _mounts;
        public NativeApfsBackend Backend { get; }
        public ServiceHostOptions Options { get; }
        public string Control { get; }
        private string Token { get; } = new('b', 64);

        public Route(string? failure = null, bool debt = false, bool retainedInventory = false, uint? vpdType = null)
        {
            Control = Path.Combine(_temp.Path, "control");
            var statusPath = Path.Combine(_temp.Path, "status.json");
            object Row(ulong oid) => new
            {
                objectId = oid.ToString(), canonicalId = $"apfs-vol:{Container}:{oid}", mounted = true, ready = true,
                writable = !debt || oid != 101, recoveryActive = debt && oid == 101, writeDegraded = debt && oid == 101,
                recoveryReason = debt && oid == 101 ? "SnapshotRecoveryExplicitControlRequired" : "",
                recoveryIdentity = failure == "wrong-peer-identity" && oid == 102 ? "replacement" : $"rec-{oid}",
                snapshotInventorySupported = !debt && failure != "all-native-refused",
                snapshotMutationSupported = !debt && failure != "all-native-refused",
                snapshotRecoverySupported = failure is not ("native-refused" or "all-native-refused"),
                volumeVerificationSupported = !debt,
                volumeVerificationScope = debt ? null : new { sourceIdentity = Scope.SourceIdentity, sourceKind = Scope.SourceKind,
                    containerUuid = Container, volumeUuid = oid == 101 ? Volume : new string('c', 32), volumeOid = oid.ToString(),
                    checkpointXid = "91", storeOffsetBytes = "8192", storeSizeBytes = "134217728" },
                dirtyTransactionCount = 0, inFlightMutationCallbacks = 0, closeCommitDeferred = false,
                deferredCommitRequested = false, deferredCommitInFlight = false, shutdownDrainActive = false,
                walAcceptedSequence = debt && oid == 101 ? "2" : "1", walApfsDurableSequence = "1", walCleanupSequence = "1",
                walRecoveryStateValid = true, payloadSpoolDirtyRangeCount = "0", payloadSpoolIndexDirty = false,
                payloadSpoolRecoveryRequired = false
            };
            File.WriteAllText(statusPath, JsonSerializer.Serialize(new { containerUuid = Container, ownerPid = _process.Id,
                ownerStartFileTimeUtc = _process.StartTime.ToUniversalTime().ToFileTimeUtc() + (failure == "owner-start" ? 1 : 0),
                leaseHeld = true, checkpointXid = "91", recoveryRequired = false, recoveryVolumeObjectId = (string?)null,
                recoveryReason = "", volumes = failure == "missing-peer" ? new[] { Row(101) } : new[] { Row(101), Row(102) } }));
            if (failure == "stale") File.SetLastWriteTimeUtc(statusPath, DateTime.UtcNow.AddMinutes(-2));
            Options = new ServiceHostOptions { EnableRawSnapshots = failure != "option-disabled",
                EnableNativeWrite = failure != "native-write-disabled", NativeWriteAllowRawPhysicalDevices = failure != "raw-disabled",
                NativeWriteRequireCanonicalCommit = failure != "noncanonical", WriteBackendMode = failure == "overlay" ? "Overlay" : "Native",
                EnableRetainedPhysicalSnapshotInventory = retainedInventory,
                RawSnapshotHardwareQualification = failure == "missing-qualification" ? null : RawSnapshotLaunchTests.TestQualification() };
            if (vpdType is not null)
            {
                Options.RawSnapshotHardwareQualification!.Scheme = RawSnapshotHardwareQualificationScheme.QualifiedDeviceVpd;
                Options.RawSnapshotHardwareQualification.QualifiedSerial = null;
                Options.RawSnapshotHardwareQualification.QualifiedVpdType = vpdType;
            }
            Backend = new(Options);
            var hostType = typeof(NativeApfsBackend).GetNestedType("HostProcessState", BindingFlags.NonPublic)!;
            var owner = hostType.GetConstructors(Flags).Single(c => c.GetParameters().Length == 8).Invoke(
                [_process, null, null, "", "", statusPath, MountAccessMode.ReadWrite, "Native"]);
            hostType.GetProperty("ContainerControlFilePath")!.SetValue(owner, Control);
            hostType.GetProperty("ContainerControlToken")!.SetValue(owner, failure == "credential-missing" ? "" : Token);
            hostType.GetProperty("RawSnapshotsEnabled")!.SetValue(owner, failure != "not-launched");
            hostType.GetProperty("RawSnapshotQualification")!.SetValue(owner, failure == "missing-retained-qualification" ? null :
                NativeRawSnapshotLaunch.CaptureQualification(Options.RawSnapshotHardwareQualification));
            var groupType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupState", BindingFlags.NonPublic)!;
            var group = groupType.GetConstructors(Flags).Single().Invoke([Container, @"\\.\PhysicalDrive2", 8192UL,
                failure == "manifest-missing" ? "" : Path.Combine(_temp.Path, "retained.container-manifest.json"), owner, true]);
            var memberType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupMember", BindingFlags.NonPublic)!;
            var members = (IDictionary)groupType.GetProperty("Members")!.GetValue(group)!;
            foreach (var oid in new[] { 101UL, 102UL })
            {
                var point = oid == 101 ? "R:\\" : "S:\\";
                members[point] = memberType.GetConstructors(Flags).Single(c => c.GetParameters().Length == 8).Invoke(
                    [$"apfs-vol:{Container}:{oid}", point, oid, failure != "readonly-peer" || oid != 102, $"rec-{oid}",
                        failure != "not-enrolled-peer" || oid != 102, failure != "detached-peer" || oid != 102, DateTime.UtcNow]);
            }
            _groups = (IDictionary)typeof(NativeApfsBackend).GetField("_containerGroups", Flags)!.GetValue(Backend)!;
            _groups[Container] = group;
            _mounts = (IDictionary)typeof(NativeApfsBackend).GetField("_mounts", Flags)!.GetValue(Backend)!;
            _mounts["R:\\"] = new MountedVolumeState($"apfs-vol:{Container}:101", "R:\\", MountAccessMode.ReadWrite,
                DeviceId: @"\\.\PhysicalDrive2", RecoveryIdentity: "rec-101", CatalogContainerUuid: Container,
                CatalogVolumeObjectId: 101, CatalogVolumeUuid: Volume);
        }

        public Task<SnapshotControlResult> Send(SnapshotControlAction action, IReadOnlyList<string>? extras = null)
            => Backend.SendSnapshotControlAsync(Container, 101, action, extras, default);

        public async Task<string[]> Request(Task<SnapshotControlResult> pending)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!pending.IsCompleted && !File.Exists(Control)) await Task.Delay(5, timeout.Token);
            Assert.True(File.Exists(Control), pending.IsCompleted ? (await pending).Code : "No request");
            var lines = await File.ReadAllLinesAsync(Control, timeout.Token);
            Assert.Equal(Token, lines[2]);
            Assert.Equal("101", lines[4]);
            return lines;
        }

        public async Task Reply(string[] lines, LiveSnapshotInventory? inventory = null)
        {
            var body = inventory is null ? (lines[3] == "snapshot-create" ? "SnapshotCreated\n" : "SnapshotRecovered\n") :
                $"SnapshotInventory\nsnapshot-inventory-json/1\n{inventory.ToJson().GetRawText()}\n";
            await File.WriteAllTextAsync(Control + ".tmp", $"APFS-CONTROL/1\n{lines[1]}\nok\n{body}");
            File.Move(Control + ".tmp", Control + ".response");
        }

        public void Dispose() { _groups.Clear(); _mounts.Clear(); Backend.Dispose(); _process.Dispose(); _temp.Dispose(); }
    }
}
