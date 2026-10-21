using System.Collections;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

[Collection("ManagementQuotaEndpointEnvironment")]
public sealed class ManagementKeeperEndpointTests
{
    [Fact]
    public void ProductionBackendExposesQuotaEndpoint()
        => Assert.True(typeof(IManagementQuotaKeeper).IsAssignableFrom(typeof(NativeApfsBackend)),
        "The actual NativeApfsBackend must expose IManagementQuotaKeeper.");

    [Theory]
    [InlineData("disabled", ManagementKeeperCodes.Refused)]
    [InlineData("root", ManagementKeeperCodes.Refused)]
    [InlineData("raw", ManagementKeeperCodes.InvalidRequest)]
    [InlineData("ownership", ManagementKeeperCodes.Refused)]
    public async Task ActualEndpointRefusesBeforeNativeContactAndPreservesFiles(string variant, string code)
    {
        using var fixture = new Fixture(register: false);
        using var environment = new Roots(fixture);
        var runner = new ScriptRunner();
        using var backend = fixture.Backend(runner, variant != "disabled");
        var request = fixture.Request;
        if (variant == "root") request = request with { JournalRoot = fixture.Spool };
        if (variant == "raw") request = request with { ImagePath = @"\\.\PhysicalDrive9999" };
        var before = fixture.Digests();
        var result = await ((IManagementQuotaKeeper)backend).SetQuotaReserveAsync(request, default);
        Assert.False(result.Committed);
        Assert.Equal(code, result.Code);
        Assert.Contains(variant switch {
            "disabled" => "ImageManagementMutationsDisabled", "root" => "ManagementQuotaStableRootMismatch",
            "ownership" => "OrdinaryImageOriginalLaunchOwnershipMissing", _ => "local" }, result.Detail!, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(runner.Arguments);
        Assert.Equal(before, fixture.Digests());
    }

    [Fact]
    public async Task EndpointCancellationAndDisposedLifecycleCannotReachNativeTransport()
    {
        using var fixture = new Fixture(register: false);
        var runner = new ScriptRunner();
        var backend = fixture.Backend(runner);
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => backend.SetQuotaReserveAsync(fixture.Request, cancellation.Token));
        backend.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => backend.SetQuotaReserveAsync(fixture.Request, default));
        Assert.Empty(runner.Arguments);
    }

    [Theory]
    [InlineData("_gate")]
    [InlineData("_discoveryGate")]
    public async Task EndpointWaitsForMountOrDiscoveryAdmissionAndReleasesAfterRefusal(string lockName)
    {
        using var fixture = new Fixture(register: false);
        using var environment = new Roots(fixture);
        var runner = new ScriptRunner();
        using var backend = fixture.Backend(runner);
        var gate = (SemaphoreSlim)Field(lockName).GetValue(backend)!;
        await gate.WaitAsync();
        Task<ManagementKeeperQuotaResult> pending;
        try
        {
            pending = backend.SetQuotaReserveAsync(fixture.Request, default);
            Assert.False(pending.IsCompleted);
            Assert.Empty(runner.Arguments);
        }
        finally { gate.Release(); }
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(ManagementKeeperCodes.Refused, result.Code);
        Assert.Contains("OrdinaryImageOriginalLaunchOwnershipMissing", result.Detail!);
        Assert.True(await gate.WaitAsync(TimeSpan.FromSeconds(1))); gate.Release();
        Assert.Empty(runner.Arguments);
    }

    [Theory]
    [InlineData("_hosts")]
    [InlineData("_retainedStartupHosts")]
    [InlineData("_containerGroups")]
    [InlineData("_mounts")]
    public async Task ActualEndpointFencesEveryOwnerIncludingPoisonedContainer(string field)
    {
        using var fixture = new Fixture(register: false);
        using var environment = new Roots(fixture);
        var runner = new ScriptRunner();
        using var backend = fixture.Backend(runner);
        var owners = (IDictionary)Field(field).GetValue(backend)!;
        using var process = Process.GetCurrentProcess();
        var hostType = typeof(NativeApfsBackend).GetNestedType("HostProcessState", BindingFlags.NonPublic)!;
        var host = hostType.GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic).Single(c => c.GetParameters().Length == 5)
            .Invoke([process, string.Empty, string.Empty, MountAccessMode.ReadOnly, null]);
        object owner = host;
        if (field == "_containerGroups")
        {
            var groupType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupState", BindingFlags.NonPublic)!;
            owner = Activator.CreateInstance(groupType, Fixture.Container, fixture.Image, 0UL, string.Empty, host, false)!;
            groupType.GetMethod("Poison")!.Invoke(owner, ["test retained poison"]);
        }
        if (field == "_mounts") owner = new MountedVolumeState("retained", fixture.Temp.Path, MountAccessMode.ReadOnly);
        owners.Add("synthetic-owned-test-entry", owner);
        try
        {
            var result = await backend.SetQuotaReserveAsync(fixture.Request, default);
            Assert.Equal(ManagementKeeperCodes.Refused, result.Code);
            Assert.Equal("ManagementQuotaOwnerStillRetained", result.Detail);
            Assert.True(owners.Contains("synthetic-owned-test-entry"));
            Assert.Empty(runner.Arguments);
        }
        finally { owners.Remove("synthetic-owned-test-entry"); }
    }

    [Fact]
    public void FreshOriginalOwnershipCannotMoveRootsOrLoseLaunchCensus()
    {
        using var fixture = new Fixture();
        var record = NativeApfsBackend.RequireManagementQuotaOwnership(fixture.Request, fixture.Root, fixture.Spool, fixture.Recovery);
        Assert.Equal(fixture.Source, record.CopiedFrom);
        Assert.Equal(2, record.LaunchBindings.Count);
        Assert.Throws<IOException>(() => NativeApfsBackend.RequireManagementQuotaOwnership(fixture.Request, fixture.Spool, fixture.Spool, fixture.Recovery));
        Assert.Throws<IOException>(() => NativeApfsBackend.RequireManagementQuotaOwnership(fixture.Request, fixture.Root, fixture.Root, fixture.Recovery));
        Assert.Throws<IOException>(() => NativeApfsBackend.RequireManagementQuotaOwnership(fixture.Request, fixture.Root, fixture.Spool, fixture.Root));
        using var missing = new Fixture(register: false);
        Assert.Throws<IOException>(() => NativeApfsBackend.RequireManagementQuotaOwnership(missing.Request, missing.Root, missing.Spool, missing.Recovery));
        var before = fixture.Digests();
        var missingWal = record.LaunchBindings[1].Wal;
        File.Delete(missingWal);
        Assert.Throws<IOException>(() => NativeOrdinaryImageOwnership.RequireCensus(fixture.Root, fixture.Image, "0", fixture.Spool,
            fixture.Recovery, Fixture.Container, fixture.Observation.Volumes));
        Assert.False(File.Exists(missingWal));
        Assert.Equal(before.Where(d => !d.StartsWith(missingWal + "=", StringComparison.Ordinal)), fixture.Digests());
    }

    [Fact]
    public void ScopeAndObservationBindCurrentWholeImageAndAllSiblingIdentities()
    {
        using var fixture = new Fixture();
        var scope = NativeApfsBackend.BindManagementQuotaScope(fixture.Request, fixture.Inventory);
        Assert.Equal(fixture.Image, scope.ImagePath);
        Assert.Equal("2097152", scope.StoreSizeBytes);
        var wals = NativeApfsBackend.BindManagementQuotaObservation(fixture.Request, scope, fixture.Observation);
        Assert.Equal(fixture.Wallets, wals);
        foreach (var bad in new[] {
            fixture.Request with { PreimageXid = "8" }, fixture.Request with { VolumeUuid = Fixture.Peer },
            fixture.Request with { ContainerUuid = Fixture.Peer }, fixture.Request with { VolumeObjectId = "103" },
            fixture.Request with { SiblingObjectIds = [] }, fixture.Request with { SiblingObjectIds = ["103"] } })
            Assert.Throws<IOException>(() => NativeApfsBackend.BindManagementQuotaScope(bad, fixture.Inventory));
        foreach (var bad in new[] {
            fixture.Observation with { CheckpointXid = "8" }, fixture.Observation with { ContainerUuid = Fixture.Peer },
            fixture.Observation with { SourceIdentity = new string('0', 80) }, fixture.Observation with { BlockBytes = "0" },
            fixture.Observation with { StoreSizeBytes = "1048576" }, fixture.Observation with { OffsetBytes = "4096" },
            fixture.Observation with { Volumes = [fixture.Observation.Volumes[0]] },
            fixture.Observation with { Volumes = [fixture.Observation.Volumes[0], fixture.Observation.Volumes[1] with { Oid = "103" }] } })
            Assert.ThrowsAny<IOException>(() => NativeApfsBackend.BindManagementQuotaObservation(fixture.Request, scope, bad));
    }

    [Theory]
    [InlineData("encrypted")]
    [InlineData("readonly")]
    [InlineData("unknown")]
    [InlineData("fusion")]
    [InlineData("offset")]
    [InlineData("partial")]
    public void ScopeRefusesUnadmittedProfilesAndPartitionWindows(string variant)
    {
        using var fixture = new Fixture();
        var inventory = fixture.Inventory;
        var snapshot = inventory.Topology!.Snapshot;
        var row = inventory.Volumes[0];
        if (variant == "encrypted") row = row with { IsEncrypted = true };
        if (variant == "readonly") row = row with { CatalogDecision = ApfsCapabilityDecision.ReadOnlyFeature };
        if (variant == "unknown") row = row with { CatalogAutoMountAllowed = false, CatalogReasons = ["UnknownIncompatibleFeature"] };
        if (variant == "fusion") snapshot = snapshot with { Containers = [snapshot.Containers[0] with { Fusion = true }] };
        if (variant == "offset") snapshot = snapshot with { Stores = [snapshot.Stores[0] with { OffsetBytes = 4096, SizeBytes = 2093056 }] };
        if (variant == "partial") snapshot = snapshot with { Stores = [snapshot.Stores[0] with { SizeBytes = 1048576 }] };
        inventory = inventory with { Volumes = [row, inventory.Volumes[1]], Topology = inventory.Topology with { Snapshot = snapshot } };
        Assert.Throws<IOException>(() => NativeApfsBackend.BindManagementQuotaScope(fixture.Request, inventory));
    }

    [Fact]
    public void OriginalMarkersAreMandatoryHeldAndBoundToCleanCheckpoint()
    {
        using var fixture = new Fixture();
        using (NativeApfsBackend.AcquireManagementQuotaDisposition(fixture.Bound, fixture.Bindings, fixture.Recovery, fixture.Root))
        {
            foreach (var path in fixture.Markers)
                Assert.ThrowsAny<IOException>(() => new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite).Dispose());
        }
        foreach (var path in fixture.Markers)
            using (var writable = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.Read)) Assert.True(writable.CanWrite);
        var missing = fixture.Markers[1]; File.Delete(missing);
        var unavailable = Assert.Throws<IOException>(() => NativeApfsBackend.AcquireManagementQuotaDisposition(fixture.Bound, fixture.Bindings, fixture.Recovery, fixture.Root));
        Assert.Equal("ManagementQuotaOriginalMarkerMissingOrInvalid", unavailable.Message);
        Assert.IsType<ArgumentException>(unavailable.InnerException);
        Assert.False(File.Exists(missing));
        File.WriteAllText(missing, "dirty=0\nlastCommitXid=8\n");
        Assert.Throws<IOException>(() => NativeApfsBackend.AcquireManagementQuotaDisposition(fixture.Bound, fixture.Bindings, fixture.Recovery, fixture.Root));
        File.WriteAllText(missing, "dirty=1\nlastCommitXid=7\n");
        Assert.Throws<IOException>(() => NativeApfsBackend.AcquireManagementQuotaDisposition(fixture.Bound, fixture.Bindings, fixture.Recovery, fixture.Root));
        File.WriteAllText(missing, "dirty=0\nlastCommitXid=7\n");
        var unexpected = Path.Combine(fixture.Spool, "unknown", "payload.bin"); Directory.CreateDirectory(Path.GetDirectoryName(unexpected)!);
        File.WriteAllText(unexpected, "preserve unclassified spool debt");
        Assert.Throws<IOException>(() => NativeApfsBackend.AcquireManagementQuotaDisposition(fixture.Bound, fixture.Bindings, fixture.Recovery, fixture.Root));
        Assert.Equal("preserve unclassified spool debt", File.ReadAllText(unexpected));
        Assert.Equal("dirty=0\nlastCommitXid=7\n", File.ReadAllText(missing));
    }

    [Fact]
    public void OriginalWalTransportCommitsExactTwoLineReportWithoutInventingJournals()
    {
        using var fixture = new Fixture();
        var before = fixture.Digests();
        var runner = new ScriptRunner(Ok(Plan()), Ok(Plan() + "\n" + Durable));
        var result = fixture.Transport(runner).SetQuotaReserveWithOriginalWals(fixture.Request, fixture.Wallets, 4096, default);
        Assert.True(result.Committed); Assert.Equal(8UL, result.CommittedXid);
        Assert.Equal(2, runner.Arguments.Count);
        AssertVectors(fixture, runner, ["256", "256"], ["128", "128"]);
        Assert.Contains("--commit", runner.Arguments[1]);
        Assert.Equal(new string('c', 64), Value(runner.Arguments[1], "--confirm"));
        Assert.False(Directory.Exists(NativeApfsVolumeQuota.JournalDirFor(fixture.Root, fixture.Image)));
        Assert.Equal(before, fixture.Digests());
    }

    [Fact]
    public void OriginalWalRecoveryBindsActualLimitsRatherThanZeroPreview()
    {
        using var fixture = new Fixture();
        var before = fixture.Digests();
        var runner = new ScriptRunner(new(1, string.Empty, "REFUSED conflicting accepted session\n"), Ok(Plan()), Ok(Plan() + "\n" + Durable));
        var result = fixture.Transport(runner).SetQuotaReserveWithOriginalWals(fixture.Request, fixture.Wallets, 4096, default);
        Assert.False(result.Committed); Assert.Equal(ManagementKeeperCodes.StalePreimage, result.Code);
        AssertVectors(fixture, runner, ["256", "256", "256"], ["128", "128", "128"]);
        Assert.DoesNotContain("--recover", runner.Arguments[0]);
        Assert.Contains("--recover", runner.Arguments[1]); Assert.Contains("--recover", runner.Arguments[2]);
        Assert.Equal(before, fixture.Digests());
    }

    [Theory]
    [InlineData("preview-write")]
    [InlineData("backward-generation")]
    [InlineData("source-replacement")]
    public void OriginalRecoveryCannotHidePreviewMutationOrFalseDurability(string variant)
    {
        using var fixture = new Fixture();
        var durable = variant == "backward-generation" ? Durable.Replace("\":8", "\":6", StringComparison.Ordinal) : Durable;
        var runner = new ScriptRunner(new(1, string.Empty, "REFUSED conflicting accepted session\n"), Ok(Plan()), Ok(Plan() + "\n" + durable));
        runner.AfterCall = count => {
            if (variant == "preview-write" && count == 2) File.WriteAllBytes(fixture.Image, new byte[1048576]);
            if (variant == "source-replacement" && count == 3)
            { File.Move(fixture.Image, fixture.Image + ".original"); File.Copy(fixture.Image + ".original", fixture.Image); }
        };
        if (variant == "preview-write")
        {
            Assert.Throws<InvalidDataException>(() => fixture.Transport(runner).SetQuotaReserveWithOriginalWals(fixture.Request, fixture.Wallets, 4096, default));
            Assert.Equal(2, runner.Arguments.Count);
            Assert.DoesNotContain(runner.Arguments, args => args.Contains("--commit"));
        }
        else
        {
            var result = fixture.Transport(runner).SetQuotaReserveWithOriginalWals(fixture.Request, fixture.Wallets, 4096, default);
            Assert.False(result.Committed); Assert.Equal(ManagementKeeperCodes.Refused, result.Code);
            Assert.Contains("source identity", result.Detail!);
        }
        foreach (var wal in fixture.Wallets) Assert.Equal("managed transport path fixture only", File.ReadAllText(wal.Path));
    }

    [Fact]
    public void OriginalRecoveryAllowsCleanupAtAlreadyPublishedGenerationAndRequiresReobserve()
    {
        using var fixture = new Fixture();
        var durable = Durable.Replace("\":8", "\":7", StringComparison.Ordinal);
        var runner = new ScriptRunner(new(1, string.Empty, "REFUSED conflicting accepted session\n"), Ok(Plan()), Ok(Plan() + "\n" + durable));
        var before = fixture.Digests();
        var result = fixture.Transport(runner).SetQuotaReserveWithOriginalWals(fixture.Request, fixture.Wallets, 4096, default);
        Assert.False(result.Committed); Assert.Equal(ManagementKeeperCodes.StalePreimage, result.Code);
        Assert.Equal(3, runner.Arguments.Count); Assert.Equal(before, fixture.Digests());
    }

    [Fact]
    public void OriginalWalAdapterRejectsMissingAliasedOrWrongMembersAndConfiguredRoot()
    {
        using var fixture = new Fixture();
        var runner = new ScriptRunner(); var keeper = fixture.Transport(runner);
        foreach (var bad in new IReadOnlyList<(ulong Oid, string Path)>[] {
            [fixture.Wallets[0]], [fixture.Wallets[0], (103, fixture.Wallets[1].Path)],
            [fixture.Wallets[0], (102, fixture.Wallets[0].Path)], [fixture.Wallets[0], fixture.Wallets[0]] })
            Assert.Throws<InvalidDataException>(() => keeper.SetQuotaReserveWithOriginalWals(fixture.Request, bad, 4096, default));
        Assert.Throws<InvalidDataException>(() => keeper.SetQuotaReserveWithOriginalWals(fixture.Request with { JournalRoot = fixture.Spool }, fixture.Wallets, 4096, default));
        Assert.Throws<InvalidDataException>(() => keeper.SetQuotaReserveWithOriginalWals(fixture.Request, fixture.Wallets, 0, default));
        File.Delete(fixture.Wallets[1].Path);
        Assert.Throws<ArgumentException>(() => keeper.SetQuotaReserveWithOriginalWals(fixture.Request, fixture.Wallets, 4096, default));
        Assert.Empty(runner.Arguments);
        Assert.False(File.Exists(fixture.Wallets[1].Path));
    }

    [Theory]
    [InlineData("bind-block")]
    [InlineData("census")]
    [InlineData("duplicate-census")]
    [InlineData("dry-write")]
    public void OriginalTransportRefusesDriftBeforeCommit(string variant)
    {
        using var fixture = new Fixture();
        var runner = new ScriptRunner(Ok(Plan(block: variant == "bind-block" ? "8192" : "4096", oids: variant switch {
                "census" => "101,103", "duplicate-census" => "101,101", _ => "101,102" })));
        if (variant == "dry-write") runner.AfterCall = count => { if (count == 1) File.WriteAllBytes(fixture.Image, new byte[1048576]); };
        var before = fixture.Digests();
        if (variant is "census" or "duplicate-census")
        {
            var result = fixture.Transport(runner).SetQuotaReserveWithOriginalWals(fixture.Request, fixture.Wallets, 4096, default);
            Assert.False(result.Committed); Assert.Equal(ManagementKeeperCodes.Refused, result.Code);
        }
        else Assert.Throws<InvalidDataException>(() => fixture.Transport(runner).SetQuotaReserveWithOriginalWals(fixture.Request, fixture.Wallets, 4096, default));
        Assert.DoesNotContain(runner.Arguments, args => args.Contains("--commit"));
        Assert.Single(runner.Arguments);
        if (variant != "dry-write") Assert.Equal(before, fixture.Digests());
        else Assert.Equal(before.Where(d => !d.StartsWith(fixture.Image + "=", StringComparison.Ordinal)),
            fixture.Digests().Where(d => !d.StartsWith(fixture.Image + "=", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("no-echo")]
    [InlineData("token")]
    [InlineData("block")]
    [InlineData("limits")]
    [InlineData("extra-line")]
    [InlineData("duplicate-field")]
    public void OriginalCommitRequiresExactConfirmedPlanAndDurableShape(string variant)
    {
        using var fixture = new Fixture();
        var plan = NativeApfsVolumeQuota.ParsePlan(Plan(), fixture.TransportRequest, "256", "128");
        var echo = variant switch {
            "token" => Plan(token: 'd'), "block" => Plan(block: "8192"), "limits" => Plan("257", "128"),
            "duplicate-field" => Plan().Replace("\"operation\":20", "\"operation\":20,\"operation\":20", StringComparison.Ordinal), _ => Plan() };
        var wire = variant == "no-echo" ? Durable : echo + "\n" + Durable;
        if (variant == "extra-line") wire += "\n" + Durable;
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeQuota.ParseCommitOutput(wire, fixture.TransportRequest, plan, requirePlanEcho: true));
        Assert.Equal(8UL, NativeApfsVolumeQuota.ParseCommitOutput(Plan() + "\n" + Durable, fixture.TransportRequest, plan, true));
        Assert.Equal(8UL, NativeApfsVolumeQuota.ParseCommitOutput(Durable, fixture.TransportRequest, plan));
    }

    private static FieldInfo Field(string name) => typeof(NativeApfsBackend).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!;
    private const string Durable = "{\"durable\":true,\"checkpointXid\":8,\"cleanupSequence\":5}";
    private static ObserverRunResult Ok(string output) => new(0, output + "\n", string.Empty);
    private static string Plan(string quota = "256", string reserve = "128", string block = "4096", char token = 'c', string oids = "101,102") =>
        $"{{\"operation\":20,\"xid\":7,\"oid\":101,\"quotaBlocks\":{quota},\"reserveBlocks\":{reserve},\"blockBytes\":{block}," +
        $"\"freeBlocks\":1000000,\"confirm\":\"{new string(token, 64)}\",\"volumes\":[" +
        string.Join(',', oids.Split(',').Select(oid => $"{{\"oid\":{oid},\"charged\":10,\"quota\":0,\"reserve\":0}}")) + "]}";
    private static string Value(IReadOnlyList<string> args, string flag) => args[args.ToList().IndexOf(flag) + 1];
    private static void AssertVectors(Fixture fixture, ScriptRunner runner, string[] quotas, string[] reserves)
    {
        for (var call = 0; call < runner.Arguments.Count; ++call)
        {
            var args = runner.Arguments[call];
            Assert.Equal(fixture.Image, Value(args, "--image")); Assert.Equal("0", Value(args, "--offset"));
            Assert.Equal(Fixture.Container, Value(args, "--container")); Assert.Equal(Fixture.Volume, Value(args, "--volume"));
            Assert.Equal("101", Value(args, "--oid")); Assert.Equal("7", Value(args, "--xid"));
            Assert.Equal(quotas[call], Value(args, "--quota-blocks")); Assert.Equal(reserves[call], Value(args, "--reserve-blocks"));
            Assert.Equal(fixture.Wallets.Select(w => $"{w.Oid}={w.Path}"), args.Select((value, at) => (value, at))
                .Where(p => p.value == "--wal").Select(p => args[p.at + 1]));
        }
    }

    private sealed class ScriptRunner(params ObserverRunResult[] results) : IObserverRunner
    {
        private readonly Queue<ObserverRunResult> queue = new(results);
        internal List<IReadOnlyList<string>> Arguments { get; } = [];
        internal Action<int>? AfterCall;
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        {
            Arguments.Add(arguments.ToArray()); AfterCall?.Invoke(Arguments.Count);
            return queue.Count == 0 ? throw new InvalidOperationException("Unexpected native contact in managed-only test.") : queue.Dequeue();
        }
    }

    private sealed class Roots : IDisposable
    {
        private readonly string? spool = Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT");
        private readonly string? recovery = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT");
        internal Roots(Fixture fixture)
        { Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", fixture.Spool); Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", fixture.Recovery); }
        public void Dispose()
        { Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", spool); Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", recovery); }
    }

    private sealed class Fixture : IDisposable
    {
        internal const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Volume = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Peer = "cccccccccccccccccccccccccccccccc";
        internal DTempDirectory Temp { get; } = DTempDirectory.Create("management-quota-endpoint");
        internal string Root, Spool, Recovery, Source, Image, Tool;
        internal DeviceInventory Inventory;
        internal ManagementKeeperQuotaRequest Request;
        internal VolumeTopologyObservation Observation;
        internal IReadOnlyList<NativeOrdinaryImageOwnership.Binding> Bindings = [];
        internal IReadOnlyList<(ulong Oid, string Path)> Wallets;
        internal string[] Markers = [];
        internal ApfsVolumeQuotaRequest TransportRequest => new(Image, Container, Volume, "101", "7", "1048576", "524288", ["102"], Root);
        internal VolumeTopologyRequest Bound => new("quota", Image, Root, "0", Container, Volume, "101", "7", Observation.SourceIdentity, Spool, Observation.Volumes);
        internal Fixture(bool register = true)
        {
            Root = Path.Combine(Temp.Path, "journals"); Spool = Path.Combine(Temp.Path, "spool"); Recovery = Path.Combine(Temp.Path, "recovery");
            foreach (var root in new[] { Root, Spool, Recovery }) Directory.CreateDirectory(root);
            Source = Path.Combine(Temp.Path, "source.apfs"); Image = Path.Combine(Temp.Path, "image.apfs"); Tool = Path.Combine(Temp.Path, "VolumeQuotaReserveImageTool.exe");
            File.WriteAllBytes(Source, new byte[2097152]); File.WriteAllBytes(Tool, [0x4d, 0x5a]);
            if (register) NativeOrdinaryImageOwnership.RegisterFreshCopy(new(Source, Image), Root, Spool, Recovery);
            else File.Copy(Source, Image);
            var cid = ApfsTopology.BuildContainerId(Container); var disk = "apfs-disk:image"; var store = "apfs-store:image";
            var vids = new[] { ApfsTopology.BuildVolumeId(Container, 101), ApfsTopology.BuildVolumeId(Container, 102) };
            var uuids = new[] { Volume, Peer };
            var rows = vids.Select((vid, i) => new VolumeInfo(vid, Image, $"Volume{i}", true, SupportsNativeWrite: true,
                RecoveryIdentity: NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, Container, (ulong)(101 + i), true),
                CatalogVolumeId: vid, CatalogContainerUuid: Container, CatalogVolumeObjectId: (ulong)(101 + i), CatalogVolumeUuid: uuids[i],
                CatalogDecision: ApfsCapabilityDecision.Writable, CatalogReasons: [], CatalogAutoMountAllowed: true)).ToArray();
            var topology = new ApfsTopologySnapshot([new(disk, Image, null, 2097152)], [], [new(store, Container, "", cid, 0, 2097152, DiskId: disk)],
                [new(cid, Container, 4096, [store], vids, false, "7", [], [], [])],
                vids.Select((vid, i) => new ApfsVolumeRecord(vid, uuids[i], (101 + i).ToString(), cid, $"Volume{i}", true,
                    ["data"], 64, null, "sensitive", "none", false, [], [], [], "7", "7")).ToArray(), []);
            Inventory = new(new(Image, "Image", true), rows, new(1, Image, [disk], topology));
            if (register)
            {
                var start = new ProcessStartInfo("never-executed.exe"); start.Environment["APFSACCESS_SPOOL_ROOT"] = Spool;
                start.Environment["APFSACCESS_RECOVERY_ROOT"] = Recovery;
                Bindings = NativeOrdinaryImageOwnership.CaptureLaunch(start, Root, Image, "0", rows).LaunchBindings;
            }
            Wallets = rows.Select(v => (v.CatalogVolumeObjectId!.Value, NativeRecoveryStorage.CanonicalWal(Spool, v.RecoveryIdentity!))).ToArray();
            if (register)
            {
                foreach (var wal in Wallets) { Directory.CreateDirectory(Path.GetDirectoryName(wal.Path)!); File.WriteAllText(wal.Path, "managed transport path fixture only"); }
                Markers = rows.Select(v => NativeRecoveryStorage.CanonicalNativeMarker(Recovery, v.RecoveryIdentity!)).ToArray();
                foreach (var marker in Markers) File.WriteAllText(marker, "dirty=0\nlastCommitXid=7\n");
            }
            Request = new(Image, Container, Volume, "101", "7", "1048576", "524288", ["102"], Root);
            Observation = new(Image, "0", "2097152", NativeApfsVolumeManagement.SourceIdentity(Image, "0"), Container, "7", "4096", "103", Spool,
                rows.Select((v, i) => new VolumeTopologyWal((101 + i).ToString(), uuids[i], Wallets[i].Path)).ToArray());
        }
        internal NativeApfsBackend Backend(IObserverRunner runner, bool enabled = true) => new(new ServiceHostOptions {
            NativeAutoDiscoverPhysicalDrives = false, EnableImageManagementMutations = enabled, ManagementJournalRoot = Root },
            lifecycleTestHooks: null, observerRunner: runner, observerPathOverride: Path.Combine(Temp.Path, "absent-observer.exe"));
        internal NativeApfsVolumeQuota Transport(IObserverRunner runner) => new(runner, Tool, Root);
        internal string[] Digests() => Directory.GetFiles(Temp.Path, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal)
            .Select(path => path + "=" + Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)))).ToArray();
        public void Dispose() => Temp.Dispose();
    }
}

[CollectionDefinition("ManagementQuotaEndpointEnvironment", DisableParallelization = true)]
public sealed class ManagementQuotaEndpointEnvironmentCollection { }
