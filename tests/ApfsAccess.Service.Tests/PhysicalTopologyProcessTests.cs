using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    // Selected only by the private software gate. No default raw factory is invoked.
    [PhysicalTopologyProcessTheory]
    [InlineData("create", "apply")] [InlineData("delete", "apply")]
    [InlineData("create", "cancel")] [InlineData("delete", "cancel")]
    [InlineData("create", "recover")] [InlineData("delete", "recover")]
    public async Task PhysicalTopology_ProcessRoutePreservesAcceptedOriginal(string kind, string finish)
    {
        using var bridge = new PhysicalTopologyProcessBackend();
        var before = bridge.Hash(); var initial = bridge.Inventory(); var count = initial.Volumes.Count;
        var request = bridge.Plan(kind); VolumeTopologyRequest original; string token;
        using (var worker = bridge.Worker(true))
        {
            var executor = new AgentControlCommandExecutor(worker);
            var plan = await executor.ExecuteAsync(request, default); Assert.True(plan.Success, plan.Diagnostic);
            var saved = bridge.Intent(); original = saved.NativeRequest; token = saved.ConfirmationToken!;
            Assert.Equal(before, bridge.Hash()); Assert.NotNull(original.PhysicalBindingHex);
            Assert.Equal(VolumePhysicalBinding.Parse(original.PhysicalBindingHex!).Limit.ToString(CultureInfo.InvariantCulture),
                VolumeTopologyProfile.DeriveManagementScope(initial, initial.Volumes[0], kind).Scope!.StoreSizeBytes);
            Assert.Equal("1048576", original.OffsetBytes); Assert.Null(original.ImageOptions);
            Assert.All(original.SiblingWals, w => Assert.StartsWith(Path.Combine(bridge.Root, "spool"), w.Path));
            if (finish == "recover") bridge.Transport.Interrupt = true;
            var command = finish == "cancel" ? ApfsControlCommands.VolumeManagementCancel : ApfsControlCommands.VolumeManagementApply;
            var result = await executor.ExecuteAsync(bridge.Confirm(request, command, token), default);
            Assert.Equal(finish != "recover", result.Success);
            Assert.Equal(finish == "recover" ? "recovery-required" : finish == "cancel" ? "cancelled" : "committed", bridge.Intent().State);
        }
        if (finish == "recover")
        {
            // A new backend and worker must use the saved typed request, without mutation opt-ins.
            bridge.ReopenNative(false); bridge.Transport.Interrupt = false;
            using var restarted = bridge.Worker(false);
            await restarted.RefreshAsync(false, default);
            Assert.Equal("committed", bridge.Intent().State);
            Assert.Contains(bridge.Transport.Calls, c => c.Arguments.Contains("recover"));
        }
        Assert.Equal(JsonSerializer.Serialize(original), JsonSerializer.Serialize(bridge.Intent().NativeRequest));
        var after = bridge.Inventory();
        Assert.Equal(finish == "cancel" ? count : count + (kind == "create" ? 1 : -1), after.Volumes.Count);
        if (finish == "cancel") Assert.Equal(before, bridge.Hash());
        else Assert.NotEqual(before, bridge.Hash());
        Assert.Equal(0, bridge.MountCalls);
        Assert.All(bridge.Transport.Calls.Where(c => c.Tool == "VolumeManagementImage.exe"), call => {
            Assert.Contains("physical", call.Arguments); Assert.Contains(original.PhysicalBindingHex!, call.Arguments);
            var cleanup = call.Arguments.Contains("cancel") || call.Arguments.Contains("recover");
            Assert.Equal(!cleanup, call.Arguments.Contains("--physical-device"));
        });
        File.WriteAllText(Path.Combine(bridge.Root, "receipt.json"), JsonSerializer.Serialize(new {
            kind, finish, before, after = bridge.Hash(), countBefore = count, countAfter = after.Volumes.Count,
            original, state = bridge.Intent().State, bridge.MountCalls, calls = bridge.Transport.Calls,
            rawOperations = 0, transport = "private held regular-file factory; production observer and keeper entry points" }));
    }

    [PhysicalTopologyProcessTheory]
    [InlineData(true)]
    public async Task PhysicalTopology_ProcessRouteRefusesChangedQualificationAndScope(bool run)
    {
        Assert.True(run); using var bridge = new PhysicalTopologyProcessBackend(); var inventory = bridge.Inventory();
        var scope = VolumeTopologyProfile.DeriveManagementScope(inventory, inventory.Volumes[0], "create").Scope!;
        var before = bridge.Hash(); var observed = await bridge.ObserveVolumeTopologyAsync(scope, inventory, "create", default);
        Assert.Equal(2, observed.Volumes.Count);
        bridge.QualificationSerial = "OTHERDEVICE99"; bridge.ReopenNative(true);
        await Assert.ThrowsAsync<InvalidDataException>(() => bridge.ObserveVolumeTopologyAsync(scope, inventory, "create", default));
        bridge.QualificationSerial = "TOPOLOGYTEST42"; bridge.ReopenNative(true);
        await Assert.ThrowsAsync<InvalidDataException>(() => bridge.ObserveVolumeTopologyAsync(scope with { CheckpointXid = "8" }, inventory, "create", default));
        var changedInventory = inventory with { Volumes = inventory.Volumes.Take(1).ToArray() };
        await Assert.ThrowsAsync<InvalidDataException>(() => bridge.ObserveVolumeTopologyAsync(scope, changedInventory, "create", default));
        var r = new VolumeTopologyRequest("create", PhysicalTopologyProcessBackend.Device, bridge.Journal, observed.OffsetBytes,
            observed.ContainerUuid, Guid.NewGuid().ToString("N"), observed.NextOid, observed.CheckpointXid, observed.SourceIdentity,
            observed.SpoolRoot, observed.Volumes, "Refusal", "0", "0", false, PhysicalBindingHex: observed.PhysicalBindingHex);
        // The public backend must refuse even without a service intent authorizing this direct negative probe.
        var stale = await bridge.NativeNegative(r with { PreXid = "8" }); Assert.Equal("refused", stale.Outcome);
        var missing = await bridge.NativeNegative(r with { SiblingWals = observed.Volumes.Take(1).ToArray() }); Assert.Equal("refused", missing.Outcome);
        bridge.ReopenNative(false); var calls = bridge.Transport.Calls.Count;
        await Assert.ThrowsAsync<IOException>(() => bridge.ObserveVolumeTopologyAsync(scope, inventory, "create", default));
        Assert.Equal(calls, bridge.Transport.Calls.Count); Assert.Equal(before, bridge.Hash());
        Assert.All(Directory.GetFiles(Path.Combine(bridge.Root, "spool"), "write-ahead.wal", SearchOption.AllDirectories), p => Assert.Equal(0, new FileInfo(p).Length));
        File.WriteAllText(Path.Combine(bridge.Root, "refusal-receipt.json"), JsonSerializer.Serialize(new {
            before, after = bridge.Hash(), stale = stale.Error, missing = missing.Error, bridge.Transport.Calls, rawOperations = 0 }));
    }

    private sealed class PhysicalTopologyProcessBackend : IApfsBackend, IVerifyBackend, IVolumeTopologyBackend, IDisposable
    {
        internal const string Device = @"\\.\PhysicalDrive42";
        public string Root { get; } = Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT") ??
            throw new InvalidOperationException("Private D test root required."), "physical-process-" + Guid.NewGuid().ToString("N"));
        public string Journal => Path.Combine(Root, "journal");
        public PhysicalTopologyTransport Transport { get; }
        private NativeApfsBackend _native = null!;
        public string QualificationSerial = "TOPOLOGYTEST42";
        private readonly string? _oldSpool = Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT");
        private readonly string? _oldRecovery = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT");
        public int MountCalls;
        public PhysicalTopologyProcessBackend()
        {
            Assert.StartsWith(@"D:\", Root, StringComparison.OrdinalIgnoreCase);
            Directory.CreateDirectory(Root); Directory.CreateDirectory(Journal);
            Transport = new(Root); var setup = Transport.Direct("bridge-setup"); Assert.Equal(0, setup.ExitCode);
            Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", Path.Combine(Root, "spool"));
            Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", Path.Combine(Root, "recovery"));
            ReopenNative(true);
        }
        private ServiceHostOptions Options(bool enabled) => new() {
            ManagementJournalRoot = Journal, AutoMountEnabled = false, NativeAutoRemountOnReconnect = false,
            EnableNativeWrite = true, WriteBackendMode = "Native", NativeWriteAllowRawPhysicalDevices = true,
            NativeWriteStrictMode = true, NativeWriteRequireCanonicalCommit = true, EnableImageManagementMutations = enabled,
            EnablePhysicalVolumeManagement = enabled, EnableImageResizeFormat = false,
            RawSnapshotHardwareQualification = new() { Scheme = RawSnapshotHardwareQualificationScheme.QualifiedSerialTuple,
                BusType = 7, Vendor = "Fictional", Product = "Topology Surrogate", QualifiedSerial = QualificationSerial } };
        public void ReopenNative(bool enabled) { _native?.Dispose(); _native = new(Options(enabled), null, Transport); }
        public ApfsMountWorker Worker(bool enabled) => new(NullLogger<ApfsMountWorker>.Instance, this, new FixedMountPolicy(),
            new RuntimeStatusPublisher(), new FixedOptionsMonitor(Options(enabled)));
        public string Hash() => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(Root, "carrier.sparse"))));
        public VolumeManagementIntent Intent() { using var store = new VolumeManagementIntentStore(Journal); return Assert.Single(store.ReadAll()); }
        public DeviceInventory Inventory()
        {
            var wire = Transport.Direct("bridge-probe"); Assert.Equal(0, wire.ExitCode);
            using var doc = JsonDocument.Parse(wire.StandardOutput); var j = doc.RootElement;
            var container = j.GetProperty("containerUuid").GetString()!; var xid = j.GetProperty("xid").GetString()!;
            var binding = VolumePhysicalBinding.Parse(j.GetProperty("bindingHex").GetString()!);
            var cid = ApfsTopology.BuildContainerId(container); const string store = "apfs-store:private", disk = "apfs-disk:private";
            var volumes = j.GetProperty("volumes").EnumerateArray().Select(v => {
                var oid = ulong.Parse(v.GetProperty("oid").GetString()!, CultureInfo.InvariantCulture); var uuid = v.GetProperty("uuid").GetString()!;
                var id = ApfsTopology.BuildVolumeId(container, oid);
                return new VolumeInfo(id, Device, "Peer " + oid, true, SupportsNativeWrite: true,
                    RecoveryIdentity: NativeApfsBackend.BuildRecoveryIdentityFromComponents(binding.PartitionGuid, container, oid, false),
                    CatalogVolumeId: id, CatalogContainerUuid: container, CatalogVolumeUuid: uuid, CatalogVolumeObjectId: oid,
                    CatalogDecision: ApfsCapabilityDecision.Writable, CatalogReasons: [], CatalogAutoMountAllowed: true);
            }).ToArray();
            var topo = new ApfsTopologySnapshot([new(disk, Device, null, (long)binding.DiskBytes)], [],
                [new(store, container, "", cid, (long)binding.BaseOffset, (long)binding.PartitionLengthBytes,
                    BlockSizeBytes: 4096, TotalBlocks: binding.Limit / 4096, DiskId: disk)],
                [new(cid, container, 4096, [store], volumes.Select(v => v.VolumeId).ToArray(), false, xid, [], [], [])],
                volumes.Select(v => new ApfsVolumeRecord(v.VolumeId, v.CatalogVolumeUuid!, v.CatalogVolumeObjectId!.Value.ToString(CultureInfo.InvariantCulture),
                    cid, v.VolumeName, true, ["data"], 64, null, "sensitive", "none", false, [], [], [], "7", xid)).ToArray(), []);
            var result = new DeviceInventory(new(Device, "Private physical surrogate", true), volumes, new(1, Device, [disk], topo));
            Assert.True(TopologyAdmission.Validate(result)); return result;
        }
        public ControlOperationRequestPayload Plan(string kind)
        {
            var d = Inventory(); return new(Guid.NewGuid().ToString("D"), kind == "create" ? ApfsControlCommands.VolumeCreatePlan : ApfsControlCommands.VolumeDeletePlan,
                kind == "create" ? new(Device, "", ContainerUuid: d.Volumes[0].CatalogContainerUuid) : SelectedControlTarget.Create(d, d.Volumes[0]),
                ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2), VolumeManagement: kind == "create" ? new("create", "Managed Peer", "0", "0", false) : new("delete"));
        }
        public ControlOperationRequestPayload Confirm(ControlOperationRequestPayload plan, string command, string token)
            => new(Guid.NewGuid().ToString("D"), command, plan.Target, ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2), VolumeManagement: plan.VolumeManagement! with { Token = token });
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<DeviceInfo>>([Inventory().Device]);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string id, CancellationToken ct) => Task.FromResult(Inventory().Volumes);
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken ct) => Task.FromResult<IReadOnlyList<DeviceInventory>>([Inventory()]);
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<MountedVolumeState>>([]);
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken ct) { ++MountCalls; throw new InvalidOperationException("No mount in physical software gate."); }
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken ct) => throw new InvalidOperationException("No unmount in physical software gate.");
        public Task<ImageVerifyResult> VerifyImageAsync(VerifyScope scope, CancellationToken ct) => throw new InvalidOperationException("Regular-file verification cannot authorize a physical source.");
        public Task<VolumeTopologyObservation> ObserveVolumeTopologyAsync(VerifyScope scope, DeviceInventory inventory, CancellationToken ct)
            => throw new InvalidOperationException("Typed physical operation required.");
        public Task<VolumeTopologyObservation> ObserveVolumeTopologyAsync(VerifyScope scope, DeviceInventory inventory, string operation, CancellationToken ct)
            => _native.ObserveVolumeTopologyAsync(scope, inventory, operation, ct);
        public Task<VolumeTopologyResult> RunVolumeTopologyAsync(VolumeTopologyRequest r, VolumeTopologyMode mode, string? confirm, CancellationToken ct)
        {
            Assert.Equal(JsonSerializer.Serialize(r), JsonSerializer.Serialize(Intent().NativeRequest));
            return _native.RunVolumeTopologyAsync(r, mode, confirm, ct);
        }
        public Task<VolumeTopologyResult> NativeNegative(VolumeTopologyRequest r)
            => _native.RunVolumeTopologyAsync(r, VolumeTopologyMode.Prepare, null, default);
        public void Dispose()
        {
            _native.Dispose(); Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", _oldSpool);
            Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", _oldRecovery);
        }
    }
    private sealed class PhysicalTopologyTransport(string root) : IObserverRunner
    {
        private readonly string _binary = Environment.GetEnvironmentVariable("APFSACCESS_PHYSICAL_TOPOLOGY_TEST_BINARY") ??
            throw new InvalidOperationException("Explicit private native process bridge required.");
        public sealed record Call(string Tool, IReadOnlyList<string> Arguments, ObserverRunResult Result);
        public List<Call> Calls { get; } = [];
        public bool Interrupt;
        public ObserverRunResult Direct(string mode) => new ProcessObserverRunner().Run(_binary, [mode, root]);
        public ObserverRunResult Run(string path, IReadOnlyList<string> args)
        {
            var name = Path.GetFileName(path);
            var mode = name switch { "VolumePhysicalObserve.exe" => "bridge-observe", "VolumeManagementImage.exe" => "bridge-tool",
                _ => throw new InvalidOperationException("Unexpected native tool: " + name) };
            string[] actual = [.. args, .. Interrupt && args.Contains("apply") ? new[] { "--interrupt-at", "before-apple-checkpoint-switch" } : []];
            var result = new ProcessObserverRunner().Run(_binary, [mode, root, .. actual]);
            Calls.Add(new(name, actual, result)); return result;
        }
    }
}

public sealed class PhysicalTopologyProcessTheoryAttribute : TheoryAttribute
{
    public PhysicalTopologyProcessTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("APFSACCESS_PHYSICAL_TOPOLOGY_TEST_BINARY") is null)
            Skip = "Requires the private held-file native process gate; never opens a raw device.";
    }
}
