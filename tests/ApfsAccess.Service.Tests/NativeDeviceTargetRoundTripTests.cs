using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class NativeDeviceTargetRoundTripTests
{
    private const string Device = @"\\.\PhysicalDrive2";
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Theory]
    [InlineData(@"\\.\PhysicalDrive2", false)]
    [InlineData(@"\\.\PhysicalDrive2", true)]
    [InlineData(@"\\.\physicaldrive2", true)]
    public async Task ContainerUnmount_NativePathSurvivesWireNormalizationAndEvidence(string requestedDevice, bool discoveryGap)
    {
        var backend = new OwnedMountBackend(discoveryGap);
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker);
        var request = RoundTrip(new(Guid.NewGuid().ToString("D"), ApfsControlCommands.ContainerUnmount,
            new(requestedDevice, "", ContainerUuid: Container), ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2)));
        Assert.Equal(requestedDevice, request.Target!.DeviceId);
        Assert.Equal(18, request.Target.DeviceId.Length);
        var root = Path.Combine(Path.GetTempPath(), "native-device-roundtrip", request.OperationId);
        var service = new AgentControlOperationService((operation, token) =>
        {
            Assert.Equal(Device.ToLowerInvariant(), operation.Target!.DeviceId);
            Assert.Equal(18, operation.Target.DeviceId.Length);
            return executor.ExecuteAsync(operation, token);
        }, root);
        try
        {
            var result = await service.ExecuteOrReplayAsync(request).WaitAsync(TimeSpan.FromSeconds(10));
            if (discoveryGap)
            {
                Assert.False(result.Success);
                Assert.Equal(ApfsOperationCodes.OperationFailed, result.Code);
                Assert.Equal("failed", result.FinalStatus);
                Assert.Contains("not connected", result.Diagnostic);
                Assert.Equal(0, backend.UnmountCalls);
                Assert.Equal(2, (await backend.GetMountStateAsync(CancellationToken.None)).Count);
                Assert.Equal("not-proven", result.MountProof);
                Assert.Equal("not-proven", result.OwnershipProof);
                Assert.Equal("not-proven", result.DurabilityProof);
            }
            else
            {
                Assert.True(result.Success, result.Diagnostic);
                Assert.Equal(2, backend.UnmountCalls);
                Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
                Assert.Equal("proven", result.OwnershipProof);
                Assert.Equal("proven", result.DurabilityProof);
            }
            Assert.Equal(ApfsOperationFingerprint.Compute(request), result.Fingerprint);
            using var evidence = JsonDocument.Parse(await File.ReadAllTextAsync(result.EvidencePath!));
            var persistedDevice = evidence.RootElement.GetProperty("target").GetProperty("deviceId").GetString();
            Assert.Equal(Device.ToLowerInvariant(), persistedDevice);
            Assert.Equal(18, persistedDevice!.Length);
            Assert.Equal(3, persistedDevice.Count(character => character == '\\'));
            var replay = await service.ExecuteOrReplayAsync(request);
            Assert.Equal(result.Success, replay.Success);
            Assert.Equal(result.Code, replay.Code);
            Assert.Equal(discoveryGap ? 0 : 2, backend.UnmountCalls);
        }
        finally { await service.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)); }
    }

    [Theory]
    [InlineData(@"\\\\.\\PhysicalDrive2")]
    [InlineData(@"\\.\PhysicalDrive3")]
    public async Task ContainerUnmount_DifferentOrActuallyDoubledNativePathCannotRetargetOwnedMounts(string device)
    {
        var backend = new OwnedMountBackend(true);
        using var worker = CreateWorker(backend);
        var request = RoundTrip(new(Guid.NewGuid().ToString("D"), ApfsControlCommands.ContainerUnmount,
            new(device, "", ContainerUuid: Container), ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2)));
        var result = await new AgentControlCommandExecutor(worker)
            .ExecuteAsync(request, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.MissingVolume, result.Code);
        Assert.Equal(0, backend.UnmountCalls);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(42, true)]
    public async Task ContainerUnmount_DiscoveryGapDoesNotAuthorizeUnownedOrDifferentContainerMounts(int ownerPid, bool differentContainer)
    {
        var backend = new OwnedMountBackend(true, ownerPid, differentContainer ? new string('b', 32) : Container);
        using var worker = CreateWorker(backend);
        var request = RoundTrip(new(Guid.NewGuid().ToString("D"), ApfsControlCommands.ContainerUnmount,
            new(Device.ToLowerInvariant(), "", ContainerUuid: Container), ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2)));
        var result = await new AgentControlCommandExecutor(worker)
            .ExecuteAsync(request, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal(0, backend.UnmountCalls);
        Assert.Equal(2, (await backend.GetMountStateAsync(CancellationToken.None)).Count);
    }

    private static ControlOperationRequestPayload RoundTrip(ControlOperationRequestPayload request)
    {
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2);
        Assert.True(PipeMessageCodec.Validate(envelope).IsValid);
        Assert.True(PipeMessageCodec.TryDeserialize(PipeMessageCodec.Serialize(envelope), out var decoded));
        Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(decoded!, out var payload));
        return payload!;
    }

    [Theory]
    [InlineData("duplicate-device")]
    [InlineData("cross-device-volume")]
    public async Task ContainerUnmount_ContradictoryRefreshCannotUseEarlierInventoryOrOwnedMounts(string refreshFault)
    {
        var backend = new OwnedMountBackend(false, refreshFault: refreshFault);
        using var worker = CreateWorker(backend);
        var request = RoundTrip(new(Guid.NewGuid().ToString("D"), ApfsControlCommands.ContainerUnmount,
            new(Device, "", ContainerUuid: Container), ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2)));
        var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(request, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.OperationFailed, result.Code);
        Assert.Contains("malformed or contradictory", result.Diagnostic);
        Assert.Equal(0, backend.UnmountCalls);
        Assert.Equal(2, (await backend.GetMountStateAsync(CancellationToken.None)).Count);
        Assert.Equal("not-proven", result.MountProof);
        Assert.Equal("not-proven", result.OwnershipProof);
        Assert.Equal("not-proven", result.DurabilityProof);
    }

    private static ApfsMountWorker CreateWorker(IApfsBackend backend) => new(
        NullLogger<ApfsMountWorker>.Instance, backend, new NoMountPolicy(), new RuntimeStatusPublisher(),
        new FixedOptions(new ServiceHostOptions()));

    private sealed class OwnedMountBackend(bool gap, int ownerPid = 42, string mountedContainer = Container,
        string? refreshFault = null) : IApfsBackend
    {
        private readonly VolumeInfo[] _volumes = Enumerable.Range(101, 2).Select(oid => new VolumeInfo(
            $"apfs-vol:{Container}:{oid}", Device, oid == 101 ? "Alpha" : "Beta", true,
            RecoveryIdentity: $"recovery-{oid}", CatalogVolumeId: $"apfs-vol:{Container}:{oid}",
            CatalogContainerUuid: Container, CatalogVolumeObjectId: (ulong)oid)).ToArray();
        private readonly List<MountedVolumeState> _mounts = Enumerable.Range(101, 2).Select(oid => new MountedVolumeState(
            $"apfs-vol:{Container}:{oid}", oid == 101 ? "E:\\" : "F:\\", MountAccessMode.ReadWrite,
            DeviceId: Device, RecoveryIdentity: $"recovery-{oid}", HostProcessId: ownerPid,
            CatalogVolumeId: $"apfs-vol:{Container}:{oid}", CatalogContainerUuid: mountedContainer,
            CatalogVolumeObjectId: (ulong)oid)).ToList();
        private int _inventoryCalls;
        public int UnmountCalls { get; private set; }
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var refreshed = ++_inventoryCalls > 1;
            DeviceInventory device = new(new(Device, "Samsung", true), _volumes);
            IReadOnlyList<DeviceInventory> inventory = !refreshed ? [device] : refreshFault switch
            {
                "duplicate-device" => [device, device],
                "cross-device-volume" => [device with { Volumes =
                    _volumes.Select(volume => volume with { DeviceId = @"\\.\PhysicalDrive3" }).ToArray() }],
                _ => gap ? [] : [device],
            };
            return Task.FromResult(inventory);
        }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => throw new NotSupportedException();
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
            => Task.FromResult<IReadOnlyList<MountedVolumeState>>(_mounts.ToArray());
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            UnmountCalls++;
            _mounts.RemoveAll(mount => mount.MountPoint == point);
            return Task.FromResult(new UnmountResult(true, point, null, true, true, true));
        }
    }
    private sealed class NoMountPolicy : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> used) => throw new NotSupportedException();
        public bool ShouldAutoMount(VolumeInfo volume) => false;
    }
    private sealed class FixedOptions(ServiceHostOptions options) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => options;
        public ServiceHostOptions Get(string? name) => options;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
}
