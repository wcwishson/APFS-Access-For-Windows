using System.Text;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;
using Xunit;

namespace ApfsAccess.Service.Tests;

public sealed class FusionServiceRouteTests
{
    private static FusionImageProfile Profile(string root) => new(new('a', 32), new('b', 32), new('c', 32), 101, 20,
        [new(Path.Combine(root, "main.apfs"), "main", "main-store", 4096, 4096),
         new(Path.Combine(root, "tier.apfs"), "tier2", "tier-store", 4096, 4096)]);
    private static string Root()
    {
        var root = Path.Combine(Path.GetTempPath(), "fusion-service-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root); return root;
    }
    private static void Member(string path) { using var file = File.Create(path); file.SetLength(8192); }
    private static ServiceHostOptions Options(string root) => new() { BackendMode = "Native", ManagementJournalRoot = root,
        NativeAutoDiscoverPhysicalDrives = false, NativeDeviceCandidates = [], AutoMountEnabled = false };

    [Fact]
    public void TrayProfileAndIpcFingerprintBindBothMembersAndWindows()
    {
        var p = Profile(Root());
        var json = JsonSerializer.Serialize(p, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        var parsed = FusionImageRegistration.ReadProfile(stream);
        var request = FusionImageRegistration.CreateRequest(parsed);
        Assert.True(SelectedControlTarget.IsWellFormed(request.Target!));
        var validation = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, PipeSchemaVersions.Schema2));
        Assert.True(validation.IsValid, validation.Diagnostic);
        var changed = p with { Members = [p.Members[0], p.Members[1] with { StoreOffset = 0 }] };
        var other = request with { Target = SelectedControlTarget.ForFusion(changed) };
        Assert.NotEqual(ApfsOperationFingerprint.Compute(request), ApfsOperationFingerprint.Compute(other));
        var target = request.Target!;
        Assert.False(SelectedControlTarget.IsWellFormed(target with { RegisteredFusion = changed }));
        p.Members[0] = p.Members[1];
        Assert.Equal("main", target.RegisteredFusion!.Members[0].Role);
    }

    [Fact]
    public void DuplicateAndUnknownSelectorsRefuse()
    {
        var p = Profile(Root());
        var json = JsonSerializer.Serialize(p, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        foreach (var text in new[] { json.Insert(1, "\"volumeOid\":101,"), json.Insert(1, "\"assumeWritable\":true,") })
        { using var bytes = new MemoryStream(Encoding.UTF8.GetBytes(text)); Assert.ThrowsAny<Exception>(() => FusionImageRegistration.ReadProfile(bytes)); }
        Assert.False((p with { Members = [p.Members[0], p.Members[0]] }).IsValid());
        Assert.False((p with { Members = [p.Members[0], p.Members[1] with { StoreOffset = ulong.MaxValue }] }).IsValid());
    }

    [Fact]
    public async Task RegistrationHoldsExactPairAndRejectsStaleTarget()
    {
        var root = Root(); var p = Profile(root); foreach (var member in p.Members) Member(member.Path);
        using (var backend = new NativeApfsBackend(Options(root)))
        {
            await backend.RegisterFusionImageAsync(p, default);
            var inventory = await backend.ProbeInventoryAsync(true, default);
            var row = Assert.Single(Assert.Single(inventory).Volumes);
            Assert.All(row.RegisteredFusion!.Members, m => Assert.NotNull(m.Identity));
            Assert.True(SelectedControlTarget.Matches(inventory, SelectedControlTarget.ForFusion(row.RegisteredFusion)));
            Assert.False(SelectedControlTarget.Matches(inventory, SelectedControlTarget.ForFusion(p)));
            foreach (var member in p.Members) Assert.Throws<IOException>(() => File.Open(member.Path, FileMode.Open, FileAccess.Write, FileShare.None));
            await Assert.ThrowsAsync<InvalidOperationException>(() => backend.RegisterFusionImageAsync(p, default));
            var old = row.RegisteredFusion.Contract;
            row.RegisteredFusion.Members[0] = row.RegisteredFusion.Members[1];
            var again = await backend.ProbeInventoryAsync(false, default);
            Assert.Equal(old, again[0].Volumes[0].RegisteredFusion!.Contract);
        }
        foreach (var member in p.Members) { using var writable = File.Open(member.Path, FileMode.Open, FileAccess.Write, FileShare.None); }
    }

    [Fact]
    public async Task MissingSecondMemberUnwindsFirstLease()
    {
        var root = Root(); var p = Profile(root); Member(p.Members[0].Path);
        using var backend = new NativeApfsBackend(Options(root));
        await Assert.ThrowsAnyAsync<IOException>(() => backend.RegisterFusionImageAsync(p, default));
        using var first = File.Open(p.Members[0].Path, FileMode.Open, FileAccess.Write, FileShare.None);
        Assert.Empty(await backend.ProbeInventoryAsync(true, default));
    }

    [Fact]
    public async Task ReverseSelectionUsesCanonicalRetainedPairOrder()
    {
        var root = Root(); var p = Profile(root); foreach (var member in p.Members) Member(member.Path);
        var reverse = p with { Members = [p.Members[1], p.Members[0]] };
        using var backend = new NativeApfsBackend(Options(root));
        await backend.RegisterFusionImageAsync(reverse, default);
        var inventory = await backend.ProbeInventoryAsync(true, default);
        var registered = Assert.Single(Assert.Single(inventory).Volumes).RegisteredFusion!;
        Assert.Equal(p.Members.Select(m => m.Role), registered.Members.Select(m => m.Role));
        Assert.Equal(p.DeviceId, registered.DeviceId);
        Assert.All(registered.Members, m => Assert.NotNull(m.Identity));
        Assert.Equal("tier2", reverse.Members[0].Role);
        Assert.True(SelectedControlTarget.Matches(inventory, SelectedControlTarget.ForFusion(registered)));
        Assert.False(SelectedControlTarget.Matches(inventory, SelectedControlTarget.ForFusion(reverse)));
    }

    [Fact]
    public async Task TrayMountRequestCarriesCapturedPairAndRefusesOldObservation()
    {
        var root = Root(); var p = Profile(root); foreach (var member in p.Members) Member(member.Path);
        using var backend = new NativeApfsBackend(Options(root)); await backend.RegisterFusionImageAsync(p, default);
        var inventory = await backend.ProbeInventoryAsync(true, default);
        var status = new StatusChangedPayload(RuntimeState.Idle, [], null, DateTime.UtcNow, [], false, [], ConnectedInventory: inventory, InventoryGeneration: 1);
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.True(row.CanFix); Assert.False(DriveDashboardPresenter.CanFixVolume(row));
        var request = DriveDashboardPresenter.CreateMountRequest(status, row);
        Assert.Equal(ApfsControlModes.ReadWrite, request.RequestedMode);
        Assert.Equal(inventory[0].Volumes[0].RegisteredFusion!.Contract, request.Target!.RegisteredFusion!.Contract);
        var changed = inventory[0].Volumes[0].RegisteredFusion! with { CheckpointXid = 21 };
        var newer = status with { ConnectedInventory = [inventory[0] with { Volumes = [inventory[0].Volumes[0] with { RegisteredFusion = changed, RecoveryIdentity = changed.Contract }] }] };
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateMountRequest(newer, row));
    }
}
