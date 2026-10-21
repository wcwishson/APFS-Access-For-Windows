using System.Security.Cryptography;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Backend.Native.Tests;

[Collection("ObserverPathEnv")]
public sealed class RealNativeImageManagementWorkflowTests
{
    [RealImageKeeperTheory]
    [InlineData("format", false)] [InlineData("format", true)]
    [InlineData("erase", false)] [InlineData("erase", true)]
    [InlineData("grow", false)] [InlineData("shrink", false)]
    public async Task RealBinary_OriginalRequestAndExistingFixtureWalsSurvivePrepareApplyCancelAndReload(string operation, bool cancel)
    {
        var toolRoot = Environment.GetEnvironmentVariable("APFSACCESS_IMAGE_KEEPER_TOOLS")!;
        var fixture = Environment.GetEnvironmentVariable("APFSACCESS_IMAGE_KEEPER_FIXTURE")!;
        var fixtureSpool = Environment.GetEnvironmentVariable("APFSACCESS_IMAGE_KEEPER_FIXTURE_SPOOL") ?? fixture;
        var root = Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!, "real-vif-" + Guid.NewGuid().ToString("N"));
        var journals = Path.Combine(root, "journals"); var spool = Path.Combine(root, "spool"); var recovery = Path.Combine(root, "recovery");
        Directory.CreateDirectory(journals); Directory.CreateDirectory(spool); Directory.CreateDirectory(recovery);
        var image = Path.Combine(root, "fresh.apfs.img");
        NativeOrdinaryImageOwnership.RegisterFreshCopy(new(Path.Combine(fixture, "image.apfs"), image), journals, spool, recovery);
        using var backend = new NativeApfsBackend(new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false,
            NativeDeviceCandidates = [image] }, lifecycleTestHooks: null, observerRunner: new ProcessObserverRunner(),
            observerPathOverride: Path.Combine(toolRoot, "ApfsObserver.exe"));
        var inventory = Assert.Single(await backend.ProbeInventoryAsync(true, default));
        Assert.NotEmpty(inventory.Volumes); Assert.DoesNotContain(inventory.Volumes, v => v.CatalogContainerUuid == new string('a', 32));
        foreach (var volume in inventory.Volumes)
        {
            var sourceWal = NativeRecoveryStorage.CanonicalWal(fixtureSpool, volume.RecoveryIdentity!);
            Assert.True(File.Exists(sourceWal), "Every native-observed sibling needs an existing fixture WAL; no empty fallback is created.");
            var wal = NativeRecoveryStorage.CanonicalWal(spool, volume.RecoveryIdentity!);
            Directory.CreateDirectory(Path.GetDirectoryName(wal)!); File.Copy(sourceWal, wal);
        }
        var selected = inventory.Volumes[0]; var scope = VerifyScopeDerivation.TryDerive(inventory, selected).Scope!;
        var observed = new NativeApfsVolumeManagement(new ProcessObserverRunner(), Path.Combine(toolRoot, "VolumeManagementImage.exe"), journals, spool)
            .Observe(scope, inventory, recovery, default);
        var format = operation is "format" or "erase";
        var newContainer = format ? Guid.NewGuid().ToString("N") : null; var newVolume = format ? Guid.NewGuid().ToString("N") : null;
        var bytes = ulong.Parse(observed.StoreSizeBytes);
        var targetBytes = format ? observed.StoreSizeBytes : (operation == "grow" ? bytes + 1048576UL : bytes - 1048576UL).ToString();
        var destination = format ? NativeApfsVolumeImageManagement.DestinationWal(spool, newContainer!) : null;
        var request = new VolumeTopologyRequest(operation, image, journals, "0", observed.ContainerUuid, selected.CatalogVolumeUuid!,
            selected.CatalogVolumeObjectId!.Value.ToString(), observed.CheckpointXid, observed.SourceIdentity, spool, observed.Volumes,
            Name: format ? "Managed data" : null, CaseSensitive: format ? false : null,
            ImageOptions: new(observed.StoreSizeBytes, targetBytes, newContainer, newVolume, destination));
        var original = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), format ? ApfsControlCommands.VolumeFormatPlan : ApfsControlCommands.VolumeResizePlan,
            SelectedControlTarget.Create(inventory, selected), ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2),
            VolumeManagement: format ? new(operation, Name: request.Name, CaseSensitive: false) : new(operation, TargetBytes: targetBytes));
        var keeper = new NativeApfsVolumeImageManagement(new ProcessObserverRunner(), Path.Combine(toolRoot, format ? "VolumeFormatImage.exe" : "VolumeResizeImage.exe"), journals, spool);
        var preimage = Hash(image); var walHashes = observed.Volumes.ToDictionary(w => w.Path, w => Hash(w.Path));
        File.WriteAllText(Path.Combine(root, "fixture-and-tools.json"), JsonSerializer.Serialize(new { fixture, fixtureSpool,
            imageSha256Before = preimage, siblingWals = observed.Volumes.Select(w => new { w.Oid, w.VolumeUuid, w.Path, bytes = new FileInfo(w.Path).Length, sha256 = walHashes[w.Path] }),
            tools = new[] { "VolumeManagementImage.exe", "VolumeFormatImage.exe", "VolumeResizeImage.exe", "VolumeKeeperInspect.exe", "ApfsObserver.exe" }
                .Select(name => new { path = Path.Combine(toolRoot, name), sha256 = Hash(Path.Combine(toolRoot, name)) }) }));
        using (var store = new VolumeManagementIntentStore(journals)) store.Save(new(original, request, "preparing"));
        NativeRecoveryStorage.RequireDisposition(request, recovery);
        Inspect(toolRoot, request, null);
        var prepared = keeper.Execute(request, VolumeTopologyMode.Prepare, null, default);
        Save(root, "prepared", prepared);
        Assert.True(prepared.Outcome == "prepared", prepared.Report.GetRawText()); Assert.Equal(preimage, Hash(image));
        if (format)
        {
            Assert.True(File.Exists(destination));
            Assert.Throws<IOException>(() => NativeRecoveryStorage.RequireDisposition(spool, recovery, request.SiblingWals));
        }
        using (var store = new VolumeManagementIntentStore(journals)) store.Save(new(original, request, "prepared", prepared, prepared.ConfirmationToken));
        using (var store = new VolumeManagementIntentStore(journals))
        {
            var persisted = Assert.Single(store.ReadAll()); Assert.Equal(request, persisted.NativeRequest with { SiblingWals = request.SiblingWals });
            store.Save(persisted with { State = "applying" });
        }
        NativeRecoveryStorage.RequireDisposition(request, recovery); Inspect(toolRoot, request, request);
        var terminal = keeper.Execute(request, cancel ? VolumeTopologyMode.Cancel : VolumeTopologyMode.Apply, prepared.ConfirmationToken, default);
        Assert.Equal(cancel ? "cancelled" : "committed", terminal.Outcome); Save(root, "terminal", terminal);
        if (cancel) Assert.Equal(preimage, Hash(image));
        else { Assert.NotEqual(preimage, Hash(image)); Assert.Equal(long.Parse(targetBytes), new FileInfo(image).Length); }
        using (var store = new VolumeManagementIntentStore(journals))
        {
            var persisted = Assert.Single(store.ReadAll()); store.Save(persisted with { State = terminal.Outcome, Result = terminal });
        }
        var terminalHash = Hash(image);
        VolumeTopologyRequest saved;
        using (var store = new VolumeManagementIntentStore(journals)) saved = Assert.Single(store.ReadAll()).NativeRequest;
        NativeRecoveryStorage.RequireDisposition(saved, recovery); Inspect(toolRoot, saved, saved);
        var replay = new NativeApfsVolumeImageManagement(new ProcessObserverRunner(), Path.Combine(toolRoot, format ? "VolumeFormatImage.exe" : "VolumeResizeImage.exe"), journals, spool)
            .Execute(saved, VolumeTopologyMode.Recover, null, default);
        Assert.Equal(terminal.Outcome, replay.Outcome); Assert.Equal(terminalHash, Hash(image)); Save(root, "recovered", replay);
        foreach (var wal in walHashes) Assert.Equal(wal.Value, Hash(wal.Key));
        Assert.Empty(NativeOrdinaryImageOwnership.Read(journals, image, "0").LaunchBindings);
    }
    private static void Inspect(string tools, VolumeTopologyRequest request, VolumeTopologyRequest? original)
    {
        var source = NativeApfsVolumeManagement.SourceIdentity(request.Image, "0");
        var wire = new ProcessObserverRunner().Run(Path.Combine(tools, "VolumeKeeperInspect.exe"),
            ["--image", request.Image, "--offset", "0", "--journal-directory", request.JournalRoot], default);
        NativeManagementJournalAdmission.ValidateInspection(wire, request.JournalRoot, source, original);
    }
    private static string Hash(string path) { using var file = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(file)); }
    private static void Save(string root, string stage, VolumeTopologyResult result) => File.WriteAllText(Path.Combine(root, stage + ".json"), result.Report.GetRawText());
}

public sealed class RealImageKeeperTheoryAttribute : TheoryAttribute
{
    public RealImageKeeperTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("APFSACCESS_IMAGE_KEEPER_TOOLS") is null || Environment.GetEnvironmentVariable("APFSACCESS_IMAGE_KEEPER_FIXTURE") is null)
            Skip = "Requires explicitly released real helpers and existing canonical fixture WALs; no mounted service operations.";
    }
}
