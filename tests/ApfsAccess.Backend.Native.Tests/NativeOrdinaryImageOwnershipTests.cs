using System.Diagnostics;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

[Collection("ObserverPathEnv")]
public sealed class NativeOrdinaryImageOwnershipTests
{
    [Fact]
    public async Task ProductionDiscoveryRegistersFlushedFreshDestinationBeforePublishingItsCandidate()
    {
        using var temp = DTempDirectory.Create("ordinary-discovery");
        var root = Path.Combine(temp.Path, "journals"); var spool = Path.Combine(temp.Path, "spool"); var recovery = Path.Combine(temp.Path, "recovery");
        Directory.CreateDirectory(root); Directory.CreateDirectory(spool); Directory.CreateDirectory(recovery);
        var source = Path.Combine(temp.Path, "source.apfs.img"); var image = Path.Combine(temp.Path, "fresh.apfs.img");
        SyntheticApfsTestImage.Create(source, sizeMiB: 4);
        var oldSpool = Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT");
        var oldRecovery = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT");
        try
        {
            Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", spool);
            Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", recovery);
            using var backend = new NativeApfsBackend(new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false,
                ManagementJournalRoot = root, OrdinaryManagementImages = [new(source, image)] }, lifecycleTestHooks: null, observerRunner: null,
                observerPathOverride: Path.Combine(temp.Path, "absent-observer.exe"));
            Assert.False(File.Exists(image));
            var inventory = await backend.ProbeInventoryAsync(false, default);
            Assert.Equal(image, Assert.Single(inventory).Device.DeviceId);
            Assert.Equal(File.ReadAllBytes(source), File.ReadAllBytes(image));
            var record = NativeOrdinaryImageOwnership.Read(root, image, "0");
            Assert.True(record.FreshCopy); Assert.Empty(record.LaunchBindings); Assert.Equal(source, record.CopiedFrom);
            Assert.Equal(record.OriginalDigest, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(image))));
            Assert.Empty(Directory.GetFiles(spool, "*", SearchOption.AllDirectories));
            Assert.Equal(image, Assert.Single(await backend.ProbeInventoryAsync(false, default)).Device.DeviceId);
        }
        finally
        {
            Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", oldSpool);
            Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", oldRecovery);
        }
    }
    [Fact]
    public void BusySourceCannotPublishFreshDestinationOrProvenance()
    {
        using var temp = DTempDirectory.Create("ordinary-busy-source");
        var source = Path.Combine(temp.Path, "source.apfs"); var image = Path.Combine(temp.Path, "fresh.apfs");
        File.WriteAllBytes(source, new byte[1048576]);
        using var writer = new FileStream(source, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
        Assert.ThrowsAny<IOException>(() => NativeOrdinaryImageOwnership.RegisterFreshCopy(new(source, image), temp.Path, temp.Path, temp.Path));
        Assert.False(File.Exists(image)); Assert.Empty(Directory.GetFiles(temp.Path, "ordinary-image-*"));
    }
    [Fact]
    public void FreshCopyAndExactOriginalLaunchRootsSurviveReloadWhileAbsentSiblingWalRefuses()
    {
        using var temp = DTempDirectory.Create("ordinary-image-provenance");
        var root = Path.Combine(temp.Path, "journals"); var spool = Path.Combine(temp.Path, "spool"); var recovery = Path.Combine(temp.Path, "recovery");
        Directory.CreateDirectory(root); Directory.CreateDirectory(spool); Directory.CreateDirectory(recovery);
        var source = Path.Combine(temp.Path, "source.apfs"); var image = Path.Combine(temp.Path, "fresh.apfs"); File.WriteAllBytes(source, new byte[2097152]);
        var registration = new OrdinaryManagementImageRegistration(source, image);
        NativeOrdinaryImageOwnership.RegisterFreshCopy(registration, root, spool, recovery);
        Assert.Equal(File.ReadAllBytes(source), File.ReadAllBytes(image));
        var inventory = NativeRecoveryStorageTests.Inventory(image); var volume = inventory.Volumes[0];
        var start = new ProcessStartInfo("test-no-process.exe"); start.Environment["APFSACCESS_SPOOL_ROOT"] = spool; start.Environment["APFSACCESS_RECOVERY_ROOT"] = recovery;
        NativeOrdinaryImageOwnership.CaptureLaunch(start, root, image, "0", [volume]);
        var record = NativeOrdinaryImageOwnership.Read(root, image, "0"); Assert.True(record.FreshCopy); Assert.Equal(source, record.CopiedFrom);
        var binding = Assert.Single(record.LaunchBindings); Assert.Equal(NativeRecoveryStorage.CanonicalWal(spool, volume.RecoveryIdentity!), binding.Wal);
        VolumeTopologyWal[] census = [new(binding.Oid, binding.VolumeUuid, binding.Wal)];
        Assert.Throws<IOException>(() => NativeOrdinaryImageOwnership.RequireCensus(root, image, "0", spool, recovery, binding.ContainerUuid, census));
        Directory.CreateDirectory(Path.GetDirectoryName(binding.Wal)!); File.WriteAllBytes(binding.Wal, []);
        NativeOrdinaryImageOwnership.RequireCensus(root, image, "0", spool, recovery, binding.ContainerUuid, census);
        NativeOrdinaryImageOwnership.RegisterFreshCopy(registration, root, spool, recovery);
        var other = Path.Combine(temp.Path, "other-spool"); Directory.CreateDirectory(other); start.Environment["APFSACCESS_SPOOL_ROOT"] = other;
        Assert.Throws<IOException>(() => NativeOrdinaryImageOwnership.CaptureLaunch(start, root, image, "0", [volume]));
        Assert.Equal(spool, NativeOrdinaryImageOwnership.Read(root, image, "0").SpoolRoot);
        File.Move(image, image + ".original"); File.Copy(image + ".original", image);
        Assert.ThrowsAny<IOException>(() => NativeOrdinaryImageOwnership.Read(root, image, "0"));
    }
    [Fact]
    public void HistoricalImageCannotBeRelabelledAsFresh()
    {
        using var temp = DTempDirectory.Create("ordinary-historical");
        var source = Path.Combine(temp.Path, "source.apfs"); var existing = Path.Combine(temp.Path, "existing.apfs");
        File.WriteAllBytes(source, new byte[1048576]); File.WriteAllBytes(existing, new byte[1048576]);
        Assert.ThrowsAny<IOException>(() => NativeOrdinaryImageOwnership.RegisterFreshCopy(new(source, existing), temp.Path, temp.Path, temp.Path));
        Assert.Equal(1048576, new FileInfo(existing).Length);
    }
}
