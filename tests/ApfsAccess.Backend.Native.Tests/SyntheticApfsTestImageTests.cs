using ApfsAccess.Backend.Native;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class SyntheticApfsTestImageTests
{
    [Fact]
    public async Task Create_WritesImageThatNativeBackendCanDiscover()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "safe-test.apfs.img");

        var result = SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);

        Assert.Equal(Path.GetFullPath(imagePath), result.ImagePath);
        Assert.Equal(4, result.SizeMiB);
        Assert.Equal(4 * 1024 * 1024, new FileInfo(imagePath).Length);
        Assert.False(result.MacOsCompatible);

        using var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            BackendMode = "Native",
            NativeDeviceCandidates = [imagePath],
            NativeAutoDiscoverPhysicalDrives = false,
        });

        var devices = await backend.ProbeDevicesAsync(CancellationToken.None);
        var device = Assert.Single(devices);
        Assert.Equal(imagePath, device.DeviceId);

        var volumes = await backend.ProbeVolumesAsync(imagePath, CancellationToken.None);
        var volume = Assert.Single(volumes);
        Assert.Equal("Main", volume.VolumeName);
        Assert.Equal($"{imagePath}|Main", volume.VolumeId);
        Assert.True(volume.SupportsExplorerMount);
    }

    [Fact]
    public void Create_RefusesToOverwriteExistingFile()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "existing.apfs.img");
        File.WriteAllText(imagePath, "keep");

        var ex = Assert.Throws<IOException>(() => SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4));

        Assert.Contains("Refusing to overwrite existing file", ex.Message);
        Assert.Equal("keep", File.ReadAllText(imagePath));
    }

    [Theory]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"\\?\PhysicalDrive1")]
    public void Create_RejectsRawPhysicalDevicePaths(string devicePath)
    {
        var ex = Assert.Throws<ArgumentException>(() => SyntheticApfsTestImage.Create(devicePath, sizeMiB: 4));

        Assert.Contains("normal files", ex.Message);
    }

    private sealed class TempDirectory : IDisposable
    {
        private TempDirectory(string path) => Path = path;

        public string Path { get; }

        public static TempDirectory Create()
        {
            var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "apfsaccess-image-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return new TempDirectory(path);
        }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
