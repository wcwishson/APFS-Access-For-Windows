using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using System.Buffers.Binary;
using System.Reflection;

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
        AssertValidApfsObjectChecksum(imagePath, 0, result.BlockSize);
        AssertValidApfsObjectChecksum(imagePath, result.BlockSize, result.BlockSize);

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
    public async Task ProbeDevices_ReusesDiscoveryForUnchangedImage()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "cached.apfs.img");
        SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);

        using var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            BackendMode = "Native",
            NativeDeviceCandidates = [imagePath],
            NativeAutoDiscoverPhysicalDrives = false,
        });

        var initialDevices = await backend.ProbeDevicesAsync(CancellationToken.None);
        Assert.Single(initialDevices);
        Assert.Equal(1L, GetDiscoveryScanCount(backend));

        var secondDevices = await backend.ProbeDevicesAsync(CancellationToken.None);
        Assert.Single(secondDevices);
        Assert.Equal(1L, GetDiscoveryScanCount(backend));
    }

    [Fact]
    public async Task ProbeDevices_InvalidatesDiscoveryWhenImageChanges()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "invalidate.apfs.img");
        SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);

        using var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            BackendMode = "Native",
            NativeDeviceCandidates = [imagePath],
            NativeAutoDiscoverPhysicalDrives = false,
        });

        var initialDevices = await backend.ProbeDevicesAsync(CancellationToken.None);
        Assert.Single(initialDevices);
        Assert.Equal(1L, GetDiscoveryScanCount(backend));

        using (var stream = new FileStream(imagePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
        {
            stream.WriteByte(0x7F);
        }

        var devicesAfterChange = await backend.ProbeDevicesAsync(CancellationToken.None);
        Assert.Single(devicesAfterChange);
        Assert.Equal(2L, GetDiscoveryScanCount(backend));
    }

    [Fact]
    public async Task ProbeDevices_DropsCachedImage_WhenBackingFileDisappears()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "hot-unplug.apfs.img");
        SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);

        using var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            BackendMode = "Native",
            NativeDeviceCandidates = [imagePath],
            NativeAutoDiscoverPhysicalDrives = false,
        });

        var initialDevices = await backend.ProbeDevicesAsync(CancellationToken.None);
        Assert.Single(initialDevices);

        File.Delete(imagePath);

        var devicesAfterRemoval = await backend.ProbeDevicesAsync(CancellationToken.None);
        Assert.Empty(devicesAfterRemoval);
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

    private static long GetDiscoveryScanCount(NativeApfsBackend backend)
    {
        var field = typeof(NativeApfsBackend).GetField(
            "_deviceDiscoveryScanCount",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);
        return (long)field!.GetValue(backend)!;
    }

    private static void AssertValidApfsObjectChecksum(string imagePath, long offset, int blockSize)
    {
        var block = new byte[blockSize];
        using (var stream = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            stream.Position = offset;
            stream.ReadExactly(block);
        }

        var storedChecksum = BinaryPrimitives.ReadUInt64LittleEndian(block);
        Assert.NotEqual(0UL, storedChecksum);
        Assert.Equal(ComputeApfsObjectChecksum(block.AsSpan(8)), storedChecksum);
    }

    private static ulong ComputeApfsObjectChecksum(ReadOnlySpan<byte> bytes)
    {
        const ulong modulus = uint.MaxValue;
        ulong sum1 = 0;
        ulong sum2 = 0;
        for (var offset = 0; offset < bytes.Length; offset += sizeof(uint))
        {
            sum1 += BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(offset, sizeof(uint)));
            sum2 += sum1;
        }

        var low = modulus - ((sum1 + sum2) % modulus);
        var high = modulus - ((sum1 + low) % modulus);
        return (high << 32) | low;
    }
}
