using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Reflection;
using System.Text;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeApfsBackendVolumeResolutionTests
{
    private static readonly Guid ApfsPartitionTypeGuid = new("7C3457EF-0000-11AA-AA11-00306543ECAC");
    private static readonly Guid FirstPartitionGuid = new("11111111-2222-3333-4444-555555555555");
    private static readonly Guid SecondPartitionGuid = new("99999999-2222-3333-4444-555555555555");
    private static readonly Guid ContainerUuid = new("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
    private const int SectorSize = 512;
    private const int BlockSize = 4096;

    [Fact]
    public async Task ResolveVolumeAsync_RejectsSyntacticallyValidUnknownVolumeId()
    {
        using var temp = TestDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "single.apfs.img");
        SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);

        using var backend = CreateBackend();

        var discovered = await InvokeResolveVolumeAsync(
            backend,
            $"{imagePath}|Main",
            CancellationToken.None);
        Assert.NotNull(discovered);
        Assert.Equal(0UL, ReadTargetOffset(InvokeResolveMountTarget(backend, discovered!)));

        var resolved = await InvokeResolveVolumeAsync(
            backend,
            $"{imagePath}|Missing",
            CancellationToken.None);

        Assert.Null(resolved);
    }

    [Fact]
    public async Task ResolveVolumeAsync_RejectsStaleCachedVolumeAfterBackingImageDisappears()
    {
        using var temp = TestDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "stale.apfs.img");
        SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);

        using var backend = CreateBackend();

        var initial = await InvokeResolveVolumeAsync(
            backend,
            $"{imagePath}|Main",
            CancellationToken.None);
        Assert.NotNull(initial);

        File.Delete(imagePath);

        var resolvedAfterRemoval = await InvokeResolveVolumeAsync(
            backend,
            $"{imagePath}|Main",
            CancellationToken.None);

        Assert.Null(resolvedAfterRemoval);
    }

    [Fact]
    public async Task ResolveVolumeAsync_DoesNotTrustCachedVolumeWithMismatchedDevice()
    {
        using var temp = TestDirectory.Create();
        var discoveredDevicePath = Path.Combine(temp.Path, "discovered.apfs.img");
        var requestedDevicePath = Path.Combine(temp.Path, "requested.apfs.img");
        SyntheticApfsTestImage.Create(discoveredDevicePath, sizeMiB: 4);

        using var backend = CreateBackend();
        var discovered = Assert.Single(
            await backend.ProbeVolumesAsync(discoveredDevicePath, CancellationToken.None));
        var requestedVolumeId = $"{requestedDevicePath}|Main";
        SeedVolumeCache(backend, requestedVolumeId, discovered with { VolumeId = requestedVolumeId });

        var resolved = await InvokeResolveVolumeAsync(
            backend,
            requestedVolumeId,
            CancellationToken.None);

        Assert.Null(resolved);
    }

    [Fact]
    public async Task ResolveVolumeAsync_RequiresExactNameOnMultiPartitionDevice_AndPreservesPartitionOffset()
    {
        using var temp = TestDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "multi-partition.img");
        CreateTwoPartitionImage(imagePath);

        using var backend = CreateBackend();
        var requestedVolumeId = $"{imagePath}|Backup";
        var resolved = await InvokeResolveVolumeAsync(
            backend,
            requestedVolumeId,
            CancellationToken.None);

        Assert.NotNull(resolved);
        Assert.Equal("Backup", resolved!.VolumeName);

        var target = InvokeResolveMountTarget(backend, resolved);
        Assert.Equal(6UL * 1024 * 1024, ReadTargetOffset(target));

        var caseInsensitive = await InvokeResolveVolumeAsync(
            backend,
            $"{imagePath.ToUpperInvariant()}|backup",
            CancellationToken.None);
        Assert.NotNull(caseInsensitive);
        Assert.Equal("Backup", caseInsensitive!.VolumeName);

        var unknown = await InvokeResolveVolumeAsync(
            backend,
            $"{imagePath}|Main",
            CancellationToken.None);
        Assert.Null(unknown);
    }

    [Fact]
    public void ResolveMountTarget_RejectsUntrackedVolumeInsteadOfDefaultingToZeroOffset()
    {
        using var backend = CreateBackend();
        var volume = new VolumeInfo(
            VolumeId: @"D:\missing.apfs.img|Main",
            DeviceId: @"D:\missing.apfs.img",
            VolumeName: "Main",
            SupportsReadWrite: false,
            NativeVolumePath: @"D:\missing.apfs.img\ApfsAccess_Volumes\Main");

        var exception = Assert.Throws<TargetInvocationException>(
            () => InvokeResolveMountTarget(backend, volume));

        Assert.IsType<InvalidOperationException>(exception.InnerException);
    }

    private static NativeApfsBackend CreateBackend()
        => new(new ServiceHostOptions
        {
            BackendMode = "Native",
            NativeAutoDiscoverPhysicalDrives = false,
        });

    private static async Task<VolumeInfo?> InvokeResolveVolumeAsync(
        NativeApfsBackend backend,
        string volumeId,
        CancellationToken cancellationToken)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveVolumeAsync",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var task = Assert.IsType<Task<VolumeInfo?>>(method!.Invoke(backend, [volumeId, cancellationToken]));
        return await task;
    }

    private static object InvokeResolveMountTarget(NativeApfsBackend backend, VolumeInfo volume)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveMountTarget",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        return method!.Invoke(backend, [volume])!;
    }

    private static ulong ReadTargetOffset(object target)
    {
        var property = target.GetType().GetProperty("DeviceOffsetBytes");
        Assert.NotNull(property);
        return Assert.IsType<ulong>(property!.GetValue(target));
    }

    private static void SeedVolumeCache(
        NativeApfsBackend backend,
        string volumeId,
        VolumeInfo volume)
    {
        var field = typeof(NativeApfsBackend).GetField(
            "_volumeCache",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        var cache = Assert.IsType<ConcurrentDictionary<string, VolumeInfo>>(field!.GetValue(backend));
        cache[volumeId] = volume;
    }

    private static void CreateTwoPartitionImage(string path)
    {
        const ulong sizeBytes = 12UL * 1024 * 1024;
        const ulong firstPartitionOffset = 1UL * 1024 * 1024;
        const ulong secondPartitionOffset = 6UL * 1024 * 1024;
        const ulong partitionSize = 3UL * 1024 * 1024;

        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
        stream.SetLength(checked((long)sizeBytes));

        var entries = new byte[2 * 128];
        WritePartitionEntry(
            entries.AsSpan(0, 128),
            FirstPartitionGuid,
            firstPartitionOffset,
            partitionSize,
            "Data");
        WritePartitionEntry(
            entries.AsSpan(128, 128),
            SecondPartitionGuid,
            secondPartitionOffset,
            partitionSize,
            "Backup");

        Span<byte> header = stackalloc byte[SectorSize];
        "EFI PART"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(8, 4), 0x00010000);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(12, 4), 92);
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(72, 8), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(80, 4), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(84, 4), 128);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(88, 4), ComputeCrc32(entries));
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(16, 4), ComputeCrc32(header[..92]));

        stream.Position = SectorSize;
        stream.Write(header);
        stream.Position = 2L * SectorSize;
        stream.Write(entries);

        WriteContainerSuperblock(stream, firstPartitionOffset, 0x1122334455667788, checkpointXid: 7);
        WriteContainerSuperblock(stream, secondPartitionOffset, 0x8877665544332211, checkpointXid: 7);
        WriteContainerSuperblock(stream, firstPartitionOffset + BlockSize, 0x1122334455667788, checkpointXid: 8);
        WriteContainerSuperblock(stream, secondPartitionOffset + BlockSize, 0x8877665544332211, checkpointXid: 8);
        stream.Flush(flushToDisk: true);
    }

    private static void WritePartitionEntry(
        Span<byte> entry,
        Guid partitionGuid,
        ulong offsetBytes,
        ulong sizeBytes,
        string name)
    {
        entry.Clear();
        ApfsPartitionTypeGuid.TryWriteBytes(entry[..16]);
        partitionGuid.TryWriteBytes(entry.Slice(16, 16));
        var startLba = offsetBytes / SectorSize;
        BinaryPrimitives.WriteUInt64LittleEndian(entry.Slice(32, 8), startLba);
        BinaryPrimitives.WriteUInt64LittleEndian(entry.Slice(40, 8), startLba + (sizeBytes / SectorSize) - 1);
        Encoding.Unicode.GetBytes(name.AsSpan(), entry.Slice(56, 72));
    }

    private static void WriteContainerSuperblock(
        FileStream stream,
        ulong offsetBytes,
        ulong volumeObjectId,
        ulong checkpointXid)
    {
        Span<byte> block = stackalloc byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0x10, 8), checkpointXid);
        BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(0x20, 4), 0x4253584E);
        BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(0x24, 4), BlockSize);
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0x28, 8), 1024);
        ContainerUuid.TryWriteBytes(block.Slice(0x48, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0xA0, 8), 0x54);
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0xB8, 8), volumeObjectId);
        BinaryPrimitives.WriteUInt64LittleEndian(block, ComputeApfsObjectChecksum(block[8..]));

        stream.Position = checked((long)offsetBytes);
        stream.Write(block);
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> bytes)
    {
        var crc = uint.MaxValue;
        foreach (var value in bytes)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc >> 1) ^ (0xEDB88320u & (uint)-(int)(crc & 1));
            }
        }

        return ~crc;
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

    private sealed class TestDirectory : IDisposable
    {
        private TestDirectory(string path) => Path = path;

        public string Path { get; }

        public static TestDirectory Create()
        {
            var path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "ApfsAccessTests",
                "phase10-test-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return new TestDirectory(path);
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
