using System.Buffers.Binary;

namespace ApfsAccess.Backend.Native;

public static class SyntheticApfsTestImage
{
    public const int DefaultSizeMiB = 64;
    public const int MinSizeMiB = 4;
    public const int MaxSizeMiB = 1024;

    private const int BlockSize = 4096;
    private const ulong InitialCheckpointXid = 7;
    private const ulong SpacemanObjectId = 0x2A;
    private const ulong VolumeRootObjectId = 0x54;
    private const uint NxsbMagic = 0x4253584E;

    public static SyntheticApfsTestImageResult Create(string imagePath, int sizeMiB = DefaultSizeMiB)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(imagePath);
        if (IsRawPhysicalDevicePath(imagePath))
        {
            throw new ArgumentException("Test images must be normal files, not raw physical device paths.", nameof(imagePath));
        }

        if (!HasSupportedImageExtension(imagePath))
        {
            throw new ArgumentException("Test image path must end with .apfs.img or .img.", nameof(imagePath));
        }

        if (sizeMiB is < MinSizeMiB or > MaxSizeMiB)
        {
            throw new ArgumentOutOfRangeException(
                nameof(sizeMiB),
                sizeMiB,
                $"Test image size must be between {MinSizeMiB} MiB and {MaxSizeMiB} MiB.");
        }

        var fullPath = Path.GetFullPath(imagePath);
        if (File.Exists(fullPath))
        {
            throw new IOException($"Refusing to overwrite existing file: {fullPath}");
        }

        var parent = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(parent))
        {
            Directory.CreateDirectory(parent);
        }

        var sizeBytes = checked((long)sizeMiB * 1024L * 1024L);
        var totalBlocks = (ulong)(sizeBytes / BlockSize);
        using var stream = new FileStream(
            fullPath,
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize: BlockSize,
            FileOptions.RandomAccess);

        stream.SetLength(sizeBytes);
        WriteContainerSuperblock(stream, 0, totalBlocks);
        WriteContainerSuperblock(stream, BlockSize, totalBlocks);
        stream.Flush(flushToDisk: true);

        return new SyntheticApfsTestImageResult(
            ImagePath: fullPath,
            SizeBytes: sizeBytes,
            SizeMiB: sizeMiB,
            BlockSize: BlockSize,
            TotalBlocks: totalBlocks,
            InitialCheckpointXid: InitialCheckpointXid,
            SpacemanObjectId: SpacemanObjectId,
            VolumeRootObjectId: VolumeRootObjectId,
            MacOsCompatible: false,
            Notes: "Synthetic APFS-like test image for APFS Access image-backed validation; not a macOS-compatible formatter output yet.");
    }

    private static void WriteContainerSuperblock(FileStream stream, long offsetBytes, ulong totalBlocks)
    {
        Span<byte> block = stackalloc byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0x10, 8), InitialCheckpointXid);
        BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(0x20, 4), NxsbMagic);
        BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(0x24, 4), BlockSize);
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0x28, 8), totalBlocks);
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0x98, 8), SpacemanObjectId);
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0xA0, 8), VolumeRootObjectId);

        stream.Seek(offsetBytes, SeekOrigin.Begin);
        stream.Write(block);
    }

    private static bool HasSupportedImageExtension(string imagePath)
    {
        var normalized = imagePath.Trim().ToLowerInvariant();
        return normalized.EndsWith(".apfs.img", StringComparison.Ordinal) ||
               normalized.EndsWith(".img", StringComparison.Ordinal);
    }

    private static bool IsRawPhysicalDevicePath(string path)
        => path.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
           path.StartsWith(@"\\?\PhysicalDrive", StringComparison.OrdinalIgnoreCase);
}

public sealed record SyntheticApfsTestImageResult(
    string ImagePath,
    long SizeBytes,
    int SizeMiB,
    int BlockSize,
    ulong TotalBlocks,
    ulong InitialCheckpointXid,
    ulong SpacemanObjectId,
    ulong VolumeRootObjectId,
    bool MacOsCompatible,
    string Notes);
