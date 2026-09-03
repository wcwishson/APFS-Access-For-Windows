using System.Buffers.Binary;
using System.Text;

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
    private static readonly Guid ContainerUuid = new("A9CB92D2-8B7C-4B59-9EAB-633C7625F491");

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

    // ---- Task 1 catalog fixture writer (additive; legacy Create above untouched) ----
    //
    // Writes a GPT image whose APFS partitions each hold an NXSB checkpoint
    // pair + omap object + single-leaf omap btree + K APSB volume superblocks,
    // with byte offsets per task-1-interface-freeze.md section 5. Managed code
    // never parses these bytes back; the native observer cross-validates them.
    // Conventions: Guid bytes via Guid.TryWriteBytes (same as legacy Create);
    // block_size is fixed at 4096; object ids equal their block index for the
    // omap (2) and omap btree (3); volume oids default to 101+i.

    private const int CatalogSectorSize = 512;
    private const ulong CatalogNxsbObjectId = 1;
    private const ulong CatalogOmapObjectId = 2;
    private const ulong CatalogOmapBtreeObjectId = 3;
    private const int CatalogFirstVolumeBlock = 4;
    private const int CatalogSpareBlocks = 8;
    private const ulong CatalogFirstVolumeObjectId = 101;
    private const int CatalogMaxVolumesPerContainer = 100;
    private const int CatalogMaxPartitions = 512;
    private static readonly Guid CatalogApfsPartitionTypeGuid = new("7C3457EF-0000-11AA-AA11-00306543ECAC");

    public static CatalogFixtureResult CreateCatalogFixture(string imagePath, CatalogFixtureSpec? spec = null)
    {
        spec ??= new CatalogFixtureSpec();
        ArgumentException.ThrowIfNullOrWhiteSpace(imagePath);
        if (IsRawPhysicalDevicePath(imagePath))
        {
            throw new ArgumentException("Test images must be normal files, not raw physical device paths.", nameof(imagePath));
        }

        if (!HasSupportedImageExtension(imagePath))
        {
            throw new ArgumentException("Test image path must end with .apfs.img or .img.", nameof(imagePath));
        }

        if (spec.SizeMiB is < MinSizeMiB or > MaxSizeMiB)
        {
            throw new ArgumentOutOfRangeException(
                nameof(spec),
                spec.SizeMiB,
                $"Catalog fixture size must be between {MinSizeMiB} MiB and {MaxSizeMiB} MiB.");
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

        var requested = spec.Partitions is { Count: > 0 } ? spec.Partitions : [new CatalogPartitionSpec()];
        if (requested.Count > CatalogMaxPartitions)
        {
            throw new ArgumentOutOfRangeException(
                nameof(spec),
                requested.Count,
                $"Catalog fixture supports at most {CatalogMaxPartitions} partitions.");
        }

        var plans = requested.Select(ResolveCatalogPartitionPlan).ToArray();

        var sizeBytes = checked((long)spec.SizeMiB * 1024L * 1024L);
        var totalSectors = sizeBytes / CatalogSectorSize;
        var entriesBytes = checked((long)plans.Length * 128L);
        var entriesLbas = (entriesBytes + CatalogSectorSize - 1) / CatalogSectorSize;
        var firstUsableLba = AlignUp(2 + entriesLbas, 8);
        var nextLba = firstUsableLba;
        var starts = new long[plans.Length];
        var ends = new long[plans.Length];
        for (var i = 0; i < plans.Length; i++)
        {
            var sectors = checked(plans[i].TotalBlocks * (BlockSize / CatalogSectorSize));
            starts[i] = nextLba;
            ends[i] = checked(nextLba + sectors - 1);
            nextLba = AlignUp(ends[i] + 1, 8);
        }

        if (nextLba - 1 > totalSectors - 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(spec),
                spec.SizeMiB,
                "Catalog fixture partitions do not fit in the requested image size.");
        }

        var diskGuid = spec.DiskGuid != Guid.Empty ? spec.DiskGuid : Guid.NewGuid();
        long? truncateAt = null;

        using (var stream = new FileStream(
            fullPath,
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize: BlockSize,
            FileOptions.RandomAccess))
        {
            stream.SetLength(sizeBytes);
            WriteCatalogGpt(stream, diskGuid, plans, starts, ends, firstUsableLba, ends[^1], totalSectors - 1);
            for (var i = 0; i < plans.Length; i++)
            {
                var startByte = checked(starts[i] * CatalogSectorSize);
                WriteCatalogContainer(stream, startByte, plans[i]);
                if (plans[i].Corruption == CatalogCorruptionKind.BadChecksum)
                {
                    // Zero the stored Fletcher64 of the first volume APSB; the
                    // magic stays intact so the failure reads as a checksum
                    // mismatch on a needed (listed-volume) object.
                    stream.Seek(checked(startByte + CatalogFirstVolumeBlock * (long)BlockSize), SeekOrigin.Begin);
                    stream.Write(new byte[8]);
                }

                if (plans[i].Corruption == CatalogCorruptionKind.Truncate)
                {
                    var cut = checked(startByte + (CatalogFirstVolumeBlock + plans[i].Volumes.Count - 1) * (long)BlockSize + 512);
                    truncateAt = truncateAt.HasValue ? Math.Min(truncateAt.Value, cut) : cut;
                }
            }

            stream.Flush(flushToDisk: true);
            if (truncateAt.HasValue)
            {
                stream.SetLength(truncateAt.Value);
            }
        }

        var results = new CatalogPartitionResult[plans.Length];
        for (var i = 0; i < plans.Length; i++)
        {
            var volumes = new CatalogVolumeResult[plans[i].Volumes.Count];
            for (var v = 0; v < volumes.Length; v++)
            {
                volumes[v] = new CatalogVolumeResult(
                    plans[i].Volumes[v].Name,
                    plans[i].VolumeObjectIds[v],
                    CatalogFirstVolumeBlock + v,
                    plans[i].VolumeXids[v]);
            }

            results[i] = new CatalogPartitionResult(
                i + 1,
                plans[i].PartitionUuid,
                plans[i].Spec.Name,
                checked(starts[i] * CatalogSectorSize),
                checked(plans[i].TotalBlocks * (long)BlockSize),
                plans[i].ContainerUuid,
                plans[i].Spec.Xid,
                volumes);
        }

        return new CatalogFixtureResult(fullPath, sizeBytes, spec.SizeMiB, diskGuid, results);
    }

    private sealed record CatalogPartitionPlan(
        CatalogPartitionSpec Spec,
        IReadOnlyList<CatalogVolumeSpec> Volumes,
        Guid PartitionUuid,
        Guid ContainerUuid,
        ulong[] VolumeObjectIds,
        ulong[] VolumeXids,
        long TotalBlocks,
        CatalogCorruptionKind Corruption);

    private static CatalogPartitionPlan ResolveCatalogPartitionPlan(CatalogPartitionSpec spec)
    {
        var volumes = spec.Volumes ?? [new CatalogVolumeSpec()];
        if (volumes.Count > CatalogMaxVolumesPerContainer)
        {
            throw new ArgumentOutOfRangeException(
                nameof(spec),
                volumes.Count,
                $"Catalog fixture supports at most {CatalogMaxVolumesPerContainer} volumes per container.");
        }

        if (spec.Corruption != CatalogCorruptionKind.None && volumes.Count == 0)
        {
            throw new ArgumentException(
                $"Corruption '{spec.Corruption}' requires at least one volume.", nameof(spec));
        }

        if (spec.Corruption == CatalogCorruptionKind.DuplicateOid && volumes.Count < 2)
        {
            throw new ArgumentException(
                "Corruption 'DuplicateOid' requires at least two volumes.", nameof(spec));
        }

        if (Encoding.Unicode.GetByteCount(spec.Name) > 72)
        {
            throw new ArgumentException("Partition name must fit in 72 UTF-16 bytes.", nameof(spec));
        }

        foreach (var volume in volumes)
        {
            if (Encoding.UTF8.GetByteCount(volume.Name) > 255)
            {
                throw new ArgumentException(
                    $"Volume name '{volume.Name}' exceeds 255 UTF-8 bytes.", nameof(spec));
            }
        }

        var oids = new ulong[volumes.Count];
        for (var i = 0; i < volumes.Count; i++)
        {
            oids[i] = volumes[i].ObjectId != 0 ? volumes[i].ObjectId : checked(CatalogFirstVolumeObjectId + (ulong)i);
        }

        if (spec.Corruption == CatalogCorruptionKind.DuplicateOid)
        {
            oids[1] = oids[0];
        }

        var xids = new ulong[volumes.Count];
        for (var i = 0; i < volumes.Count; i++)
        {
            xids[i] = volumes[i].Xid != 0 ? volumes[i].Xid : spec.Xid;
        }

        if (spec.Corruption == CatalogCorruptionKind.StaleXid)
        {
            xids[0] = checked(spec.Xid + 1);
        }

        return new CatalogPartitionPlan(
            spec,
            volumes,
            spec.PartitionUuid != Guid.Empty ? spec.PartitionUuid : Guid.NewGuid(),
            spec.ContainerUuid != Guid.Empty ? spec.ContainerUuid : Guid.NewGuid(),
            oids,
            xids,
            checked(CatalogFirstVolumeBlock + volumes.Count + CatalogSpareBlocks),
            spec.Corruption);
    }

    private static long AlignUp(long value, long alignment)
        => alignment <= 0 ? value : ((value + alignment - 1) / alignment) * alignment;

    private static void WriteCatalogGpt(
        FileStream stream,
        Guid diskGuid,
        CatalogPartitionPlan[] plans,
        long[] starts,
        long[] ends,
        long firstUsableLba,
        long lastUsableLba,
        long backupLba)
    {
        var entries = new byte[checked(plans.Length * 128)];
        for (var i = 0; i < plans.Length; i++)
        {
            var entry = entries.AsSpan(i * 128, 128);
            CatalogApfsPartitionTypeGuid.TryWriteBytes(entry[..16]);
            plans[i].PartitionUuid.TryWriteBytes(entry.Slice(16, 16));
            BinaryPrimitives.WriteUInt64LittleEndian(entry.Slice(32, 8), (ulong)starts[i]);
            BinaryPrimitives.WriteUInt64LittleEndian(entry.Slice(40, 8), (ulong)ends[i]);
            BinaryPrimitives.WriteUInt64LittleEndian(entry.Slice(48, 8), 0);
            var nameBytes = Encoding.Unicode.GetBytes(plans[i].Spec.Name);
            nameBytes.CopyTo(entry.Slice(56, nameBytes.Length));
        }

        Span<byte> header = stackalloc byte[CatalogSectorSize];
        Encoding.ASCII.GetBytes("EFI PART").CopyTo(header);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(8, 4), 0x10000);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(12, 4), 92);
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(24, 8), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(32, 8), (ulong)backupLba);
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(40, 8), (ulong)firstUsableLba);
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(48, 8), (ulong)lastUsableLba);
        diskGuid.TryWriteBytes(header.Slice(56, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(72, 8), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(80, 4), (uint)plans.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(84, 4), 128);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(88, 4), ComputeGptCrc32(entries));
        BinaryPrimitives.WriteUInt32LittleEndian(
            header.Slice(16, 4), ComputeGptCrc32(header[..92]));

        stream.Seek(CatalogSectorSize, SeekOrigin.Begin);
        stream.Write(header);
        stream.Seek(2 * CatalogSectorSize, SeekOrigin.Begin);
        stream.Write(entries);
    }

    private static void WriteCatalogContainer(FileStream stream, long startByte, CatalogPartitionPlan plan)
    {
        var nxsb = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x08, 8), CatalogNxsbObjectId);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x10, 8), plan.Spec.Xid);
        BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x18, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x1C, 4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x20, 4), NxsbMagic);
        BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x24, 4), BlockSize);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x28, 8), (ulong)plan.TotalBlocks);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x30, 8), plan.Spec.Features);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x38, 8), plan.Spec.ReadonlyFeatures);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x40, 8), plan.Spec.IncompatibleFeatures);
        plan.ContainerUuid.TryWriteBytes(nxsb.AsSpan(0x48, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0xA0, 8), CatalogOmapObjectId);
        for (var i = 0; i < plan.VolumeObjectIds.Length; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0xB8 + i * 8, 8), plan.VolumeObjectIds[i]);
        }

        SealApfsBlock(nxsb);
        stream.Seek(startByte, SeekOrigin.Begin);
        stream.Write(nxsb);
        stream.Seek(startByte + BlockSize, SeekOrigin.Begin);
        stream.Write(nxsb);

        var omap = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(omap.AsSpan(0x08, 8), CatalogOmapObjectId);
        BinaryPrimitives.WriteUInt64LittleEndian(omap.AsSpan(0x10, 8), plan.Spec.Xid);
        BinaryPrimitives.WriteUInt32LittleEndian(omap.AsSpan(0x18, 4), 0xB);
        BinaryPrimitives.WriteUInt32LittleEndian(omap.AsSpan(0x1C, 4), 0);
        BinaryPrimitives.WriteUInt64LittleEndian(omap.AsSpan(0x30, 8), CatalogOmapBtreeObjectId);
        SealApfsBlock(omap);
        stream.Seek(startByte + 2 * BlockSize, SeekOrigin.Begin);
        stream.Write(omap);

        WriteCatalogOmapBtree(stream, startByte, plan);
        for (var i = 0; i < plan.Volumes.Count; i++)
        {
            WriteCatalogVolume(stream, startByte, plan, i);
        }
    }

    private static void WriteCatalogOmapBtree(FileStream stream, long startByte, CatalogPartitionPlan plan)
    {
        var count = plan.Volumes.Count;
        var node = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(node.AsSpan(0x08, 8), CatalogOmapBtreeObjectId);
        BinaryPrimitives.WriteUInt64LittleEndian(node.AsSpan(0x10, 8), plan.Spec.Xid);
        BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(0x18, 4), 0x3);
        BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(0x1C, 4), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x20, 2), 0x3);
        BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x22, 2), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(0x24, 4), (uint)count);
        BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x28, 2), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x2A, 2), checked((ushort)(count * 8)));
        BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x2C, 2), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x2E, 2), 0);

        const int valueAreaEnd = BlockSize - 40;
        for (var i = 0; i < count; i++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x38 + i * 8, 2), checked((ushort)(i * 16)));
            BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x38 + i * 8 + 2, 2), 16);
            BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x38 + i * 8 + 4, 2), checked((ushort)((i + 1) * 16)));
            BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x38 + i * 8 + 6, 2), 16);

            var key = 0x38 + count * 8 + i * 16;
            BinaryPrimitives.WriteUInt64LittleEndian(node.AsSpan(key, 8), plan.VolumeObjectIds[i]);
            BinaryPrimitives.WriteUInt64LittleEndian(node.AsSpan(key + 8, 8), plan.VolumeXids[i]);

            var value = valueAreaEnd - (i + 1) * 16;
            BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(value, 4), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(value + 4, 4), BlockSize);
            BinaryPrimitives.WriteUInt64LittleEndian(node.AsSpan(value + 8, 8), (ulong)(CatalogFirstVolumeBlock + i));
        }

        BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(valueAreaEnd + 8, 4), 16);
        BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(valueAreaEnd + 12, 4), 16);

        SealApfsBlock(node);
        stream.Seek(startByte + 3 * BlockSize, SeekOrigin.Begin);
        stream.Write(node);
    }

    private static void WriteCatalogVolume(FileStream stream, long startByte, CatalogPartitionPlan plan, int index)
    {
        var volume = plan.Volumes[index];
        var apsb = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x08, 8), plan.VolumeObjectIds[index]);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x10, 8), plan.VolumeXids[index]);
        BinaryPrimitives.WriteUInt32LittleEndian(apsb.AsSpan(0x18, 4), 0xD);
        BinaryPrimitives.WriteUInt32LittleEndian(apsb.AsSpan(0x1C, 4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(apsb.AsSpan(0x20, 4), 0x42535041);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x28, 8), volume.Features);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x30, 8), volume.ReadonlyFeatures);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x38, 8), volume.IncompatibleFeatures);
        BinaryPrimitives.WriteUInt64LittleEndian(
            apsb.AsSpan(0x80, 8), volume.OmapOid != 0 ? volume.OmapOid : (0x1000 + (ulong)index));
        BinaryPrimitives.WriteUInt64LittleEndian(
            apsb.AsSpan(0x88, 8), volume.RootOid != 0 ? volume.RootOid : (0x2000 + (ulong)index));
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0xB8, 8), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0xC0, 8), 1);
        if (volume.VolumeUuid != Guid.Empty)
        {
            volume.VolumeUuid.TryWriteBytes(apsb.AsSpan(0xF0, 16));
        }

        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x108, 8), volume.FsFlags);
        Encoding.UTF8.GetBytes(volume.Name).CopyTo(apsb.AsSpan(0x120));
        BinaryPrimitives.WriteUInt16LittleEndian(apsb.AsSpan(0x224, 2), volume.Role);
        if (volume.GroupUuid != Guid.Empty)
        {
            volume.GroupUuid.TryWriteBytes(apsb.AsSpan(0x228, 16));
        }

        SealApfsBlock(apsb);
        stream.Seek(startByte + (CatalogFirstVolumeBlock + index) * (long)BlockSize, SeekOrigin.Begin);
        stream.Write(apsb);
    }

    private static void SealApfsBlock(byte[] block)
        => BinaryPrimitives.WriteUInt64LittleEndian(block, ComputeApfsObjectChecksum(block.AsSpan(8)));

    private static uint ComputeGptCrc32(ReadOnlySpan<byte> bytes)
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

    private static void WriteContainerSuperblock(FileStream stream, long offsetBytes, ulong totalBlocks)
    {
        Span<byte> block = stackalloc byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0x10, 8), InitialCheckpointXid);
        BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(0x20, 4), NxsbMagic);
        BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(0x24, 4), BlockSize);
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0x28, 8), totalBlocks);
        ContainerUuid.TryWriteBytes(block.Slice(0x48, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0x98, 8), SpacemanObjectId);
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0xA0, 8), VolumeRootObjectId);
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0xB8, 8), VolumeRootObjectId);
        BinaryPrimitives.WriteUInt64LittleEndian(block, ComputeApfsObjectChecksum(block[8..]));

        stream.Seek(offsetBytes, SeekOrigin.Begin);
        stream.Write(block);
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

// ---- Task 1 catalog fixture surface (test-fixture WRITER, not a parser) ----

public enum CatalogCorruptionKind
{
    None = 0,
    BadChecksum = 1,
    Truncate = 2,
    StaleXid = 3,
    DuplicateOid = 4,
}

public sealed record CatalogVolumeSpec(
    string Name = "Data",
    ushort Role = 32,
    Guid VolumeUuid = default,
    Guid GroupUuid = default,
    ulong ObjectId = 0,
    ulong Features = 0,
    ulong ReadonlyFeatures = 0,
    ulong IncompatibleFeatures = 0,
    ulong FsFlags = 0x1,
    ulong Xid = 0,
    ulong OmapOid = 0,
    ulong RootOid = 0);

public sealed record CatalogPartitionSpec(
    string Name = "APFS",
    Guid PartitionUuid = default,
    Guid ContainerUuid = default,
    ulong Features = 0,
    ulong ReadonlyFeatures = 0,
    ulong IncompatibleFeatures = 0,
    ulong Xid = 7,
    IReadOnlyList<CatalogVolumeSpec>? Volumes = null,
    CatalogCorruptionKind Corruption = CatalogCorruptionKind.None);

public sealed record CatalogFixtureSpec(
    int SizeMiB = 16,
    IReadOnlyList<CatalogPartitionSpec>? Partitions = null,
    Guid DiskGuid = default);

public sealed record CatalogVolumeResult(
    string Name,
    ulong ObjectId,
    long SuperblockBlock,
    ulong Xid);

public sealed record CatalogPartitionResult(
    int Index,
    Guid PartitionUuid,
    string Name,
    long StartByte,
    long SizeBytes,
    Guid ContainerUuid,
    ulong CheckpointXid,
    IReadOnlyList<CatalogVolumeResult> Volumes);

public sealed record CatalogFixtureResult(
    string ImagePath,
    long SizeBytes,
    int SizeMiB,
    Guid DiskGuid,
    IReadOnlyList<CatalogPartitionResult> Partitions);
