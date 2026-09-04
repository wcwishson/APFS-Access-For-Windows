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
    // Writes a GPT image whose APFS partitions each hold one descriptor-ring
    // checkpoint plus the typed object graph needed by the strict native
    // observer. Managed code never parses these bytes back; byte-level tests
    // and the native observer independently cross-validate them.
    // Conventions: Guid bytes via Guid.TryWriteBytes (same as legacy Create);
    // block_size is fixed at 4096; object ids equal their block index for the
    // omap (2) and omap btree (3); volume oids default to 101+i.

    private const int CatalogSectorSize = 512;
    private const ulong CatalogNxsbObjectId = 1;
    private const ulong CatalogOmapObjectId = 2;
    private const ulong CatalogOmapBtreeObjectId = 3;
    private const int CatalogFirstVolumeBlock = 4;
    private const int CatalogPerVolumeObjectBlocks = 6;
    private const int CatalogCheckpointDescriptorBlocks = 4;
    private const int CatalogCheckpointDataBlocks = 4;
    private const int CatalogFixedBlocks = 15;
    private const ulong CatalogSpacemanObjectId = 0x4000;
    private const ulong CatalogFreeQueueObjectId = 0x4001;
    private const ulong CatalogMainFreeQueueObjectId = 0x4002;
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
            checked(CatalogFixedBlocks + volumes.Count * (1 + CatalogPerVolumeObjectBlocks)),
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
        var volumeLayoutBase = checked(CatalogFirstVolumeBlock + plan.Volumes.Count);
        var descriptorBase = checked(volumeLayoutBase + plan.Volumes.Count * CatalogPerVolumeObjectBlocks);
        var dataBase = checked(descriptorBase + CatalogCheckpointDescriptorBlocks);
        var internalPoolBitmapBlock = checked(dataBase + CatalogCheckpointDataBlocks);
        var internalPoolBase = checked(internalPoolBitmapBlock + 1);
        var cibBlock = internalPoolBase;
        var chunkBitmapBlock = checked(internalPoolBase + 1);

        WriteCatalogBlock(stream, startByte, 0, BuildCatalogNxsb(plan, selected: false, descriptorBase, dataBase));
        WriteCatalogOmap(stream, startByte, CatalogOmapObjectId, CatalogOmapBtreeObjectId, plan.Spec.Xid);
        WriteCatalogOmapBtree(stream, startByte, plan);
        for (var i = 0; i < plan.Volumes.Count; i++)
        {
            WriteCatalogVolume(stream, startByte, plan, i, checked(volumeLayoutBase + i * CatalogPerVolumeObjectBlocks));
        }

        WriteCatalogCheckpointMap(stream, startByte, descriptorBase, dataBase, plan.Spec.Xid);
        WriteCatalogBlock(
            stream,
            startByte,
            descriptorBase + 1,
            BuildCatalogNxsb(plan, selected: true, descriptorBase, dataBase));
        var chunkBitmap = BuildCatalogAllocationBitmap(
            plan,
            volumeLayoutBase,
            descriptorBase,
            dataBase,
            internalPoolBitmapBlock,
            internalPoolBase);
        var allocatedBlocks = CountSetBits(chunkBitmap, plan.TotalBlocks);
        WriteCatalogSpaceman(
            stream,
            startByte,
            dataBase,
            plan.Spec.Xid,
            plan.TotalBlocks,
            allocatedBlocks,
            internalPoolBitmapBlock,
            internalPoolBase,
            cibBlock);
        WriteCatalogFreeQueue(stream, startByte, dataBase + 1, CatalogFreeQueueObjectId, plan.Spec.Xid);
        WriteCatalogFreeQueue(stream, startByte, dataBase + 2, CatalogMainFreeQueueObjectId, plan.Spec.Xid);
        WriteCatalogCib(
            stream,
            startByte,
            cibBlock,
            chunkBitmapBlock,
            plan.Spec.Xid,
            plan.TotalBlocks,
            allocatedBlocks);
        var internalPoolBitmap = new byte[BlockSize];
        SetBitmapBit(internalPoolBitmap, 0);
        SetBitmapBit(internalPoolBitmap, 1);
        WriteCatalogBlock(stream, startByte, internalPoolBitmapBlock, internalPoolBitmap);
        WriteCatalogBlock(stream, startByte, chunkBitmapBlock, chunkBitmap);
    }

    private static byte[] BuildCatalogNxsb(
        CatalogPartitionPlan plan,
        bool selected,
        int descriptorBase,
        int dataBase)
    {
        var nxsb = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x08, 8), CatalogNxsbObjectId);
        BinaryPrimitives.WriteUInt64LittleEndian(
            nxsb.AsSpan(0x10, 8), selected || plan.Spec.Xid == 0 ? plan.Spec.Xid : plan.Spec.Xid - 1);
        BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x18, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x20, 4), NxsbMagic);
        BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x24, 4), BlockSize);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x28, 8), (ulong)plan.TotalBlocks);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x30, 8), plan.Spec.Features);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x38, 8), plan.Spec.ReadonlyFeatures);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x40, 8), plan.Spec.IncompatibleFeatures);
        plan.ContainerUuid.TryWriteBytes(nxsb.AsSpan(0x48, 16));
        BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x68, 4), CatalogCheckpointDescriptorBlocks);
        BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x6C, 4), CatalogCheckpointDataBlocks);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x70, 8), (ulong)descriptorBase);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x78, 8), (ulong)dataBase);
        if (selected)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x80, 4), 2);
            BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x84, 4), 3);
            BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x8C, 4), 2);
            BinaryPrimitives.WriteUInt32LittleEndian(nxsb.AsSpan(0x94, 4), 3);
        }

        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0x98, 8), CatalogSpacemanObjectId);
        BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0xA0, 8), CatalogOmapObjectId);
        BinaryPrimitives.WriteUInt32LittleEndian(
            nxsb.AsSpan(0xB4, 4), (uint)Math.Max(1, plan.VolumeObjectIds.Length));
        for (var i = 0; i < plan.VolumeObjectIds.Length; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(nxsb.AsSpan(0xB8 + i * 8, 8), plan.VolumeObjectIds[i]);
        }

        SealApfsBlock(nxsb);
        return nxsb;
    }

    private static void WriteCatalogOmap(
        FileStream stream,
        long startByte,
        ulong objectId,
        ulong treeBlock,
        ulong xid)
    {
        var omap = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(omap.AsSpan(0x08, 8), objectId);
        BinaryPrimitives.WriteUInt64LittleEndian(omap.AsSpan(0x10, 8), xid);
        BinaryPrimitives.WriteUInt32LittleEndian(omap.AsSpan(0x18, 4), 0x4000000B);
        BinaryPrimitives.WriteUInt32LittleEndian(omap.AsSpan(0x28, 4), 0x40000002);
        BinaryPrimitives.WriteUInt64LittleEndian(omap.AsSpan(0x30, 8), treeBlock);
        SealApfsBlock(omap);
        WriteCatalogBlock(stream, startByte, checked((int)objectId), omap);
    }

    private static void WriteCatalogOmapBtree(FileStream stream, long startByte, CatalogPartitionPlan plan)
    {
        var records = new CatalogOmapRecord[plan.Volumes.Count];
        for (var i = 0; i < records.Length; i++)
        {
            records[i] = new CatalogOmapRecord(
                plan.VolumeObjectIds[i], plan.VolumeXids[i], (ulong)(CatalogFirstVolumeBlock + i));
        }

        WriteCatalogOmapLeaf(
            stream, startByte, CatalogOmapBtreeObjectId, plan.Spec.Xid, records);
    }

    private static void WriteCatalogVolume(
        FileStream stream,
        long startByte,
        CatalogPartitionPlan plan,
        int index,
        int layoutBlock)
    {
        var volume = plan.Volumes[index];
        var volumeOid = plan.VolumeObjectIds[index];
        var volumeXid = plan.VolumeXids[index];
        var volumeOmapBlock = layoutBlock;
        var volumeOmapTreeBlock = checked(layoutBlock + 1);
        var rootBlock = checked(layoutBlock + 2);
        var extentrefBlock = checked(layoutBlock + 3);
        var snapshotBlock = checked(layoutBlock + 4);
        var rootOid = volume.RootOid != 0 ? volume.RootOid : checked(0x2000UL + volumeOid);
        var snapshotOid = checked(0x3000UL + volumeOid);
        var apsb = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x08, 8), volumeOid);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x10, 8), volumeXid);
        BinaryPrimitives.WriteUInt32LittleEndian(apsb.AsSpan(0x18, 4), 0xD);
        BinaryPrimitives.WriteUInt32LittleEndian(apsb.AsSpan(0x20, 4), 0x42535041);
        BinaryPrimitives.WriteUInt32LittleEndian(apsb.AsSpan(0x24, 4), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x28, 8), volume.Features);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x30, 8), volume.ReadonlyFeatures);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x38, 8), volume.IncompatibleFeatures);
        BinaryPrimitives.WriteUInt32LittleEndian(apsb.AsSpan(0x74, 4), 0x00000002);
        BinaryPrimitives.WriteUInt32LittleEndian(apsb.AsSpan(0x78, 4), 0x40000002);
        BinaryPrimitives.WriteUInt32LittleEndian(apsb.AsSpan(0x7C, 4), 0x00000002);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x80, 8), (ulong)volumeOmapBlock);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x88, 8), rootOid);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x90, 8), (ulong)extentrefBlock);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x98, 8), snapshotOid);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0xB8, 8), 11);
        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0xC0, 8), 3);
        if (volume.VolumeUuid != Guid.Empty)
        {
            volume.VolumeUuid.TryWriteBytes(apsb.AsSpan(0xF0, 16));
        }

        BinaryPrimitives.WriteUInt64LittleEndian(apsb.AsSpan(0x108, 8), volume.FsFlags);
        Encoding.UTF8.GetBytes(volume.Name).CopyTo(apsb.AsSpan(0x2C0));
        BinaryPrimitives.WriteUInt16LittleEndian(apsb.AsSpan(0x3C4, 2), volume.Role);
        if (volume.GroupUuid != Guid.Empty)
        {
            volume.GroupUuid.TryWriteBytes(apsb.AsSpan(0x3F0, 16));
        }

        SealApfsBlock(apsb);
        WriteCatalogBlock(stream, startByte, CatalogFirstVolumeBlock + index, apsb);

        WriteCatalogOmap(stream, startByte, (ulong)volumeOmapBlock, (ulong)volumeOmapTreeBlock, volumeXid);
        WriteCatalogOmapLeaf(
            stream,
            startByte,
            (ulong)volumeOmapTreeBlock,
            volumeXid,
            [
                new CatalogOmapRecord(rootOid, volumeXid, (ulong)rootBlock),
                new CatalogOmapRecord(snapshotOid, volumeXid, (ulong)snapshotBlock),
            ]);

        var inodeKey = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(inodeKey, 2UL | (3UL << 60));
        var inodeValue = new byte[0x60];
        BinaryPrimitives.WriteUInt64LittleEndian(inodeValue.AsSpan(0, 8), 2);
        BinaryPrimitives.WriteUInt64LittleEndian(inodeValue.AsSpan(8, 8), 9);
        inodeValue[0x50] = 0xED;
        inodeValue[0x51] = 0x41;
        WriteCatalogTypedLeaf(
            stream,
            startByte,
            rootBlock,
            rootOid,
            volumeXid,
            0x00000002,
            0xE,
            [new CatalogLeafRecord(inodeKey, inodeValue)]);
        WriteCatalogTypedLeaf(
            stream, startByte, extentrefBlock, (ulong)extentrefBlock, volumeXid, 0x40000002, 0xF, []);
        WriteCatalogTypedLeaf(
            stream, startByte, snapshotBlock, snapshotOid, volumeXid, 0x00000002, 0x10, []);
    }

    private static void WriteCatalogCheckpointMap(
        FileStream stream,
        long startByte,
        int descriptorBlock,
        int dataBlock,
        ulong xid)
    {
        var map = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(map.AsSpan(0x08, 8), checked((ulong)descriptorBlock));
        BinaryPrimitives.WriteUInt64LittleEndian(map.AsSpan(0x10, 8), xid);
        BinaryPrimitives.WriteUInt32LittleEndian(map.AsSpan(0x18, 4), 0x4000000C);
        BinaryPrimitives.WriteUInt32LittleEndian(map.AsSpan(0x20, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(map.AsSpan(0x24, 4), 3);
        WriteCheckpointMapping(map, 0x28, 0x80000005, 0, CatalogSpacemanObjectId, (ulong)dataBlock);
        WriteCheckpointMapping(map, 0x50, 0x80000002, 0x9, CatalogFreeQueueObjectId, (ulong)(dataBlock + 1));
        WriteCheckpointMapping(map, 0x78, 0x80000002, 0x9, CatalogMainFreeQueueObjectId, (ulong)(dataBlock + 2));
        SealApfsBlock(map);
        WriteCatalogBlock(stream, startByte, descriptorBlock, map);
    }

    private static void WriteCheckpointMapping(
        byte[] map,
        int offset,
        uint type,
        uint subtype,
        ulong objectId,
        ulong physicalBlock)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(map.AsSpan(offset, 4), type);
        BinaryPrimitives.WriteUInt32LittleEndian(map.AsSpan(offset + 4, 4), subtype);
        BinaryPrimitives.WriteUInt32LittleEndian(map.AsSpan(offset + 8, 4), BlockSize);
        BinaryPrimitives.WriteUInt64LittleEndian(map.AsSpan(offset + 0x18, 8), objectId);
        BinaryPrimitives.WriteUInt64LittleEndian(map.AsSpan(offset + 0x20, 8), physicalBlock);
    }

    private static void WriteCatalogSpaceman(
        FileStream stream,
        long startByte,
        int block,
        ulong xid,
        long totalBlocks,
        long allocatedBlocks,
        int internalPoolBitmapBlock,
        int internalPoolBase,
        int cibBlock)
    {
        var spaceman = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(spaceman.AsSpan(0x08, 8), CatalogSpacemanObjectId);
        BinaryPrimitives.WriteUInt64LittleEndian(spaceman.AsSpan(0x10, 8), xid);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x18, 4), 0x80000005);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x20, 4), BlockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x24, 4), BlockSize * 8);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x28, 4), (BlockSize - 0x28) / 0x20);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x2C, 4), (BlockSize - 0x28) / 8);
        BinaryPrimitives.WriteUInt64LittleEndian(spaceman.AsSpan(0x30, 8), checked((ulong)totalBlocks));
        BinaryPrimitives.WriteUInt64LittleEndian(spaceman.AsSpan(0x38, 8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x40, 4), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(
            spaceman.AsSpan(0x48, 8), checked((ulong)(totalBlocks - allocatedBlocks)));
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x50, 4), 0x600);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x94, 4), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(spaceman.AsSpan(0x98, 8), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0xA0, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0xA4, 4), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(
            spaceman.AsSpan(0xA8, 8), checked((ulong)internalPoolBitmapBlock));
        BinaryPrimitives.WriteUInt64LittleEndian(
            spaceman.AsSpan(0xB0, 8), checked((ulong)internalPoolBase));
        BinaryPrimitives.WriteUInt64LittleEndian(spaceman.AsSpan(0xC0, 8), 0xDEADBEEFDEADBEEFUL);
        BinaryPrimitives.WriteUInt64LittleEndian(spaceman.AsSpan(0xD0, 8), CatalogFreeQueueObjectId);
        BinaryPrimitives.WriteUInt16LittleEndian(spaceman.AsSpan(0xE0, 2), 64);
        BinaryPrimitives.WriteUInt64LittleEndian(spaceman.AsSpan(0xF8, 8), CatalogMainFreeQueueObjectId);
        BinaryPrimitives.WriteUInt16LittleEndian(spaceman.AsSpan(0x108, 2), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(spaceman.AsSpan(0x140, 2), 0xFFFF);
        BinaryPrimitives.WriteUInt16LittleEndian(spaceman.AsSpan(0x142, 2), 0xFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x144, 4), 0x700);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x148, 4), 0x708);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x14C, 4), 0x720);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x150, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(spaceman.AsSpan(0x154, 4), 0x800);
        BinaryPrimitives.WriteUInt64LittleEndian(spaceman.AsSpan(0x600, 8), checked((ulong)cibBlock));
        BinaryPrimitives.WriteUInt64LittleEndian(spaceman.AsSpan(0x700, 8), xid);
        BinaryPrimitives.WriteUInt16LittleEndian(spaceman.AsSpan(0x708, 2), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(spaceman.AsSpan(0x720, 2), 0xFFFF);
        SealApfsBlock(spaceman);
        WriteCatalogBlock(stream, startByte, block, spaceman);
    }

    private static void WriteCatalogFreeQueue(
        FileStream stream,
        long startByte,
        int block,
        ulong objectId,
        ulong xid)
    {
        WriteCatalogTypedLeaf(
            stream,
            startByte,
            block,
            objectId,
            xid,
            0x80000002,
            0x9,
            [],
            fixedKeyValue: true);
    }

    private static void WriteCatalogCib(
        FileStream stream,
        long startByte,
        int block,
        int chunkBitmapBlock,
        ulong xid,
        long totalBlocks,
        long allocatedBlocks)
    {
        var cib = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(cib.AsSpan(0x08, 8), checked((ulong)block));
        BinaryPrimitives.WriteUInt64LittleEndian(cib.AsSpan(0x10, 8), xid);
        BinaryPrimitives.WriteUInt32LittleEndian(cib.AsSpan(0x18, 4), 0x40000007);
        BinaryPrimitives.WriteUInt32LittleEndian(cib.AsSpan(0x20, 4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(cib.AsSpan(0x24, 4), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(cib.AsSpan(0x28, 8), xid);
        BinaryPrimitives.WriteUInt64LittleEndian(cib.AsSpan(0x30, 8), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(cib.AsSpan(0x38, 4), checked((uint)totalBlocks));
        BinaryPrimitives.WriteUInt32LittleEndian(
            cib.AsSpan(0x3C, 4), checked((uint)(totalBlocks - allocatedBlocks)));
        BinaryPrimitives.WriteUInt64LittleEndian(cib.AsSpan(0x40, 8), checked((ulong)chunkBitmapBlock));
        SealApfsBlock(cib);
        WriteCatalogBlock(stream, startByte, block, cib);
    }

    private static byte[] BuildCatalogAllocationBitmap(
        CatalogPartitionPlan plan,
        int volumeLayoutBase,
        int descriptorBase,
        int dataBase,
        int internalPoolBitmapBlock,
        int internalPoolBase)
    {
        var bitmap = new byte[BlockSize];
        SetBitmapBit(bitmap, 0);
        SetBitmapBit(bitmap, CatalogOmapObjectId);
        SetBitmapBit(bitmap, CatalogOmapBtreeObjectId);
        for (var index = 0; index < plan.Volumes.Count; index++)
        {
            SetBitmapBit(bitmap, checked((ulong)(CatalogFirstVolumeBlock + index)));
            var layout = checked(volumeLayoutBase + index * CatalogPerVolumeObjectBlocks);
            for (var offset = 0; offset < 5; offset++)
            {
                SetBitmapBit(bitmap, checked((ulong)(layout + offset)));
            }
        }

        for (var offset = 0; offset < CatalogCheckpointDescriptorBlocks; offset++)
        {
            SetBitmapBit(bitmap, checked((ulong)(descriptorBase + offset)));
        }

        for (var offset = 0; offset < CatalogCheckpointDataBlocks; offset++)
        {
            SetBitmapBit(bitmap, checked((ulong)(dataBase + offset)));
        }

        SetBitmapBit(bitmap, checked((ulong)internalPoolBitmapBlock));
        SetBitmapBit(bitmap, checked((ulong)internalPoolBase));
        SetBitmapBit(bitmap, checked((ulong)(internalPoolBase + 1)));
        return bitmap;
    }

    private static void SetBitmapBit(byte[] bitmap, ulong bit)
        => bitmap[checked((int)(bit / 8))] |= checked((byte)(1u << checked((int)(bit % 8))));

    private static long CountSetBits(byte[] bitmap, long bitCount)
    {
        var count = 0;
        for (var bit = 0; bit < bitCount; bit++)
        {
            if ((bitmap[bit / 8] & (1 << (bit % 8))) != 0)
            {
                count++;
            }
        }

        return count;
    }

    private static void WriteCatalogOmapLeaf(
        FileStream stream,
        long startByte,
        ulong block,
        ulong xid,
        IReadOnlyList<CatalogOmapRecord> mappings)
    {
        var records = new CatalogLeafRecord[mappings.Count];
        for (var i = 0; i < mappings.Count; i++)
        {
            var key = new byte[16];
            BinaryPrimitives.WriteUInt64LittleEndian(key.AsSpan(0, 8), mappings[i].ObjectId);
            BinaryPrimitives.WriteUInt64LittleEndian(key.AsSpan(8, 8), mappings[i].Xid);
            var value = new byte[16];
            BinaryPrimitives.WriteUInt32LittleEndian(value.AsSpan(4, 4), BlockSize);
            BinaryPrimitives.WriteUInt64LittleEndian(value.AsSpan(8, 8), mappings[i].PhysicalBlock);
            records[i] = new CatalogLeafRecord(key, value);
        }

        WriteCatalogTypedLeaf(
            stream,
            startByte,
            checked((int)block),
            block,
            xid,
            0x40000002,
            0xB,
            records);
    }

    private static void WriteCatalogTypedLeaf(
        FileStream stream,
        long startByte,
        int block,
        ulong objectId,
        ulong xid,
        uint objectType,
        uint objectSubtype,
        IReadOnlyList<CatalogLeafRecord> records,
        bool fixedKeyValue = false)
    {
        var node = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(node.AsSpan(0x08, 8), objectId);
        BinaryPrimitives.WriteUInt64LittleEndian(node.AsSpan(0x10, 8), xid);
        BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(0x18, 4), objectType);
        BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(0x1C, 4), objectSubtype);
        BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x20, 2), fixedKeyValue ? (ushort)0x7 : (ushort)0x3);
        BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(0x24, 4), checked((uint)records.Count));
        BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x2A, 2), checked((ushort)(records.Count * 8)));

        var keyArea = checked(0x38 + records.Count * 8);
        var keyCursor = 0;
        var valuePrefix = 0;
        for (var i = 0; i < records.Count; i++)
        {
            valuePrefix = checked(valuePrefix + records[i].Value.Length);
            var table = 0x38 + i * 8;
            BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(table, 2), checked((ushort)keyCursor));
            BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(table + 2, 2), checked((ushort)records[i].Key.Length));
            BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(table + 4, 2), checked((ushort)valuePrefix));
            BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(table + 6, 2), checked((ushort)records[i].Value.Length));
            keyCursor = checked(keyCursor + records[i].Key.Length);
        }

        var keyWrite = keyArea;
        foreach (var record in records)
        {
            record.Key.CopyTo(node.AsSpan(keyWrite));
            keyWrite = checked(keyWrite + record.Key.Length);
        }

        const int infoStart = BlockSize - 40;
        var prefix = 0;
        foreach (var record in records)
        {
            prefix = checked(prefix + record.Value.Length);
            record.Value.CopyTo(node.AsSpan(infoStart - prefix));
        }

        var valuesStart = infoStart - prefix;
        if (keyWrite > valuesStart)
        {
            throw new InvalidOperationException("Catalog fixture B-tree records exceed one block.");
        }

        BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x2C, 2), checked((ushort)(keyWrite - keyArea)));
        BinaryPrimitives.WriteUInt16LittleEndian(node.AsSpan(0x2E, 2), checked((ushort)(valuesStart - keyWrite)));
        var storageType = objectType & 0xC0000000u;
        BinaryPrimitives.WriteUInt32LittleEndian(
            node.AsSpan(infoStart, 4),
            fixedKeyValue ? 0x0000000Fu : storageType == 0x40000000u ? 0x50u : storageType == 0x80000000u ? 0x48u : 0x40u);
        BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(infoStart + 4, 4), BlockSize);
        if (fixedKeyValue)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(infoStart + 8, 4), 16);
            BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(infoStart + 12, 4), 8);
            BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(infoStart + 16, 4), 16);
            BinaryPrimitives.WriteUInt32LittleEndian(node.AsSpan(infoStart + 20, 4), 8);
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(
                node.AsSpan(infoStart + 16, 4),
                checked((uint)(records.Count == 0 ? 0 : records.Max(static record => record.Key.Length))));
            BinaryPrimitives.WriteUInt32LittleEndian(
                node.AsSpan(infoStart + 20, 4),
                checked((uint)(records.Count == 0 ? 0 : records.Max(static record => record.Value.Length))));
        }

        BinaryPrimitives.WriteUInt64LittleEndian(node.AsSpan(infoStart + 24, 8), checked((ulong)records.Count));
        BinaryPrimitives.WriteUInt64LittleEndian(node.AsSpan(infoStart + 32, 8), 1);
        SealApfsBlock(node);
        WriteCatalogBlock(stream, startByte, block, node);
    }

    private static void WriteCatalogBlock(FileStream stream, long startByte, int block, byte[] bytes)
    {
        stream.Seek(checked(startByte + block * (long)BlockSize), SeekOrigin.Begin);
        stream.Write(bytes);
    }

    private readonly record struct CatalogOmapRecord(ulong ObjectId, ulong Xid, ulong PhysicalBlock);

    private readonly record struct CatalogLeafRecord(byte[] Key, byte[] Value);

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
    ushort Role = 0x40,
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
