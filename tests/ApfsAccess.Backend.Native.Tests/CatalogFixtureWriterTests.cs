using System.Buffers.Binary;
using System.Text;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Backend.Native.Tests;

// Byte-level writer tests. These assert raw facts at freeze-specified offsets
// (magic values, Fletcher64/GPT-CRC32 recomputed by independent local copies,
// entry layouts) WITHOUT parsing APFS structures. The native observer (built
// later) cross-validates the same fixtures.
public sealed class CatalogFixtureWriterTests
{
    private const int SectorSize = 512;
    private const int BlockSize = 4096;

    private static readonly byte[] ExpectedApfsTypeGuidBytes =
    [
        0xEF, 0x57, 0x34, 0x7C, 0x00, 0x00, 0xAA, 0x11,
        0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC,
    ];

    [Fact]
    public void Crc32_MatchesStandardCheckValue()
    {
        // IEEE CRC32 check value for "123456789" (freeze section 5).
        Assert.Equal(0xCBF43926u, ComputeCrc32("123456789"u8));
    }

    [Fact]
    public void CreateCatalogFixture_SinglePartitionSingleVolume_ByteLayout()
    {
        using var temp = CatalogTemp.Create();
        var imagePath = temp.File("single.apfs.img");
        var partitionGuid = new Guid("11111111-2222-3333-4444-555555555555");
        var containerGuid = new Guid("a9cb92d2-8b7c-4b59-9eab-633c7625f491");
        var volumeGuid = new Guid("c3d4e5f6-0718-293a-4b5c-6d7e8f90a1b2");
        var diskGuid = new Guid("99999999-8888-7777-6666-555555555555");

        var result = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(
                SizeMiB: 16,
                Partitions:
                [
                    new CatalogPartitionSpec(
                        Name: "TestContainer",
                        PartitionUuid: partitionGuid,
                        ContainerUuid: containerGuid,
                        Xid: 7,
                        Volumes:
                        [
                            new CatalogVolumeSpec(
                                Name: "Data",
                                Role: 32,
                                VolumeUuid: volumeGuid,
                                FsFlags: 0x1,
                                Features: 0x1),
                        ]),
                ],
                DiskGuid: diskGuid));

        Assert.Equal(Path.GetFullPath(imagePath), result.ImagePath);
        Assert.Equal(16 * 1024 * 1024, result.SizeBytes);
        Assert.Equal(diskGuid, result.DiskGuid);
        var part = Assert.Single(result.Partitions);
        Assert.Equal(1, part.Index);
        Assert.Equal(partitionGuid, part.PartitionUuid);
        Assert.Equal(4096L, part.StartByte);
        Assert.Equal((4 + 1 + 8) * BlockSize, part.SizeBytes);
        Assert.Equal(containerGuid, part.ContainerUuid);
        Assert.Equal(7UL, part.CheckpointXid);
        var vol = Assert.Single(part.Volumes);
        Assert.Equal("Data", vol.Name);
        Assert.Equal(101UL, vol.ObjectId);
        Assert.Equal(4L, vol.SuperblockBlock);
        Assert.Equal(7UL, vol.Xid);

        var image = File.ReadAllBytes(imagePath);
        Assert.Equal(16 * 1024 * 1024, image.Length);

        // GPT header @ LBA1.
        Assert.Equal("EFI PART"u8.ToArray(), image.AsSpan(512, 8).ToArray());
        Assert.Equal(0x10000u, ReadU32(image, 512 + 8));
        Assert.Equal(92u, ReadU32(image, 512 + 12));
        Assert.Equal(1UL, ReadU64(image, 512 + 24));
        Assert.Equal(32767UL, ReadU64(image, 512 + 32));
        Assert.Equal(8UL, ReadU64(image, 512 + 40));
        Assert.Equal(111UL, ReadU64(image, 512 + 48));
        Assert.Equal(diskGuid.ToByteArray(), image.AsSpan(512 + 56, 16).ToArray());
        Assert.Equal(2UL, ReadU64(image, 512 + 72));
        Assert.Equal(1u, ReadU32(image, 512 + 80));
        Assert.Equal(128u, ReadU32(image, 512 + 84));
        AssertValidGptCrc(image, headerOffset: 512, entriesOffset: 2 * SectorSize, entriesBytes: 128);

        // GPT entry 0: APFS type GUID bytes exactly per freeze section 5.
        var entry = 2 * SectorSize;
        Assert.Equal(ExpectedApfsTypeGuidBytes, image.AsSpan(entry, 16).ToArray());
        Assert.Equal(partitionGuid.ToByteArray(), image.AsSpan(entry + 16, 16).ToArray());
        Assert.Equal(8UL, ReadU64(image, entry + 32));
        Assert.Equal(111UL, ReadU64(image, entry + 40));
        Assert.Equal(0UL, ReadU64(image, entry + 48));
        Assert.Equal("TestContainer", Encoding.Unicode.GetString(image.AsSpan(entry + 56, 26).ToArray()));

        // Dual NXSB checkpoints: identical bytes when xids match, valid checksums.
        var nx0 = (int)part.StartByte;
        var nx1 = nx0 + BlockSize;
        Assert.Equal(
            image.AsSpan(nx0, BlockSize).ToArray(),
            image.AsSpan(nx1, BlockSize).ToArray());
        foreach (var nx in new[] { nx0, nx1 })
        {
            AssertValidFletcher64(image, nx);
            Assert.Equal(1UL, ReadU64(image, nx + 8));
            Assert.Equal(7UL, ReadU64(image, nx + 16));
            Assert.Equal(1u, ReadU32(image, nx + 24));
            Assert.Equal(0u, ReadU32(image, nx + 28));
            Assert.Equal(0x4253584Eu, ReadU32(image, nx + 32));
            Assert.Equal(4096u, ReadU32(image, nx + 36));
            Assert.Equal(13UL, ReadU64(image, nx + 40));
            Assert.Equal(containerGuid.ToByteArray(), image.AsSpan(nx + 72, 16).ToArray());
            Assert.Equal(2UL, ReadU64(image, nx + 160));
            Assert.Equal(101UL, ReadU64(image, nx + 184));
        }

        // OMAP object @ block 2.
        var omap = nx0 + 2 * BlockSize;
        AssertValidFletcher64(image, omap);
        Assert.Equal(2UL, ReadU64(image, omap + 8));
        Assert.Equal(7UL, ReadU64(image, omap + 16));
        Assert.Equal(0xBu, ReadU32(image, omap + 24) & 0xFFFFu);
        Assert.Equal(3UL, ReadU64(image, omap + 48));

        // OMAP btree leaf-root @ block 3: 1 non-fixed entry.
        var btree = nx0 + 3 * BlockSize;
        AssertValidFletcher64(image, btree);
        Assert.Equal(3u, ReadU16(image, btree + 32));
        Assert.Equal(0u, ReadU16(image, btree + 34));
        Assert.Equal(1u, ReadU32(image, btree + 36));
        Assert.Equal(0u, ReadU16(image, btree + 40));
        Assert.Equal(8u, ReadU16(image, btree + 42));
        Assert.Equal(0u, ReadU16(image, btree + 44));
        Assert.Equal(0u, ReadU16(image, btree + 46));
        // Entry: key @ keys area, value measured backward from 4056.
        Assert.Equal(0u, ReadU16(image, btree + 56));
        Assert.Equal(16u, ReadU16(image, btree + 58));
        Assert.Equal(16u, ReadU16(image, btree + 60));
        Assert.Equal(16u, ReadU16(image, btree + 62));
        var keyStart = btree + 56 + 8;
        Assert.Equal(101UL, ReadU64(image, keyStart));
        Assert.Equal(7UL, ReadU64(image, keyStart + 8));
        var valueStart = btree + 4056 - 16;
        Assert.Equal(0u, ReadU32(image, valueStart));
        Assert.Equal(4096u, ReadU32(image, valueStart + 4));
        Assert.Equal(4UL, ReadU64(image, valueStart + 8));

        // APSB volume @ block 4.
        var apsb = nx0 + 4 * BlockSize;
        AssertValidFletcher64(image, apsb);
        Assert.Equal(101UL, ReadU64(image, apsb + 8));
        Assert.Equal(7UL, ReadU64(image, apsb + 16));
        Assert.Equal(0xDu, ReadU32(image, apsb + 24) & 0xFFFFu);
        Assert.Equal(0x42535041u, ReadU32(image, apsb + 32));
        Assert.Equal(1UL, ReadU64(image, apsb + 40));
        Assert.Equal(0UL, ReadU64(image, apsb + 48));
        Assert.Equal(0UL, ReadU64(image, apsb + 56));
        Assert.NotEqual(0UL, ReadU64(image, apsb + 128));
        Assert.NotEqual(0UL, ReadU64(image, apsb + 136));
        Assert.Equal(volumeGuid.ToByteArray(), image.AsSpan(apsb + 240, 16).ToArray());
        Assert.Equal(1UL, ReadU64(image, apsb + 264));
        Assert.Equal("Data"u8.ToArray(), image.AsSpan(apsb + 288, 4).ToArray());
        Assert.Equal(0, image[apsb + 292]);
        Assert.Equal(32u, ReadU16(image, apsb + 548));
        Assert.Equal(new byte[16], image.AsSpan(apsb + 552, 16).ToArray());
        Assert.Equal(0UL, ReadU64(image, apsb + 1032));
    }

    [Fact]
    public void CreateCatalogFixture_TwoPartitionsTwoVolumesEach_IsolatesContainers()
    {
        using var temp = CatalogTemp.Create();
        var imagePath = temp.File("multi.apfs.img");
        var group = new Guid("dddddddd-dddd-dddd-dddd-dddddddddddd");

        var result = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(
                SizeMiB: 16,
                Partitions:
                [
                    new CatalogPartitionSpec(
                        Name: "First",
                        PartitionUuid: new Guid("11111111-1111-1111-1111-111111111111"),
                        ContainerUuid: new Guid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                        Xid: 7,
                        Features: 0x1,
                        Volumes:
                        [
                            new CatalogVolumeSpec(Name: "Data", Role: 32, GroupUuid: group),
                            new CatalogVolumeSpec(
                                Name: "Données",
                                Role: 1,
                                ObjectId: 502,
                                FsFlags: 0x8,
                                IncompatibleFeatures: 0x4000),
                        ]),
                    new CatalogPartitionSpec(
                        Name: "Second",
                        PartitionUuid: new Guid("22222222-2222-2222-2222-222222222222"),
                        ContainerUuid: new Guid("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                        Xid: 9,
                        Volumes:
                        [
                            new CatalogVolumeSpec(Name: "Data", Role: 32),
                            new CatalogVolumeSpec(Name: "Backup", Role: 2048, GroupUuid: group),
                        ]),
                ]));

        Assert.Equal(2, result.Partitions.Count);
        var first = result.Partitions[0];
        var second = result.Partitions[1];
        Assert.Equal(1, first.Index);
        Assert.Equal(2, second.Index);
        Assert.Equal(8L * SectorSize, first.StartByte);
        Assert.Equal(0, second.StartByte % BlockSize);
        Assert.True(second.StartByte > first.StartByte + first.SizeBytes - BlockSize);
        Assert.Equal(7UL, first.CheckpointXid);
        Assert.Equal(9UL, second.CheckpointXid);
        Assert.Equal([101UL, 502UL], first.Volumes.Select(v => v.ObjectId).ToArray());
        Assert.Equal([101UL, 102UL], second.Volumes.Select(v => v.ObjectId).ToArray());
        Assert.Equal(502UL, first.Volumes[1].ObjectId);
        Assert.Equal(9UL, second.Volumes[0].Xid);

        var image = File.ReadAllBytes(imagePath);
        Assert.Equal(2u, ReadU32(image, 512 + 80));
        AssertValidGptCrc(image, headerOffset: 512, entriesOffset: 2 * SectorSize, entriesBytes: 256);

        // Volume names: UTF-8 NUL-terminated at +288.
        var firstApsb1 = (int)first.StartByte + 5 * BlockSize;
        Assert.Equal("Données"u8.ToArray(), image.AsSpan(firstApsb1 + 288, 8).ToArray());
        Assert.Equal(0, image[firstApsb1 + 296]);
        Assert.Equal(1u, ReadU16(image, firstApsb1 + 548));
        Assert.Equal(0x8UL, ReadU64(image, firstApsb1 + 264));
        Assert.Equal(0x4000UL, ReadU64(image, firstApsb1 + 56));
        AssertValidFletcher64(image, firstApsb1);

        // Shared group UUID bytes are identical on both grouped volumes.
        var firstApsb0 = (int)first.StartByte + 4 * BlockSize;
        var secondApsb1 = (int)second.StartByte + 5 * BlockSize;
        Assert.Equal(
            image.AsSpan(firstApsb0 + 552, 16).ToArray(),
            image.AsSpan(secondApsb1 + 552, 16).ToArray());
        Assert.Equal(group.ToByteArray(), image.AsSpan(firstApsb0 + 552, 16).ToArray());
        Assert.Equal(2048u, ReadU16(image, secondApsb1 + 548));

        // Container feature bits and xids land at NXSB offsets.
        Assert.Equal(0x1UL, ReadU64(image, (int)first.StartByte + 48));
        Assert.Equal(7UL, ReadU64(image, (int)first.StartByte + 16));
        Assert.Equal(9UL, ReadU64(image, (int)second.StartByte + 16));

        // Same volume name in different containers keeps distinct object layouts.
        var secondApsb0 = (int)second.StartByte + 4 * BlockSize;
        Assert.Equal("Data"u8.ToArray(), image.AsSpan(secondApsb0 + 288, 4).ToArray());
        AssertValidFletcher64(image, secondApsb0);
    }

    [Fact]
    public void CreateCatalogFixture_EmptyVolumeList_WritesVolumeLessContainer()
    {
        using var temp = CatalogTemp.Create();
        var imagePath = temp.File("empty.apfs.img");

        var result = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(
                Partitions:
                [
                    new CatalogPartitionSpec(Name: "Empty", Volumes: []),
                ]));

        var part = Assert.Single(result.Partitions);
        Assert.Empty(part.Volumes);

        var image = File.ReadAllBytes(imagePath);
        AssertValidFletcher64(image, (int)part.StartByte);
        Assert.Equal(0u, ReadU32(image, (int)part.StartByte + 3 * BlockSize + 36));
    }

    [Fact]
    public void CreateCatalogFixture_BadChecksum_ZeroesFirstVolumeChecksumOnly()
    {
        using var temp = CatalogTemp.Create();
        var imagePath = temp.File("badsum.apfs.img");

        var result = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(
                Partitions:
                [
                    new CatalogPartitionSpec(
                        Name: "Bad",
                        Volumes: [new CatalogVolumeSpec(), new CatalogVolumeSpec(Name: "Second")],
                        Corruption: CatalogCorruptionKind.BadChecksum),
                ]));

        var part = Assert.Single(result.Partitions);
        var image = File.ReadAllBytes(imagePath);
        var firstApsb = (int)part.StartByte + 4 * BlockSize;
        var secondApsb = (int)part.StartByte + 5 * BlockSize;

        Assert.Equal(0UL, ReadU64(image, firstApsb));
        Assert.Equal(0x42535041u, ReadU32(image, firstApsb + 32));
        Assert.NotEqual(0UL, ComputeFletcher64(image.AsSpan(firstApsb + 8, BlockSize - 8)));
        AssertValidFletcher64(image, secondApsb);
        AssertValidFletcher64(image, (int)part.StartByte);
    }

    [Fact]
    public void CreateCatalogFixture_StaleXid_SetsVolumeXidAboveContainerXid()
    {
        using var temp = CatalogTemp.Create();
        var imagePath = temp.File("stale.apfs.img");

        var result = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(
                Partitions:
                [
                    new CatalogPartitionSpec(
                        Name: "Stale",
                        Xid: 7,
                        Volumes: [new CatalogVolumeSpec(), new CatalogVolumeSpec(Name: "Fresh")],
                        Corruption: CatalogCorruptionKind.StaleXid),
                ]));

        var part = Assert.Single(result.Partitions);
        Assert.Equal(8UL, part.Volumes[0].Xid);
        Assert.Equal(7UL, part.Volumes[1].Xid);

        var image = File.ReadAllBytes(imagePath);
        var firstApsb = (int)part.StartByte + 4 * BlockSize;
        Assert.Equal(8UL, ReadU64(image, firstApsb + 16));
        Assert.Equal(7UL, ReadU64(image, (int)part.StartByte + 16));
        AssertValidFletcher64(image, firstApsb);
    }

    [Fact]
    public void CreateCatalogFixture_DuplicateOid_SharesFirstTwoObjectIds()
    {
        using var temp = CatalogTemp.Create();
        var imagePath = temp.File("dupoid.apfs.img");

        var result = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(
                Partitions:
                [
                    new CatalogPartitionSpec(
                        Name: "Dup",
                        Volumes: [new CatalogVolumeSpec(), new CatalogVolumeSpec(Name: "Clone")],
                        Corruption: CatalogCorruptionKind.DuplicateOid),
                ]));

        var part = Assert.Single(result.Partitions);
        Assert.Equal(part.Volumes[0].ObjectId, part.Volumes[1].ObjectId);

        var image = File.ReadAllBytes(imagePath);
        var firstApsb = (int)part.StartByte + 4 * BlockSize;
        var secondApsb = (int)part.StartByte + 5 * BlockSize;
        Assert.Equal(ReadU64(image, firstApsb + 8), ReadU64(image, secondApsb + 8));
        Assert.Equal(101UL, ReadU64(image, firstApsb + 8));
        Assert.Equal(ReadU64(image, (int)part.StartByte + 184), ReadU64(image, (int)part.StartByte + 192));
        AssertValidFletcher64(image, firstApsb);
        AssertValidFletcher64(image, secondApsb);
    }

    [Fact]
    public void CreateCatalogFixture_Truncate_CutsFileInsideLastVolumeBlock()
    {
        using var temp = CatalogTemp.Create();
        var imagePath = temp.File("trunc.apfs.img");

        var result = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(
                SizeMiB: 16,
                Partitions:
                [
                    new CatalogPartitionSpec(
                        Name: "Cut",
                        Volumes: [new CatalogVolumeSpec()],
                        Corruption: CatalogCorruptionKind.Truncate),
                ]));

        var part = Assert.Single(result.Partitions);
        var expectedCut = part.StartByte + 4 * BlockSize + 512;
        Assert.Equal(expectedCut, new FileInfo(imagePath).Length);

        var image = File.ReadAllBytes(imagePath);
        Assert.Equal("EFI PART"u8.ToArray(), image.AsSpan(512, 8).ToArray());
    }

    [Fact]
    public void CreateCatalogFixture_RejectsBelowMinimumSize()
    {
        using var temp = CatalogTemp.Create();

        Assert.Throws<ArgumentOutOfRangeException>(() => SyntheticApfsTestImage.CreateCatalogFixture(
            temp.File("tiny.apfs.img"),
            new CatalogFixtureSpec(SizeMiB: 1)));
    }

    [Fact]
    public void CreateCatalogFixture_RejectsWhenPartitionsExceedImage()
    {
        using var temp = CatalogTemp.Create();
        var partitions = Enumerable.Range(0, 300)
            .Select(_ => new CatalogPartitionSpec(Volumes: []))
            .ToArray();

        Assert.Throws<ArgumentOutOfRangeException>(() => SyntheticApfsTestImage.CreateCatalogFixture(
            temp.File("overflow.apfs.img"),
            new CatalogFixtureSpec(SizeMiB: 4, Partitions: partitions)));
    }

    [Fact]
    public void CreateCatalogFixture_RejectsMoreThanOneHundredVolumesPerContainer()
    {
        // One 4 KiB omap btree node holds at most (4056 - 56) / 40 = 100
        // non-fixed 16/16-byte records (8 table + 16 key + 16 value each).
        using var temp = CatalogTemp.Create();

        Assert.Throws<ArgumentOutOfRangeException>(() => SyntheticApfsTestImage.CreateCatalogFixture(
            temp.File("toomany.apfs.img"),
            new CatalogFixtureSpec(
                Partitions:
                [
                    new CatalogPartitionSpec(
                        Volumes: Enumerable.Repeat(new CatalogVolumeSpec(), 101).ToArray()),
                ])));
    }

    [Fact]
    public void CreateCatalogFixture_DuplicateOidWithSingleVolume_Throws()
    {
        using var temp = CatalogTemp.Create();

        Assert.Throws<ArgumentException>(() => SyntheticApfsTestImage.CreateCatalogFixture(
            temp.File("dup1.apfs.img"),
            new CatalogFixtureSpec(
                Partitions:
                [
                    new CatalogPartitionSpec(
                        Volumes: [new CatalogVolumeSpec()],
                        Corruption: CatalogCorruptionKind.DuplicateOid),
                ])));
    }

    [Fact]
    public void CreateCatalogFixture_VolumeCorruptionWithoutVolumes_Throws()
    {
        using var temp = CatalogTemp.Create();

        foreach (var corruption in new[]
                 {
                     CatalogCorruptionKind.BadChecksum,
                     CatalogCorruptionKind.StaleXid,
                     CatalogCorruptionKind.Truncate,
                     CatalogCorruptionKind.DuplicateOid,
                 })
        {
            Assert.Throws<ArgumentException>(() => SyntheticApfsTestImage.CreateCatalogFixture(
                temp.File($"{corruption}-empty.apfs.img"),
                new CatalogFixtureSpec(
                    Partitions:
                    [
                        new CatalogPartitionSpec(Volumes: [], Corruption: corruption),
                    ])));
        }
    }

    [Fact]
    public void CreateCatalogFixture_RefusesToOverwriteAndRejectsBadExtensions()
    {
        using var temp = CatalogTemp.Create();
        var existing = temp.File("existing.apfs.img");
        File.WriteAllText(existing, "keep");

        Assert.Throws<IOException>(() => SyntheticApfsTestImage.CreateCatalogFixture(existing));
        Assert.Equal("keep", File.ReadAllText(existing));
        Assert.Throws<ArgumentException>(() => SyntheticApfsTestImage.CreateCatalogFixture(
            temp.File("bad.txt")));
    }

    // ---- Independent checksum copies (freeze section 5 formulas) ----

    private static void AssertValidFletcher64(byte[] image, int blockOffset)
    {
        var stored = ReadU64(image, blockOffset);
        Assert.NotEqual(0UL, stored);
        Assert.NotEqual(ulong.MaxValue, stored);
        Assert.Equal(ComputeFletcher64(image.AsSpan(blockOffset + 8, BlockSize - 8)), stored);
    }

    private static ulong ComputeFletcher64(ReadOnlySpan<byte> bytes)
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

    private static void AssertValidGptCrc(byte[] image, int headerOffset, int entriesOffset, int entriesBytes)
    {
        var storedHeader = ReadU32(image, headerOffset + 16);
        Assert.NotEqual(0u, storedHeader);
        var header = image.AsSpan(headerOffset, 92).ToArray();
        header.AsSpan(16, 4).Clear();
        Assert.Equal(storedHeader, ComputeCrc32(header));

        var storedEntries = ReadU32(image, headerOffset + 88);
        Assert.NotEqual(0u, storedEntries);
        Assert.Equal(storedEntries, ComputeCrc32(image.AsSpan(entriesOffset, entriesBytes)));
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

    private static ushort ReadU16(byte[] image, int offset)
        => BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(offset, 2));

    private static uint ReadU32(byte[] image, int offset)
        => BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(offset, 4));

    private static ulong ReadU64(byte[] image, int offset)
        => BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(offset, 8));

    // D:-rooted scratch: the repo lives on D: and every test artifact must
    // stay there (never Path.GetTempPath(), which may resolve to C:).
    private sealed class CatalogTemp : IDisposable
    {
        private CatalogTemp(string path) => Path = path;

        public string Path { get; }

        public static CatalogTemp Create()
        {
            var path = System.IO.Path.Combine(
                AppContext.BaseDirectory, "test-tmp", "catalog-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return new CatalogTemp(path);
        }

        public string File(string name) => System.IO.Path.Combine(Path, name);

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
