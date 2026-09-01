using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeApfsBackendRecoveryIdentityTests
{
    private static readonly Guid ApfsPartitionTypeGuid = new("7C3457EF-0000-11AA-AA11-00306543ECAC");
    private static readonly Guid DefaultPartitionGuid = new("11111111-2222-3333-4444-555555555555");
    private static readonly Guid DefaultContainerUuid = new("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
    private const ulong DefaultVolumeOid = 0x1122334455667788;

    [Theory]
    [InlineData("ImmutableRecoveryIdentityMissing")]
    [InlineData("ImmutableRecoveryIdentityInvalid")]
    [InlineData("LegacyRecoveryEvidenceAmbiguous")]
    public void MountedReadOnlyIdentityFallback_PreservesExactRecoveryReason(string recoveryReason)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "GetMountedReadOnlyIdentityFallbackReason",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var retainedReason = method!.Invoke(
            null,
            [MountAccessMode.ReadWrite, "Disabled", recoveryReason]);

        Assert.Equal(recoveryReason, retainedReason);
    }

    [Theory]
    [InlineData(MountAccessMode.ReadOnly, "Disabled", "ImmutableRecoveryIdentityMissing")]
    [InlineData(MountAccessMode.ReadWrite, "Native", "ImmutableRecoveryIdentityMissing")]
    [InlineData(MountAccessMode.ReadWrite, "Disabled", "RecoveryMarkerDirty")]
    public void MountedReadOnlyIdentityFallback_RejectsOtherMountStates(
        MountAccessMode requestedAccessMode,
        string hostWriteBackend,
        string recoveryReason)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "GetMountedReadOnlyIdentityFallbackReason",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var retainedReason = method!.Invoke(
            null,
            [requestedAccessMode, hostWriteBackend, recoveryReason]);

        Assert.Null(retainedReason);
    }

    [Fact]
    public async Task DirectContainerRecoveryIdentity_IsStableAcrossPathAndBackendLifetime()
    {
        using var temp = TempDirectory.Create();
        var firstPath = Path.Combine(temp.Path, "first.apfs.img");
        var secondPath = Path.Combine(temp.Path, "renamed.apfs.img");
        CreateDirectContainerImage(firstPath, DefaultContainerUuid, DefaultVolumeOid);
        CreateDirectContainerImage(secondPath, DefaultContainerUuid, DefaultVolumeOid);

        var firstIdentity = await DiscoverRecoveryIdentityAsync(firstPath);
        var secondIdentity = await DiscoverRecoveryIdentityAsync(secondPath);

        Assert.Equal(firstIdentity, secondIdentity);
        Assert.Matches("^apfs-recovery-v1-[A-Za-z0-9_-]{43}$", firstIdentity);
        Assert.DoesNotContain("first", firstIdentity, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(DefaultContainerUuid.ToString("N"), firstIdentity, StringComparison.OrdinalIgnoreCase);
        Assert.All(firstIdentity!, static character => Assert.InRange((int)character, 0x21, 0x7E));
    }

    [Fact]
    public async Task GptRecoveryIdentity_IsIndependentOfPathOffsetAndDisplayLabel()
    {
        using var temp = TempDirectory.Create();
        var firstPath = Path.Combine(temp.Path, "physical-drive-2.img");
        var secondPath = Path.Combine(temp.Path, "physical-drive-9.img");
        CreateGptContainerImage(
            firstPath,
            partitionOffsetBytes: 1UL * 1024 * 1024,
            partitionName: "Main");
        CreateGptContainerImage(
            secondPath,
            partitionOffsetBytes: 2UL * 1024 * 1024,
            partitionName: "Renamed Partition");

        var firstIdentity = await DiscoverRecoveryIdentityAsync(firstPath);
        var secondIdentity = await DiscoverRecoveryIdentityAsync(secondPath);

        Assert.Equal(firstIdentity, secondIdentity);
    }

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    public async Task GptRecoveryIdentity_ChangesWithEachImmutableIdentityComponent(
        bool changePartitionGuid,
        bool changeContainerUuid,
        bool changeVolumeOid)
    {
        using var temp = TempDirectory.Create();
        var baselinePath = Path.Combine(temp.Path, "baseline.img");
        var changedPath = Path.Combine(temp.Path, "changed.img");
        CreateGptContainerImage(baselinePath);
        CreateGptContainerImage(
            changedPath,
            partitionGuid: changePartitionGuid
                ? new Guid("99999999-2222-3333-4444-555555555555")
                : DefaultPartitionGuid,
            containerUuid: changeContainerUuid
                ? new Guid("FFFFFFFF-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
                : DefaultContainerUuid,
            volumeOid: changeVolumeOid ? DefaultVolumeOid + 1 : DefaultVolumeOid);

        var baselineIdentity = await DiscoverRecoveryIdentityAsync(baselinePath);
        var changedIdentity = await DiscoverRecoveryIdentityAsync(changedPath);

        Assert.NotEqual(baselineIdentity, changedIdentity);
    }

    [Fact]
    public async Task DirectContainerRecoveryIdentity_UsesNoPartitionNamespace()
    {
        using var temp = TempDirectory.Create();
        var directPath = Path.Combine(temp.Path, "direct.img");
        var gptPath = Path.Combine(temp.Path, "gpt.img");
        CreateDirectContainerImage(directPath, DefaultContainerUuid, DefaultVolumeOid);
        CreateGptContainerImage(gptPath);

        var directIdentity = await DiscoverRecoveryIdentityAsync(directPath);
        var gptIdentity = await DiscoverRecoveryIdentityAsync(gptPath);

        Assert.NotEqual(directIdentity, gptIdentity);
    }

    [Fact]
    public async Task RecoveryIdentity_UsesVolumeOidFromSelectedContainerSuperblock()
    {
        using var temp = TempDirectory.Create();
        var selectedPath = Path.Combine(temp.Path, "selected.img");
        var expectedPath = Path.Combine(temp.Path, "expected.img");
        var stalePath = Path.Combine(temp.Path, "stale.img");
        CreateDirectContainerImage(
            selectedPath,
            DefaultContainerUuid,
            primaryVolumeOid: DefaultVolumeOid,
            secondaryVolumeOid: DefaultVolumeOid + 1);
        CreateDirectContainerImage(expectedPath, DefaultContainerUuid, DefaultVolumeOid + 1);
        CreateDirectContainerImage(stalePath, DefaultContainerUuid, DefaultVolumeOid);

        var selectedIdentity = await DiscoverRecoveryIdentityAsync(selectedPath);
        var expectedIdentity = await DiscoverRecoveryIdentityAsync(expectedPath);
        var staleIdentity = await DiscoverRecoveryIdentityAsync(stalePath);

        Assert.Equal(expectedIdentity, selectedIdentity);
        Assert.NotEqual(staleIdentity, selectedIdentity);
    }

    [Fact]
    public async Task RecoveryIdentity_RejectsNewerSecondarySuperblock_WhenContainerUuidDiffers()
    {
        using var temp = TempDirectory.Create();
        var mismatchedPath = Path.Combine(temp.Path, "mismatched-secondary.img");
        var expectedPath = Path.Combine(temp.Path, "expected-primary.img");
        var foreignContainerUuid = new Guid("FFFFFFFF-1111-2222-3333-444444444444");

        CreateSparseImage(mismatchedPath, 4UL * 1024 * 1024);
        WriteContainerSuperblock(
            mismatchedPath,
            offset: 0,
            DefaultContainerUuid,
            DefaultVolumeOid,
            checkpointXid: 7);
        WriteContainerSuperblock(
            mismatchedPath,
            offset: 4096,
            foreignContainerUuid,
            DefaultVolumeOid + 1,
            checkpointXid: 8);
        CreateDirectContainerImage(expectedPath, DefaultContainerUuid, DefaultVolumeOid);

        var mismatchedIdentity = await DiscoverRecoveryIdentityAsync(mismatchedPath);
        var expectedIdentity = await DiscoverRecoveryIdentityAsync(expectedPath);

        Assert.Equal(expectedIdentity, mismatchedIdentity);
    }

    [Fact]
    public async Task SyntheticImage_ProvidesStableRecoveryIdentity()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "synthetic.apfs.img");
        SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);

        var identity = await DiscoverRecoveryIdentityAsync(imagePath);

        Assert.Matches("^apfs-recovery-v1-[A-Za-z0-9_-]{43}$", identity);
    }

    [Fact]
    public async Task MissingContainerUuid_DoesNotInventIdentityFromTransientLocation()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "legacy-without-uuid.img");
        CreateDirectContainerImage(imagePath, Guid.Empty, DefaultVolumeOid);

        var identity = await DiscoverRecoveryIdentityAsync(imagePath, requireIdentity: false);

        Assert.Null(identity);
    }

    [Fact]
    public async Task MissingGptPartitionGuid_DoesNotEmitRecoveryIdentity()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "missing-partition-guid.img");
        CreateGptContainerImage(imagePath, partitionGuid: Guid.Empty);

        var identity = await DiscoverRecoveryIdentityAsync(imagePath, requireIdentity: false);

        Assert.Null(identity);
    }

    [Fact]
    public async Task MissingFirstVolumeOid_DoesNotEmitRecoveryIdentity()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "missing-volume-oid.img");
        CreateGptContainerImage(imagePath, volumeOid: 0);

        var identity = await DiscoverRecoveryIdentityAsync(imagePath, requireIdentity: false);

        Assert.Null(identity);
    }

    [Fact]
    public void PartitionlessRecoveryIdentity_IsAllowedForImageButNotRawPhysicalMedia()
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "BuildRecoveryIdentityFromComponents",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var containerUuid = Convert.ToHexString(DefaultContainerUuid.ToByteArray());

        var imageIdentity = method!.Invoke(
            null,
            [null, containerUuid, DefaultVolumeOid, true]);
        var rawPhysicalIdentity = method.Invoke(
            null,
            [null, containerUuid, DefaultVolumeOid, false]);

        Assert.Matches("^apfs-recovery-v1-[A-Za-z0-9_-]{43}$", Assert.IsType<string>(imageIdentity));
        Assert.Null(rawPhysicalIdentity);
    }

    [Fact]
    public async Task CorruptGptHeaderCrc_PreservesDiscoveryWithoutRecoveryIdentity()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "corrupt-gpt-header-crc.img");
        CreateGptContainerImage(imagePath);
        FlipByte(imagePath, 512 + 16);

        var identity = await DiscoverRecoveryIdentityAsync(imagePath, requireIdentity: false);

        Assert.Null(identity);
    }

    [Fact]
    public async Task CorruptGptEntryArrayCrc_PreservesDiscoveryWithoutRecoveryIdentity()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "corrupt-gpt-entry-crc.img");
        CreateGptContainerImage(imagePath);
        FlipByte(imagePath, 512 + 88);
        RewriteGptHeaderChecksum(imagePath);

        var identity = await DiscoverRecoveryIdentityAsync(imagePath, requireIdentity: false);

        Assert.Null(identity);
    }

    [Fact]
    public async Task BitFlipInPartitionGuid_DoesNotEmitPlausibleRecoveryIdentity()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "corrupt-partition-guid.img");
        CreateGptContainerImage(imagePath);
        FlipByte(imagePath, (2 * 512) + 16);

        var identity = await DiscoverRecoveryIdentityAsync(imagePath, requireIdentity: false);

        Assert.Null(identity);
    }

    [Theory]
    [InlineData(0x48)]
    [InlineData(0xB8)]
    public async Task BitFlipInNxsbIdentityField_DoesNotEmitPlausibleRecoveryIdentity(int fieldOffset)
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, $"corrupt-nxsb-{fieldOffset:x}.img");
        const long partitionOffset = 1L * 1024 * 1024;
        CreateGptContainerImage(imagePath, partitionOffsetBytes: partitionOffset);
        FlipByte(imagePath, partitionOffset + fieldOffset);
        FlipByte(imagePath, partitionOffset + 4096 + fieldOffset);

        var identity = await DiscoverRecoveryIdentityAsync(imagePath, requireIdentity: false);

        Assert.Null(identity);
    }

    [Fact]
    public async Task LegacyCheckpointWriterChecksumSignature_ProvidesRecoveryIdentityForSelfRepair()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "legacy-checkpoint-checksum.img");
        const long partitionOffset = 1L * 1024 * 1024;
        CreateGptContainerImage(imagePath, partitionOffsetBytes: partitionOffset);
        SimulateLegacyCheckpointWriterChecksumDamage(imagePath, partitionOffset);

        var identity = await DiscoverRecoveryIdentityAsync(imagePath);

        Assert.Matches("^apfs-recovery-v1-[A-Za-z0-9_-]{43}$", identity);
    }

    [Fact]
    public async Task LegacyCheckpointWriterChecksumSignature_RejectsAnyUnexpectedBlockDifference()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "legacy-checkpoint-extra-difference.img");
        const long partitionOffset = 1L * 1024 * 1024;
        CreateGptContainerImage(imagePath, partitionOffsetBytes: partitionOffset);
        SimulateLegacyCheckpointWriterChecksumDamage(imagePath, partitionOffset);
        FlipByte(imagePath, partitionOffset + 4096 + 0xC8);

        var identity = await DiscoverRecoveryIdentityAsync(imagePath, requireIdentity: false);

        Assert.Null(identity);
    }

    [Fact]
    public void FallbackVolume_DoesNotInventRecoveryIdentityFromDevicePath()
    {
        using var backend = CreateBackend();
        var fallback = new VolumeInfo(
            VolumeId: @"\\.\PhysicalDrive17|Main",
            DeviceId: @"\\.\PhysicalDrive17",
            VolumeName: "Main",
            SupportsReadWrite: false);

        var identity = ResolveRecoveryIdentity(backend, fallback);

        Assert.Null(identity);
    }

    [Fact]
    public void FsHostArguments_IncludeDiscoveredRecoveryIdentityAndOmitMissingIdentity()
    {
        var appendMethod = typeof(NativeApfsBackend).GetMethod(
            "AppendRecoveryIdentityArgument",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(appendMethod);

        var withIdentity = new ProcessStartInfo();
        appendMethod!.Invoke(null, [withIdentity, "apfs-recovery-v1-test_identity"]);
        Assert.Equal(
            ["--recovery-identity", "apfs-recovery-v1-test_identity"],
            withIdentity.ArgumentList.Cast<string>().ToArray());

        var withoutIdentity = new ProcessStartInfo();
        appendMethod.Invoke(null, [withoutIdentity, null]);
        Assert.Empty(withoutIdentity.ArgumentList.Cast<string>());
    }

    private static async Task<string?> DiscoverRecoveryIdentityAsync(string imagePath, bool requireIdentity = true)
    {
        using var backend = CreateBackend(imagePath);
        var volumes = await backend.ProbeVolumesAsync(imagePath, CancellationToken.None);
        var volume = Assert.Single(volumes);
        var identity = ResolveRecoveryIdentity(backend, volume);
        if (requireIdentity)
        {
            Assert.False(string.IsNullOrWhiteSpace(identity));
        }

        return identity;
    }

    private static string? ResolveRecoveryIdentity(NativeApfsBackend backend, VolumeInfo volume)
    {
        var resolveMethod = typeof(NativeApfsBackend).GetMethod(
            "ResolveMountTarget",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(resolveMethod);
        var mountTarget = resolveMethod!.Invoke(backend, [volume]);
        Assert.NotNull(mountTarget);

        var identityProperty = mountTarget!.GetType().GetProperty("RecoveryIdentity");
        Assert.NotNull(identityProperty);
        return (string?)identityProperty!.GetValue(mountTarget);
    }

    private static NativeApfsBackend CreateBackend(params string[] imagePaths)
        => new(new ServiceHostOptions
        {
            BackendMode = "Native",
            NativeDeviceCandidates = imagePaths,
            NativeAutoDiscoverPhysicalDrives = false,
        });

    private static void CreateDirectContainerImage(
        string path,
        Guid containerUuid,
        ulong volumeOid)
        => CreateDirectContainerImage(path, containerUuid, volumeOid, volumeOid);

    private static void CreateDirectContainerImage(
        string path,
        Guid containerUuid,
        ulong primaryVolumeOid,
        ulong secondaryVolumeOid)
    {
        CreateSparseImage(path, 4UL * 1024 * 1024);
        WriteContainerSuperblock(path, 0, containerUuid, primaryVolumeOid, checkpointXid: 7);
        WriteContainerSuperblock(path, 4096, containerUuid, secondaryVolumeOid, checkpointXid: 8);
    }

    private static void CreateGptContainerImage(
        string path,
        ulong partitionOffsetBytes = 1UL * 1024 * 1024,
        string partitionName = "Main",
        Guid? partitionGuid = null,
        Guid? containerUuid = null,
        ulong volumeOid = DefaultVolumeOid)
    {
        const int sectorSize = 512;
        var sizeBytes = Math.Max(8UL * 1024 * 1024, partitionOffsetBytes + (4UL * 1024 * 1024));
        CreateSparseImage(path, sizeBytes);

        Span<byte> header = stackalloc byte[sectorSize];
        "EFI PART"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(8, 4), 0x00010000);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(12, 4), 92);
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(72, 8), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(80, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(84, 4), 128);

        Span<byte> entry = stackalloc byte[128];
        ApfsPartitionTypeGuid.TryWriteBytes(entry[..16]);
        (partitionGuid ?? DefaultPartitionGuid).TryWriteBytes(entry.Slice(16, 16));
        var startLba = partitionOffsetBytes / sectorSize;
        BinaryPrimitives.WriteUInt64LittleEndian(entry.Slice(32, 8), startLba);
        BinaryPrimitives.WriteUInt64LittleEndian(entry.Slice(40, 8), (sizeBytes / sectorSize) - 1);
        Encoding.Unicode.GetBytes(partitionName.AsSpan(), entry.Slice(56, 72));
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(88, 4), ComputeCrc32(entry));
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(16, 4), ComputeCrc32(header[..92]));
        WriteAt(path, sectorSize, header);
        WriteAt(path, 2L * sectorSize, entry);

        WriteContainerSuperblock(path, checked((long)partitionOffsetBytes), containerUuid ?? DefaultContainerUuid, volumeOid, 7);
        WriteContainerSuperblock(path, checked((long)partitionOffsetBytes + 4096), containerUuid ?? DefaultContainerUuid, volumeOid, 8);
    }

    private static void WriteContainerSuperblock(
        string path,
        long offset,
        Guid containerUuid,
        ulong volumeOid,
        ulong checkpointXid)
    {
        Span<byte> block = stackalloc byte[4096];
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0x10, 8), checkpointXid);
        BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(0x20, 4), 0x4253584E);
        BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(0x24, 4), 4096);
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0x28, 8), 1024);
        containerUuid.TryWriteBytes(block.Slice(0x48, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0xA0, 8), 0x54);
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0xB8, 8), volumeOid);
        BinaryPrimitives.WriteUInt64LittleEndian(block, ComputeApfsObjectChecksum(block[8..]));
        WriteAt(path, offset, block);
    }

    private static void SimulateLegacyCheckpointWriterChecksumDamage(string path, long partitionOffset)
    {
        var block = new byte[4096];
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
        {
            stream.Position = partitionOffset;
            stream.ReadExactly(block);

            BinaryPrimitives.WriteUInt64LittleEndian(block.AsSpan(0x10, 8), 9);
            stream.Position = partitionOffset;
            stream.Write(block);

            BinaryPrimitives.WriteUInt64LittleEndian(block.AsSpan(0x10, 8), 8);
            stream.Position = partitionOffset + 4096;
            stream.Write(block);
        }
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

    private static void FlipByte(string path, long offset)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
        stream.Position = offset;
        var value = stream.ReadByte();
        Assert.NotEqual(-1, value);
        stream.Position = offset;
        stream.WriteByte((byte)(value ^ 0x01));
    }

    private static void RewriteGptHeaderChecksum(string path)
    {
        var header = new byte[512];
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
        {
            stream.Position = 512;
            stream.ReadExactly(header);
            header.AsSpan(16, 4).Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(16, 4), ComputeCrc32(header.AsSpan(0, 92)));
            stream.Position = 512;
            stream.Write(header);
        }
    }

    private static void CreateSparseImage(string path, ulong sizeBytes)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        stream.SetLength(checked((long)sizeBytes));
    }

    private static void WriteAt(string path, long offset, ReadOnlySpan<byte> bytes)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.Read);
        stream.Position = offset;
        stream.Write(bytes);
    }

    private sealed class TempDirectory : IDisposable
    {
        private TempDirectory(string path) => Path = path;

        public string Path { get; }

        public static TempDirectory Create()
        {
            var path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "ApfsAccessRecoveryIdentityTests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return new TempDirectory(path);
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch
            {
                // Best-effort test cleanup.
            }
        }
    }
}
