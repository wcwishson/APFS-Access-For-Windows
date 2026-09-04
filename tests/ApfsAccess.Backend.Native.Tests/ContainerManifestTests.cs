using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// Frozen contract v1.3 section 7 (managed side): manifestSha256 is SHA-256
// (lowercase hex) over UTF-8 bytes of `manifest-check-v1\n` +
// `<containerUuid>\n<device>\n<offset-dec>\n` + per volume in array order
// `<oid-dec>\n<containerUuid>\n<name>\n<mount>\n<W|R>\n<recoveryIdentity>\n`
// (missing optionals = ""). These tests recompute independently (never via
// the writer) and verify the written file round-trips.
public sealed class ContainerManifestTests : IDisposable
{
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";
    private const string Device = @"D:\test-device.apfs.img";

    private readonly List<string> _writtenManifests = new();

    [Fact]
    public void Checksum_MatchesIndependentlyRecomputedSha256_AndFileRoundTrips()
    {
        IReadOnlyList<ContainerManifestVolume> volumes =
        [
            new ContainerManifestVolume(101, ContainerHex, "Data", "E:\\", true, "rec-101"),
            new ContainerManifestVolume(102, ContainerHex, "Backup", "F:\\", false, "rec-102"),
        ];

        var actual = ContainerManifestWriter.ComputeManifestSha256(ContainerHex, Device, 20480, volumes);

        // Independent recompute: hand-built canonical bytes, framework SHA-256.
        var canonical = new StringBuilder();
        canonical.Append("manifest-check-v1\n");
        canonical.Append("a9cb92d28b7c4b599eab633c7625f491\n");
        canonical.Append("D:\\test-device.apfs.img\n");
        canonical.Append("20480\n");
        canonical.Append("101\n");
        canonical.Append("a9cb92d28b7c4b599eab633c7625f491\n");
        canonical.Append("Data\n");
        canonical.Append("E:\\\n");
        canonical.Append("W\n");
        canonical.Append("rec-101\n");
        canonical.Append("102\n");
        canonical.Append("a9cb92d28b7c4b599eab633c7625f491\n");
        canonical.Append("Backup\n");
        canonical.Append("F:\\\n");
        canonical.Append("R\n");
        canonical.Append("rec-102\n");
        var expected = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString()))).ToLowerInvariant();

        Assert.Equal(expected, actual);
        Assert.Equal(actual.ToLowerInvariant(), actual);

        var written = ContainerManifestWriter.WriteManifest(ContainerHex, Device, 20480, volumes);
        _writtenManifests.Add(written.ManifestPath);
        Assert.Equal(expected, written.ManifestSha256);

        // Round-trip: recompute from the parsed file content, not the inputs.
        using var stream = File.OpenRead(written.ManifestPath);
        using var document = JsonDocument.Parse(stream);
        var root = document.RootElement;
        Assert.Equal("apfs-access-container-manifest", root.GetProperty("format").GetString());
        Assert.Equal(1, root.GetProperty("version").GetInt32());
        Assert.Equal(expected, root.GetProperty("manifestSha256").GetString());
        var fileVolumes = root.GetProperty("volumes");
        Assert.Equal(2, fileVolumes.GetArrayLength());
        var reparsed = new StringBuilder();
        reparsed.Append("manifest-check-v1\n");
        reparsed.Append(root.GetProperty("containerUuid").GetString()).Append('\n');
        reparsed.Append(root.GetProperty("device").GetString()).Append('\n');
        reparsed.Append(root.GetProperty("deviceOffsetBytes").GetUInt64().ToString()).Append('\n');
        foreach (var element in fileVolumes.EnumerateArray())
        {
            reparsed.Append(element.GetProperty("objectId").GetUInt64().ToString()).Append('\n');
            reparsed.Append(element.GetProperty("containerUuid").GetString()).Append('\n');
            reparsed.Append(element.GetProperty("name").GetString()).Append('\n');
            reparsed.Append(element.GetProperty("mount").GetString()).Append('\n');
            reparsed.Append(element.GetProperty("requestedWrite").GetBoolean() ? "W" : "R").Append('\n');
            reparsed.Append(element.GetProperty("recoveryIdentity").GetString()).Append('\n');
        }

        var fromFile = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(reparsed.ToString()))).ToLowerInvariant();
        Assert.Equal(expected, fromFile);
    }

    [Fact]
    public void Checksum_MissingOptionalsSerializeAsEmpty()
    {
        IReadOnlyList<ContainerManifestVolume> withMissing =
        [
            new ContainerManifestVolume(101, ContainerHex, null, "E:\\", true, null),
        ];
        IReadOnlyList<ContainerManifestVolume> withEmpty =
        [
            new ContainerManifestVolume(101, ContainerHex, string.Empty, "E:\\", true, string.Empty),
        ];

        Assert.Equal(
            ContainerManifestWriter.ComputeManifestSha256(ContainerHex, Device, 0, withEmpty),
            ContainerManifestWriter.ComputeManifestSha256(ContainerHex, Device, 0, withMissing));
    }

    [Fact]
    public void Checksum_VolumeOrderIsSignificant()
    {
        IReadOnlyList<ContainerManifestVolume> forward =
        [
            new ContainerManifestVolume(101, ContainerHex, "Data", "E:\\", true, "r1"),
            new ContainerManifestVolume(102, ContainerHex, "Backup", "F:\\", false, "r2"),
        ];
        IReadOnlyList<ContainerManifestVolume> reversed = [forward[1], forward[0]];

        Assert.NotEqual(
            ContainerManifestWriter.ComputeManifestSha256(ContainerHex, Device, 0, forward),
            ContainerManifestWriter.ComputeManifestSha256(ContainerHex, Device, 0, reversed));
    }

    [Fact]
    public void Checksum_ContainerUuidNormalizedToLowercase()
    {
        IReadOnlyList<ContainerManifestVolume> volumes =
        [
            new ContainerManifestVolume(101, ContainerHex, "Data", "E:\\", true, "r1"),
        ];

        var lower = ContainerManifestWriter.ComputeManifestSha256(ContainerHex, Device, 0, volumes);
        var upper = ContainerManifestWriter.ComputeManifestSha256(
            ContainerHex.ToUpperInvariant(), Device, 0, volumes);
        Assert.Equal(lower, upper);

        var written = ContainerManifestWriter.WriteManifest(
            ContainerHex.ToUpperInvariant(), Device, 0, volumes);
        _writtenManifests.Add(written.ManifestPath);
        Assert.Equal(ContainerHex, written.ContainerUuid);
    }

    [Fact]
    public void ResolveManifestDirectory_UsesTheSuppliedRuntimeRoot()
    {
        var runtimeRoot = Path.Combine(
            Path.GetPathRoot(Environment.SystemDirectory)!,
            "ApfsAccess-Runtime-Contract");

        var resolved = ContainerManifestWriter.ResolveManifestDirectory(runtimeRoot);

        Assert.Equal(
            Path.Combine(Path.GetFullPath(runtimeRoot), "ApfsAccess", "manifests"),
            resolved);
    }

    [Fact]
    public void Write_LandsUnderTheCurrentTempRoot()
    {
        var written = ContainerManifestWriter.WriteManifest(
            ContainerHex,
            Device,
            0,
            [new ContainerManifestVolume(101, ContainerHex, "Data", "E:\\", false, null)]);
        _writtenManifests.Add(written.ManifestPath);

        Assert.StartsWith(
            Path.GetFullPath(Path.GetTempPath()),
            written.ManifestPath,
            StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(written.ManifestPath));
    }

    [Theory]
    [InlineData("not-hex", 101UL, ContainerHex, "E:\\")]
    [InlineData("", 101UL, ContainerHex, "E:\\")]
    [InlineData(ContainerHex, 0UL, ContainerHex, "E:\\")]
    [InlineData(ContainerHex, 101UL, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "E:\\")]
    [InlineData(ContainerHex, 101UL, ContainerHex, "")]
    public void Write_RejectsInvalidInputs(
        string containerUuid, ulong objectId, string memberContainer, string mount)
    {
        IReadOnlyList<ContainerManifestVolume> volumes =
        [
            new ContainerManifestVolume(objectId, memberContainer, "Data", mount, true, "r"),
        ];

        Assert.Throws<ContainerManifestException>(
            () => ContainerManifestWriter.WriteManifest(containerUuid, Device, 0, volumes));
    }

    [Fact]
    public void Write_RejectsDuplicateObjectIds_AndEmptyVolumeList()
    {
        IReadOnlyList<ContainerManifestVolume> duplicates =
        [
            new ContainerManifestVolume(101, ContainerHex, "Data", "E:\\", true, "r1"),
            new ContainerManifestVolume(101, ContainerHex, "Backup", "F:\\", false, "r2"),
        ];
        Assert.Throws<ContainerManifestException>(
            () => ContainerManifestWriter.WriteManifest(ContainerHex, Device, 0, duplicates));
        Assert.Throws<ContainerManifestException>(
            () => ContainerManifestWriter.WriteManifest(
                ContainerHex, Device, 0, Array.Empty<ContainerManifestVolume>()));
    }

    [Fact]
    public void Write_RejectsDuplicateWindowsMountTargets()
    {
        IReadOnlyList<ContainerManifestVolume> duplicates =
        [
            new ContainerManifestVolume(101, ContainerHex, "Data", @"E:\Data\", true, "rec-101"),
            new ContainerManifestVolume(102, ContainerHex, "Backup", "e:/data", false, "rec-102"),
        ];

        Assert.Throws<ContainerManifestException>(
            () => ContainerManifestWriter.WriteManifest(ContainerHex, Device, 0, duplicates));
    }

    [Fact]
    public void Write_RejectsSharedOrMissingWritableRecoveryIdentity()
    {
        IReadOnlyList<ContainerManifestVolume> shared =
        [
            new ContainerManifestVolume(101, ContainerHex, "Data", "E:\\", true, "rec-shared"),
            new ContainerManifestVolume(102, ContainerHex, "Backup", "F:\\", false, "rec-shared"),
        ];
        IReadOnlyList<ContainerManifestVolume> missingWritable =
        [
            new ContainerManifestVolume(101, ContainerHex, "Data", "E:\\", true, null),
        ];

        Assert.Throws<ContainerManifestException>(
            () => ContainerManifestWriter.WriteManifest(ContainerHex, Device, 0, shared));
        Assert.Throws<ContainerManifestException>(
            () => ContainerManifestWriter.WriteManifest(ContainerHex, Device, 0, missingWritable));
    }

    public void Dispose()
    {
        foreach (var path in _writtenManifests)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
            }
        }
    }
}
