using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class XattrCommandTests
{
    [Fact]
    public void NativeStreamListPreservesExactCaseAndLongUtf8Names()
    {
        var longName = "user." + new string('\u4e2d', 90);
        var buffer = Streams(("::$DATA", 321), (":APFS.Xattr.757365722E41:$DATA", 7),
            (":APFS.Xattr.757365722e61:$DATA", 9), (XattrCommand.StreamName(longName), 8193),
            (":APFS.ResourceFork:$DATA", 9));
        var values = XattrCommand.ParseStreamInformation(buffer);
        Assert.Equal(3, values.Count);
        Assert.Contains(values, x => x.Name == "user.A" && x.Bytes == 7);
        Assert.Contains(values, x => x.Name == "user.a" && x.Bytes == 9);
        Assert.Contains(values, x => x.Name == longName && x.Bytes == 8193);
    }

    [Fact]
    public void NativeStreamListRejectsInvalidLinksLengthsAndDuplicateAttributes()
    {
        var good = Streams((":APFS.Xattr.61:$DATA", 1), (":APFS.Xattr.62:$DATA", 2));
        foreach (var next in new uint[] { 1, 8, uint.MaxValue, (uint)good.Length })
        {
            var invalid = good.ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(invalid, next);
            Assert.Throws<InvalidDataException>(() => XattrCommand.ParseStreamInformation(invalid));
        }
        var malformed = good.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(malformed.AsSpan(4), uint.MaxValue);
        Assert.Throws<InvalidDataException>(() => XattrCommand.ParseStreamInformation(malformed));
        var duplicates = Streams((":APFS.Xattr.6A:$DATA", 1), (":apfs.xattr.6a:$data", 1));
        Assert.Throws<InvalidDataException>(() => XattrCommand.ParseStreamInformation(duplicates));
        Assert.Throws<InvalidDataException>(() => XattrCommand.ParseStreamInformation(good.AsSpan(0, 23)));
    }

    [Theory]
    [InlineData(":APFS.Xattr.0:$DATA")]
    [InlineData(":APFS.Xattr.GG:$DATA")]
    [InlineData(":APFS.Xattr.C080:$DATA")]
    [InlineData(":APFS.Xattr.00:$DATA")]
    [InlineData(":APFS.Xattr.:$DATA")]
    [InlineData(":APFS.Xattr.61:$INDEX_ALLOCATION")]
    public void MalformedAttributeStreamIsNotSilentlyIgnored(string name)
        => Assert.Throws<InvalidDataException>(() => XattrCommand.AttributeName(name));

    [Fact]
    public async Task NonApfsWriteRefusesWithoutCreatingAnAdsOrChangingTheBase()
    {
        var root = Path.Combine(Path.GetTempPath(), "ApfsXattrCli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "owner.txt");
        var input = Path.Combine(root, "input.bin");
        File.WriteAllText(path, "preserve this file");
        File.WriteAllBytes(input, [1, 2, 3, 4]);
        try
        {
            var prior = Console.Out;
            using var output = new StringWriter();
            int code;
            try
            {
                Console.SetOut(output);
                code = await Program.RunForTestAsync(["xattr", "write", "--path", path,
                    "--name", "user.probe", "--input", input]);
            }
            finally { Console.SetOut(prior); }
            Assert.Equal(5, code);
            using var result = JsonDocument.Parse(output.ToString());
            Assert.False(result.RootElement.GetProperty("success").GetBoolean());
            Assert.Contains("mounted APFS", result.RootElement.GetProperty("error").GetString());
            Assert.Equal("preserve this file", File.ReadAllText(path));
            Assert.False(File.Exists(path + XattrCommand.StreamName("user.probe")));
        }
        finally
        {
            File.Delete(input);
            File.Delete(path);
            Directory.Delete(root);
        }
    }

    [Theory]
    [InlineData("relative")]
    [InlineData(@"\\.\PhysicalDrive2")]
    [InlineData(@"\\?\GLOBALROOT\Device\Harddisk0")]
    [InlineData("//./PhysicalDrive2")]
    [InlineData("//?/GLOBALROOT/Device/Harddisk0")]
    [InlineData(@"D:\file:stream")]
    public void DeviceAndStreamTargetsAreRejected(string path)
        => Assert.Throws<ArgumentException>(() => XattrCommand.ValidateFilePath(path));

    [Fact]
    public void MissingOrWrongProviderProtocolRefusesWithoutCreatingIt()
    {
        var path = Path.Combine(Path.GetTempPath(), "ApfsXattrProtocol-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, "base contents");
        try
        {
            Assert.Throws<NotSupportedException>(() => XattrCommand.VerifyProviderProtocol(path));
            Assert.False(File.Exists(path + XattrCommand.ProtocolStream));
            File.WriteAllText(path + XattrCommand.ProtocolStream, "APFS-XATTR/2\n");
            Assert.Throws<InvalidDataException>(() => XattrCommand.VerifyProviderProtocol(path));
            File.WriteAllText(path + XattrCommand.ProtocolStream, "APFS-XATTR/1\n");
            XattrCommand.VerifyProviderProtocol(path);
            Assert.Equal("base contents", File.ReadAllText(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void DataReadProtocolPinBlocksBaseRenameButAllowsAnotherStreamDeletion()
    {
        var path = Path.Combine(Path.GetTempPath(), "ApfsXattrPin-" + Guid.NewGuid().ToString("N"));
        var moved = path + ".moved";
        File.WriteAllText(path, "base contents");
        File.WriteAllText(path + XattrCommand.ProtocolStream, "APFS-XATTR/1\n");
        var attribute = path + XattrCommand.StreamName("user.pin");
        File.WriteAllBytes(attribute, [1, 2, 3]);
        try
        {
            using (var pin = new FileStream(path + XattrCommand.ProtocolStream, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                Assert.Throws<IOException>(() => File.Move(path, moved));
                File.Delete(attribute);
                Assert.False(File.Exists(attribute));
                Assert.Equal("base contents", File.ReadAllText(path));
            }
            File.Move(path, moved);
            Assert.False(File.Exists(path));
        }
        finally { File.Delete(path); File.Delete(moved); }
    }

    private static byte[] Streams(params (string Name, long Bytes)[] entries)
    {
        var sizes = entries.Select(x => (24 + Encoding.Unicode.GetByteCount(x.Name) + 7) & ~7).ToArray();
        var buffer = new byte[sizes.Sum()];
        var offset = 0;
        for (var i = 0; i < entries.Length; i++)
        {
            var name = Encoding.Unicode.GetBytes(entries[i].Name);
            var record = buffer.AsSpan(offset, sizes[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(record, i + 1 == entries.Length ? 0 : (uint)sizes[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(record[4..], (uint)name.Length);
            BinaryPrimitives.WriteInt64LittleEndian(record[8..], entries[i].Bytes);
            name.CopyTo(record[24..]);
            offset += sizes[i];
        }
        return buffer;
    }
}
