using System.Text;
using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class VolumePhysicalBindingTests
{
    [Theory]
    [InlineData(4194304UL, 3145728UL, true)]
    [InlineData(4194304UL, 8388608UL, true)]
    [InlineData(4194304UL, 8392704UL, false)]
    [InlineData(8388608UL, 12582912UL, true)]
    [InlineData(8388608UL, 15728640UL, true)]
    [InlineData(8388608UL, 15732736UL, false)]
    [InlineData(4194304UL, 1048575UL, false)]
    [InlineData(4194304UL, 3145729UL, false)]
    [InlineData(4194304UL, ulong.MaxValue, false)]
    public void ResizeProjectionPreservesPrefixPartitionAndWholeDiskBounds(ulong sourceBytes, ulong targetBytes, bool allowed)
    {
        var binding = VolumePhysicalBinding.Parse(Binding(sourceBytes));
        Assert.Equal(8388608UL, binding.PartitionLengthBytes);
        Assert.Equal(sourceBytes, binding.Limit);
        Assert.Equal(allowed, binding.AllowsResizeTarget(targetBytes));
    }

    private static string Binding(ulong limit)
    {
        using var data = new MemoryStream();
        using var writer = new BinaryWriter(data, Encoding.ASCII, leaveOpen: true);
        void Number(ulong value) => writer.Write(value);
        void Text(string value) { Number((ulong)value.Length); writer.Write(Encoding.ASCII.GetBytes(value)); }
        Number(0x3646495653465041); Number(1);
        const string instance = @"USBSTOR\DISK&VEN_ACME\UNIT389";
        Number((ulong)instance.Length);
        foreach (var value in instance) Number(value);
        Number(1); Number(7);
        Text("ACME"); Text("DATA"); Text("1"); Text("FIXTURE-OWNER-389");
        writer.Write(Guid.Parse("11111111-2222-3333-4444-555555555555").ToByteArray(bigEndian: true));
        writer.Write(Guid.Parse("22222222-3333-4444-5555-666666666666").ToByteArray(bigEndian: true));
        Number(1048576); Number(8388608); Number(1048576); Number(limit); Number(16777216); Number(512); Number(4096);
        writer.Flush();
        return Convert.ToHexStringLower(data.ToArray());
    }
}
