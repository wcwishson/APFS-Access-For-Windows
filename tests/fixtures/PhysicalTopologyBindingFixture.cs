using System.Text;

namespace ApfsAccess.TestFixtures;

// Codec projection for policy/transport tests; this grants no held-source authority.
public static class PhysicalTopologyBindingFixture
{
    public static string Encode(ulong bytes = 134217728)
    {
        using var data = new MemoryStream(); using var writer = new BinaryWriter(data, Encoding.ASCII, leaveOpen: true);
        void Number(ulong value) => writer.Write(value);
        void Text(string value) { Number((ulong)value.Length); writer.Write(Encoding.ASCII.GetBytes(value)); }
        Number(0x3646495653465041); Number(1);
        const string instance = @"USBSTOR\DISK&VEN_FICTIONAL&PROD_TOPOLOGY&REV_0001\TOPOLOGYTEST42&0";
        Number((ulong)instance.Length); foreach (var c in instance) Number(c);
        Number(1); Number(7); Text("Fictional"); Text("Topology Surrogate"); Text("0001"); Text("TOPOLOGYTEST42");
        writer.Write(Enumerable.Repeat((byte)0x31, 16).ToArray()); writer.Write(Enumerable.Repeat((byte)0x52, 16).ToArray());
        Number(1048576); Number(2UL << 30); Number(1048576); Number(bytes); Number(4UL << 30); Number(4096); Number(4096);
        writer.Flush(); return Convert.ToHexStringLower(data.ToArray());
    }
}
