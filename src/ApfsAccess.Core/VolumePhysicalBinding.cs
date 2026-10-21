using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ApfsAccess.Core;

// A checked projection of VolumePhysicalBindingCodec.h, not a source capability.
public sealed class VolumePhysicalBinding
{
    public string Instance { get; private init; } = "";
    public string Serial { get; private init; } = "";
    public ulong DiskBytes { get; private init; }
    public ulong PartitionLengthBytes { get; private init; }
    public string Vendor { get; private init; } = "";
    public string Product { get; private init; } = "";
    public string Revision { get; private init; } = "";
    public Guid DiskGuid { get; private init; }
    public Guid PartitionGuid { get; private init; }
    public ulong BaseOffset { get; private init; }
    public ulong Limit { get; private init; }
    public string SourceIdentity { get; private init; } = "";
    private VolumePhysicalBinding() { }

    public bool AllowsResizeTarget(ulong targetBytes) => targetBytes is >= 1048576 and <= (1UL << 40) &&
        targetBytes % 4096 == 0 && targetBytes <= DiskBytes - BaseOffset &&
        (Limit == PartitionLengthBytes || targetBytes <= PartitionLengthBytes);

    public static bool IsDevicePath(string? path)
    {
        const string prefix = @"\\.\PhysicalDrive";
        return path is not null && path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            path.Length <= prefix.Length + 8 && VolumeTopologyProfile.Number(path[prefix.Length..]);
    }

    public static VolumePhysicalBinding Parse(string hex)
    {
        Need(hex is { Length: > 0 and <= 8192 } && hex.Length % 2 == 0 && hex.All(char.IsAsciiHexDigitLower));
        var bytes = Convert.FromHexString(hex); var at = 0;
        ulong Number()
        {
            Need(at <= bytes.Length - 8);
            var value = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(at, 8)); at += 8; return value;
        }
        string Text()
        {
            var length = Number(); Need(length <= 128 && length <= (ulong)(bytes.Length - at));
            foreach (var c in bytes.AsSpan(at, (int)length)) Need(c is >= 32 and <= 126);
            var value = Encoding.ASCII.GetString(bytes, at, (int)length); at += (int)length;
            Need(value.All(c => c is >= ' ' and <= '~') && (value.Length == 0 || value[0] != ' ' && value[^1] != ' '));
            return value;
        }
        Guid GuidValue()
        {
            Need(at <= bytes.Length - 16); var value = new Guid(bytes.AsSpan(at, 16), bigEndian: true); at += 16;
            Need(value != Guid.Empty); return value;
        }
        Need(Number() == 0x3646495653465041 && Number() == 1);
        var count = Number(); Need(count is > 0 and <= 400 && count <= (ulong)(bytes.Length - at) / 8);
        var instanceBuilder = new StringBuilder((int)count);
        for (ulong i = 0; i < count; ++i) { var c = Number(); Need(c is >= 33 and <= 126 && c is not (>= 97 and <= 122)); instanceBuilder.Append((char)c); }
        var instance = instanceBuilder.ToString(); var parts = instance.Split('\\');
        Need(parts.Length >= 3 && parts.All(p => p.Length > 0) && !instance.Contains(':'));
        Need(Number() == 1 && Number() == 7);
        var vendor = Text(); var product = Text(); var revision = Text(); var serial = Text();
        Need(NonGeneric(vendor) && NonGeneric(product) && NonGeneric(serial));
        var disk = GuidValue(); var partition = GuidValue();
        var partitionOffset = Number(); var partitionLength = Number(); var start = Number(); var limit = Number(); var size = Number();
        var logical = Number(); var physical = Number();
        static bool Sector(ulong value) => value is >= 512 and <= 65536 && (value & (value - 1)) == 0;
        Need(at == bytes.Length && size is > 0 and <= long.MaxValue && Sector(logical) && logical <= 4096 &&
            (physical == 0 || Sector(physical) && physical >= logical) && size % logical == 0 &&
            start == partitionOffset && start % 4096 == 0 && partitionOffset % logical == 0 && partitionLength % logical == 0 &&
            partitionOffset <= size && partitionLength <= size - partitionOffset && limit is >= 1048576 and <= (1UL << 40) &&
            limit % 4096 == 0 && limit % logical == 0 && limit <= partitionLength);
        using var material = new MemoryStream();
        void Put(ulong value) { Span<byte> buffer = stackalloc byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(buffer, value); material.Write(buffer); }
        void PutText(string value) { var text = Encoding.ASCII.GetBytes(value); Put((ulong)text.Length); material.Write(text); }
        PutText("volume-physical-source-v1"); Put((ulong)instance.Length);
        foreach (var c in instance) Put(c);
        PutText(serial);
        var identity = Convert.ToHexStringLower(SHA256.HashData(material.ToArray()).AsSpan(0, 24)) +
            start.ToString("x16", CultureInfo.InvariantCulture) + (start + limit).ToString("x16", CultureInfo.InvariantCulture);
        return new() { Instance = instance, Serial = serial, DiskBytes = size, Vendor = vendor, Product = product, Revision = revision, DiskGuid = disk, PartitionGuid = partition,
            BaseOffset = start, Limit = limit, PartitionLengthBytes = partitionLength, SourceIdentity = identity };
    }

    private static bool NonGeneric(string text)
    {
        var folded = new string(text.Where(c => c is not (' ' or '-' or '_' or '.' or '/' or ':')).Select(char.ToUpperInvariant).ToArray());
        return folded is not ("" or "NA" or "NONE" or "NULL" or "UNKNOWN" or "DEFAULT" or "GENERIC" or "USB" or "SERIAL" or
            "SERIALNUMBER" or "NOTSPECIFIED" or "NOTAVAILABLE" or "TOBEFILLEDBYOEM" or "123456789" or "0123456789") &&
            !folded.All(c => c == folded[0]);
    }
    private static void Need(bool ok) { if (!ok) throw new InvalidDataException("VolumePhysicalBindingInvalid"); }
}
