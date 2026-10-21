using System.Text;
using System.Buffers.Binary;

namespace ApfsAccess.StandardMount;

internal static class StandardValidation
{
    private static readonly UnicodeEncoding Utf16 = new(false, false, true);

    internal static bool Text(string? value, bool pattern = false)
    {
        if (value is null || value.Length > StandardNativeLimits.MaxPathCodeUnits ||
            value.Any(c => c == '\0' || char.IsControl(c))) return false;
        try { _ = Utf16.GetByteCount(value); }
        catch (EncoderFallbackException) { return false; }
        if (pattern) return value.Length > 0 && !value.Contains('\\') && !value.Contains('/') && !value.Contains(':');
        if (value.Length == 0 || value == "\\") return true;
        if (value[0] != '\\' || value.StartsWith("\\\\", StringComparison.Ordinal) || value.Contains('/')) return false;
        var parts = value[1..].Split('\\');
        return !parts.Any(p => p.Length == 0 || p is "." or "..") && !parts[..^1].Any(p => p.Contains(':'));
    }

    internal static bool Range(long offset, long length) => offset >= 0 && length >= 0 && offset <= long.MaxValue - length;
    internal static bool SelfRelativeDescriptor(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 20 || bytes.Length > StandardNativeLimits.MaxIoBytes || bytes[0] != 1 ||
            (BinaryPrimitives.ReadUInt16LittleEndian(bytes[2..]) & 0x8000) == 0) return false;
        for (var at = 4; at < 20; at += 4)
        {
            var offset = BinaryPrimitives.ReadUInt32LittleEndian(bytes[at..]);
            if (offset != 0 && (offset < 20 || offset >= bytes.Length || offset % 4 != 0)) return false;
        }
        return true;
    }
    internal static bool Handle(StandardNativeHandle handle, Guid owner) => owner != Guid.Empty && handle.OwnerEpoch == owner && handle.Id != 0;
    internal static bool Clean(StandardNativeRetirement r) => r.Status == 0 && r.Clean && r.OriginalOwnerAbsent && r.NamespaceAbsent &&
        r.AcceptedSequence == r.DurableSequence && r.DurableSequence == r.CleanedSequence;
}
