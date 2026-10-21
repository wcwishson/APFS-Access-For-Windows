using System.Buffers.Binary;
using System.Text;

namespace ApfsAccess.StandardMount;

public readonly record struct StandardWireHeader(ushort Operation, uint PayloadBytes, ulong RequestId, Guid Epoch);
public sealed record StandardNativeStopReceipt(ulong Accepted, ulong Durable, ulong Cleaned, bool Clean, uint Status);

// This is APST framing, not an SMB parser. SMB messages remain owned by SMBLibrary.
public static class StandardWireCodec
{
    public const int HeaderBytes = 40;
    public const uint Magic = 0x54535041;
    private static readonly UnicodeEncoding Utf16 = new(false, false, true);

    public static byte[] EncodeHeader(StandardWireHeader header)
    {
        if (header.Operation > 20 || header.PayloadBytes > StandardNativeLimits.MaxFrameBytes - HeaderBytes)
            throw new InvalidDataException("APST header bounds invalid.");
        var bytes = new byte[HeaderBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, Magic);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(6), header.Operation);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), header.PayloadBytes);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16), header.RequestId);
        header.Epoch.TryWriteBytes(bytes.AsSpan(24));
        return bytes;
    }
    public static StandardWireHeader DecodeHeader(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != HeaderBytes || BinaryPrimitives.ReadUInt32LittleEndian(bytes) != Magic ||
            BinaryPrimitives.ReadUInt16LittleEndian(bytes[4..]) != 1 || BinaryPrimitives.ReadUInt32LittleEndian(bytes[12..]) != 0)
            throw new InvalidDataException("APST header invalid.");
        var op = BinaryPrimitives.ReadUInt16LittleEndian(bytes[6..]);
        var length = BinaryPrimitives.ReadUInt32LittleEndian(bytes[8..]);
        if (op > 20 || length > StandardNativeLimits.MaxFrameBytes - HeaderBytes) throw new InvalidDataException("APST frame bounds invalid.");
        return new(op, length, BinaryPrimitives.ReadUInt64LittleEndian(bytes[16..]), new Guid(bytes.Slice(24, 16)));
    }

    public static byte[] EncodeRequest(StandardNativeCall call, Guid ownerEpoch)
    {
        if (call.RequestId == 0 || ownerEpoch == Guid.Empty ||
            call.ClientEpoch == Guid.Empty && call.Request is not StandardQueryVolume)
            throw new InvalidDataException("APST request identity invalid.");
        using var buffer = new MemoryStream();
        using var writer = new BinaryWriter(buffer, Utf16, true);
        void Handle(StandardNativeHandle h)
        {
            if (!StandardValidation.Handle(h, ownerEpoch)) throw new InvalidDataException("APST handle epoch invalid.");
            writer.Write(h.OwnerEpoch.ToByteArray()); writer.Write(h.Id);
        }
        void Text(string text, bool pattern = false)
        {
            if (!StandardValidation.Text(text, pattern)) throw new InvalidDataException("APST path invalid.");
            writer.Write((uint)text.Length); writer.Write(Utf16.GetBytes(text));
        }
        void Bytes(ReadOnlyMemory<byte> bytes)
        {
            if (bytes.Length > StandardNativeLimits.MaxIoBytes) throw new InvalidDataException("APST payload bound exceeded.");
            writer.Write((uint)bytes.Length); writer.Write(bytes.Span);
        }
        void Range(long offset, long length)
        {
            if (!StandardValidation.Range(offset, length)) throw new InvalidDataException("APST range invalid.");
            writer.Write(offset); writer.Write(length);
        }
        switch (call.Request)
        {
            case StandardOpen r:
                writer.Write(r.DesiredAccess); writer.Write(r.ShareAccess); writer.Write(r.Attributes); writer.Write(r.Disposition); writer.Write(r.Options); Text(r.Path); break;
            case StandardHandleCall r when r.Kind is StandardNativeOperation.Cleanup or StandardNativeOperation.Close or StandardNativeOperation.Flush:
                Handle(r.Handle); break;
            case StandardRead r:
                Handle(r.Handle);
                if (r.Count < 0 || r.Count > StandardNativeLimits.MaxIoBytes || !StandardValidation.Range(r.Offset, r.Count)) throw new InvalidDataException("APST read bound invalid.");
                writer.Write(r.Offset); writer.Write(r.Count); break;
            case StandardWrite r:
                Handle(r.Handle);
                if (!StandardValidation.Range(r.Offset, r.Bytes.Length)) throw new InvalidDataException("APST write range invalid.");
                writer.Write(r.Offset); Bytes(r.Bytes); break;
            case StandardQueryFile r: Handle(r.Handle); writer.Write(r.InformationClass); break;
            case StandardSetFile r: Handle(r.Handle); writer.Write(r.InformationClass); Bytes(r.Bytes); break;
            case StandardQueryDirectory r: Handle(r.Handle); writer.Write(r.InformationClass); Text(r.Pattern, true); break;
            case StandardQueryVolume r: writer.Write(r.InformationClass); break;
            case StandardQuerySecurity r: Handle(r.Handle); writer.Write(r.Information); break;
            case StandardSetSecurity r: Handle(r.Handle); writer.Write(r.Information); Bytes(r.Descriptor); break;
            case StandardRangeLock r: Handle(r.Handle); Range(r.Offset, r.Length); writer.Write(r.Exclusive ? 1u : 0u); break;
            case StandardSparse r: Handle(r.Handle); writer.Write(r.Sparse ? 1u : 0u); break;
            case StandardZeroRange r:
                Handle(r.Handle);
                if (r.Offset < 0 || r.BeyondFinalZero < r.Offset) throw new InvalidDataException("APST zero range invalid.");
                writer.Write(r.Offset); writer.Write(r.BeyondFinalZero); break;
            case StandardAllocatedRanges r:
                Handle(r.Handle); Range(r.Offset, r.Length);
                if (r.MaxOutputBytes < 0 || r.MaxOutputBytes > StandardNativeLimits.MaxFrameBytes - 72) throw new InvalidDataException("APST output bound invalid.");
                writer.Write((uint)r.MaxOutputBytes); break;
            case StandardCloneRange r:
                Handle(r.Source); Handle(r.Destination);
                if (!StandardValidation.Range(r.SourceOffset, r.Length) || !StandardValidation.Range(r.DestinationOffset, r.Length)) throw new InvalidDataException("APST clone range invalid.");
                writer.Write(r.SourceOffset); writer.Write(r.DestinationOffset); writer.Write(r.Length); break;
            case StandardDisconnect: break;
            default: throw new InvalidDataException("APST operation invalid.");
        }
        if (buffer.Length > StandardNativeLimits.MaxFrameBytes - HeaderBytes) throw new InvalidDataException("APST frame bound exceeded.");
        var result = new byte[HeaderBytes + (int)buffer.Length];
        EncodeHeader(new((ushort)call.Request.Operation, (uint)buffer.Length, call.RequestId, call.ClientEpoch)).CopyTo(result, 0);
        buffer.GetBuffer().AsSpan(0, (int)buffer.Length).CopyTo(result.AsSpan(HeaderBytes));
        return result;
    }

    private static ReadOnlySpan<byte> Body(ReadOnlySpan<byte> frame, ushort operation, ulong requestId, Guid owner)
    {
        if (frame.Length < HeaderBytes) throw new InvalidDataException("Truncated APST frame.");
        var header = DecodeHeader(frame[..HeaderBytes]);
        if (header.Operation != operation || header.RequestId != requestId || owner == Guid.Empty || header.Epoch != owner ||
            header.PayloadBytes != frame.Length - HeaderBytes) throw new InvalidDataException("APST response binding invalid.");
        return frame[HeaderBytes..];
    }
    public static StandardNativeReply DecodeReply(ReadOnlySpan<byte> frame, StandardNativeCall call, Guid owner)
    {
        var bytes = Body(frame, (ushort)call.Request.Operation, call.RequestId, owner);
        if (bytes.Length < 32 || BinaryPrimitives.ReadUInt32LittleEndian(bytes[28..]) != 0 ||
            BinaryPrimitives.ReadUInt32LittleEndian(bytes[24..]) != bytes.Length - 32) throw new InvalidDataException("APST reply payload invalid.");
        var count = BinaryPrimitives.ReadUInt32LittleEndian(bytes[12..]);
        if (count > int.MaxValue) throw new InvalidDataException("APST reply count invalid.");
        return new(call.RequestId, owner, BinaryPrimitives.ReadUInt32LittleEndian(bytes),
            BinaryPrimitives.ReadUInt64LittleEndian(bytes[16..]), BinaryPrimitives.ReadUInt32LittleEndian(bytes[4..]),
            BinaryPrimitives.ReadUInt32LittleEndian(bytes[8..]), (int)count, bytes[32..].ToArray());
    }
    public static StandardNativeBinding DecodeHello(ReadOnlySpan<byte> frame, string expectedSource, string expectedVolume, ulong expectedCheckpoint)
    {
        if (frame.Length < HeaderBytes) throw new InvalidDataException("APST hello truncated.");
        var header = DecodeHeader(frame[..HeaderBytes]);
        var body = Body(frame, 0, 0, header.Epoch); var at = 0;
        var source = ReadText(body, ref at); var volume = ReadText(body, ref at);
        if (body.Length - at != 16 || source.Length == 0 || volume.Length == 0 || source != expectedSource || volume != expectedVolume) throw new InvalidDataException("APST selection binding invalid.");
        var checkpoint = BinaryPrimitives.ReadUInt64LittleEndian(body[at..]);
        var features = BinaryPrimitives.ReadUInt64LittleEndian(body[(at + 8)..]);
        if (expectedCheckpoint == 0 || checkpoint != expectedCheckpoint || (features & ~127ul) != 0 || (features & 1) == 0) throw new InvalidDataException("APST owner profile invalid.");
        return new(header.Epoch, source, volume, checkpoint, (StandardNativeFeatures)features);
    }
    private static string ReadText(ReadOnlySpan<byte> bytes, ref int at)
    {
        if (at > bytes.Length - 4) throw new InvalidDataException("APST string truncated.");
        var units = BinaryPrimitives.ReadUInt32LittleEndian(bytes[at..]); at += 4;
        if (units > StandardNativeLimits.MaxPathCodeUnits || units * 2 > bytes.Length - at) throw new InvalidDataException("APST string bound invalid.");
        string value;
        try { value = Utf16.GetString(bytes.Slice(at, (int)units * 2)); }
        catch (DecoderFallbackException) { throw new InvalidDataException("APST UTF16 invalid."); }
        at += (int)units * 2;
        if (value.Contains('\0')) throw new InvalidDataException("APST string NUL invalid.");
        return value;
    }
    public static StandardNativeStopReceipt DecodeStop(ReadOnlySpan<byte> frame, ulong requestId, Guid owner)
    {
        var bytes = Body(frame, 20, requestId, owner);
        if (bytes.Length != 32) throw new InvalidDataException("APST stop length invalid.");
        var accepted = BinaryPrimitives.ReadUInt64LittleEndian(bytes); var durable = BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]);
        var cleaned = BinaryPrimitives.ReadUInt64LittleEndian(bytes[16..]); var clean = BinaryPrimitives.ReadUInt32LittleEndian(bytes[24..]);
        if (clean > 1 || accepted < durable || durable < cleaned || clean == 1 && accepted != cleaned) throw new InvalidDataException("APST stop watermarks invalid.");
        return new(accepted, durable, cleaned, clean == 1, BinaryPrimitives.ReadUInt32LittleEndian(bytes[28..]));
    }
    public static byte[] EncodeStop(ulong requestId, Guid owner)
    {
        if (requestId == 0 || owner == Guid.Empty) throw new InvalidDataException("APST stop identity invalid.");
        return EncodeHeader(new(20, 0, requestId, owner));
    }
    public static async ValueTask<byte[]> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var headerBytes = new byte[HeaderBytes]; await stream.ReadExactlyAsync(headerBytes, cancellationToken).ConfigureAwait(false);
        var header = DecodeHeader(headerBytes); var result = new byte[HeaderBytes + header.PayloadBytes];
        headerBytes.CopyTo(result, 0); await stream.ReadExactlyAsync(result.AsMemory(HeaderBytes), cancellationToken).ConfigureAwait(false);
        return result;
    }
}
