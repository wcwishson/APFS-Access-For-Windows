using System.Buffers.Binary;
using SMBLibrary;

namespace ApfsAccess.StandardMount;

public readonly record struct StandardSmbFileId(ulong Persistent, ulong Volatile);

// Only a server integration with the real authenticated SMB session's FileId table
// can implement this. The returned object must still be a live handle in this store.
public interface IStandardSmbHandleResolver
{
    bool TryResolveSource(object destination, StandardSmbFileId source, out object? sourceHandle);
}

public static class StandardControlCodec
{
    public const uint SetSparse = 0x000900C4;
    public const uint ZeroData = 0x000980C8;
    public const uint QueryAllocatedRanges = 0x000940CF;
    public const uint DuplicateExtents = 0x00098344;

    public static NTStatus Decode(uint code, ReadOnlySpan<byte> input, StandardNativeHandle destination,
        int maxOutputBytes, Func<StandardSmbFileId, StandardNativeHandle?>? resolveSource,
        out StandardNativeRequest? request)
    {
        request = null;
        if (!StandardValidation.Handle(destination, destination.OwnerEpoch) || maxOutputBytes < 0 || maxOutputBytes > StandardNativeLimits.MaxFrameBytes - 72)
            return NTStatus.STATUS_INVALID_PARAMETER;
        switch (code)
        {
            case SetSparse:
                if (input.Length > 1 || input.Length == 1 && input[0] > 1) return NTStatus.STATUS_INVALID_PARAMETER;
                request = new StandardSparse(destination, input.IsEmpty || input[0] == 1); break;
            case ZeroData:
                if (input.Length != 16) return NTStatus.STATUS_INVALID_PARAMETER;
                var offset = BinaryPrimitives.ReadInt64LittleEndian(input);
                var end = BinaryPrimitives.ReadInt64LittleEndian(input[8..]);
                if (offset < 0 || end < offset) return NTStatus.STATUS_INVALID_PARAMETER;
                request = new StandardZeroRange(destination, offset, end); break;
            case QueryAllocatedRanges:
                if (input.Length != 16) return NTStatus.STATUS_INVALID_PARAMETER;
                offset = BinaryPrimitives.ReadInt64LittleEndian(input);
                var length = BinaryPrimitives.ReadInt64LittleEndian(input[8..]);
                if (!StandardValidation.Range(offset, length)) return NTStatus.STATUS_INVALID_PARAMETER;
                request = new StandardAllocatedRanges(destination, offset, length, maxOutputBytes); break;
            case DuplicateExtents:
                // MS-FSCC2.3.7.2: SMB FileId16, then three signed64-bit values.
                // A local HANDLE-based32-byte buffer is never the remote form.
                if (input.Length != 40) return NTStatus.STATUS_INVALID_PARAMETER;
                var id = new StandardSmbFileId(BinaryPrimitives.ReadUInt64LittleEndian(input), BinaryPrimitives.ReadUInt64LittleEndian(input[8..]));
                var sourceOffset = BinaryPrimitives.ReadInt64LittleEndian(input[16..]);
                var targetOffset = BinaryPrimitives.ReadInt64LittleEndian(input[24..]);
                length = BinaryPrimitives.ReadInt64LittleEndian(input[32..]);
                if (!StandardValidation.Range(sourceOffset, length) || !StandardValidation.Range(targetOffset, length)) return NTStatus.STATUS_INVALID_PARAMETER;
                if (resolveSource is null) return NTStatus.STATUS_NOT_SUPPORTED;
                var source = resolveSource(id);
                if (source is null || !StandardValidation.Handle(source.Value, destination.OwnerEpoch)) return NTStatus.STATUS_FILE_CLOSED;
                request = new StandardCloneRange(source.Value, destination, sourceOffset, targetOffset, length); break;
            default: return NTStatus.STATUS_NOT_SUPPORTED;
        }
        return NTStatus.STATUS_SUCCESS;
    }

    internal static bool ValidRanges(ReadOnlySpan<byte> output, StandardAllocatedRanges request)
    {
        if (output.Length > request.MaxOutputBytes || output.Length % 16 != 0) return false;
        long previousEnd = 0;
        var requestedEnd = request.Offset + request.Length;
        for (var at = 0; at < output.Length; at += 16)
        {
            var offset = BinaryPrimitives.ReadInt64LittleEndian(output[at..]);
            var length = BinaryPrimitives.ReadInt64LittleEndian(output[(at + 8)..]);
            // MS-FSCC permits allocation-boundary rounding outside the query;
            // each returned range must intersect it, and cannot overlap its predecessor.
            if (!StandardValidation.Range(offset, length) || length == 0 || offset < previousEnd ||
                offset >= requestedEnd || offset + length <= request.Offset) return false;
            previousEnd = offset + length;
        }
        return true;
    }
}
