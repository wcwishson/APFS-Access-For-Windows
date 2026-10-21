namespace ApfsAccess.StandardMount;

public enum StandardNativeOperation : ushort
{
    Open = 1, Cleanup = 2, Close = 3, Read = 4, Write = 5, Flush = 6,
    QueryFile = 7, SetFile = 8, QueryDirectory = 9, QueryVolume = 10,
    QuerySecurity = 11, SetSecurity = 12, Lock = 13, Unlock = 14,
    SetSparse = 15, ZeroRange = 16, QueryAllocatedRanges = 17, CloneRange = 18,
    Disconnect = 19, Stop = 20
}

[Flags]
public enum StandardNativeFeatures : ulong
{
    None = 0, OrdinaryIo = 1, Security = 2, ByteRangeLocks = 4,
    Sparse = 8, Clone = 16, HardLink = 32, CaseSensitiveNames = 64
}

public readonly record struct StandardNativeHandle(Guid OwnerEpoch, ulong Id);
public sealed record StandardNativeBinding(Guid OwnerEpoch, string SourceIdentity, string VolumeIdentity,
    ulong CheckpointXid, StandardNativeFeatures Features);

// The transport is created only by the explicit, exclusively supervised native-owner launch.
// IDs are process-epoch capabilities, never OS handles, SMB FileIds, paths or inode authority.
public interface IStandardNativeTransport : IAsyncDisposable
{
    StandardNativeBinding Binding { get; }
    ValueTask<StandardNativeReply> InvokeAsync(StandardNativeCall call, CancellationToken cancellationToken);
    ValueTask<StandardNativeRetirement> RetireAsync(CancellationToken cancellationToken);
}

public sealed record StandardNativeCall(ulong RequestId, Guid ClientEpoch, StandardNativeRequest Request);
public abstract record StandardNativeRequest(StandardNativeOperation Operation);
public sealed record StandardOpen(string Path, uint DesiredAccess, uint ShareAccess, uint Attributes,
    uint Disposition, uint Options) : StandardNativeRequest(StandardNativeOperation.Open);
public sealed record StandardHandleCall(StandardNativeOperation Kind, StandardNativeHandle Handle)
    : StandardNativeRequest(Kind);
public sealed record StandardRead(StandardNativeHandle Handle, long Offset, int Count)
    : StandardNativeRequest(StandardNativeOperation.Read);
public sealed record StandardWrite(StandardNativeHandle Handle, long Offset, ReadOnlyMemory<byte> Bytes)
    : StandardNativeRequest(StandardNativeOperation.Write);
public sealed record StandardQueryFile(StandardNativeHandle Handle, uint InformationClass)
    : StandardNativeRequest(StandardNativeOperation.QueryFile);
public sealed record StandardSetFile(StandardNativeHandle Handle, uint InformationClass, ReadOnlyMemory<byte> Bytes)
    : StandardNativeRequest(StandardNativeOperation.SetFile);
public sealed record StandardQueryDirectory(StandardNativeHandle Handle, string Pattern, uint InformationClass)
    : StandardNativeRequest(StandardNativeOperation.QueryDirectory);
public sealed record StandardQueryVolume(uint InformationClass)
    : StandardNativeRequest(StandardNativeOperation.QueryVolume);
public sealed record StandardQuerySecurity(StandardNativeHandle Handle, uint Information)
    : StandardNativeRequest(StandardNativeOperation.QuerySecurity);
public sealed record StandardSetSecurity(StandardNativeHandle Handle, uint Information, ReadOnlyMemory<byte> Descriptor)
    : StandardNativeRequest(StandardNativeOperation.SetSecurity);
public sealed record StandardRangeLock(StandardNativeHandle Handle, long Offset, long Length, bool Exclusive, bool Unlock)
    : StandardNativeRequest(Unlock ? StandardNativeOperation.Unlock : StandardNativeOperation.Lock);
public sealed record StandardSparse(StandardNativeHandle Handle, bool Sparse)
    : StandardNativeRequest(StandardNativeOperation.SetSparse);
public sealed record StandardZeroRange(StandardNativeHandle Handle, long Offset, long BeyondFinalZero)
    : StandardNativeRequest(StandardNativeOperation.ZeroRange);
public sealed record StandardAllocatedRanges(StandardNativeHandle Handle, long Offset, long Length, int MaxOutputBytes)
    : StandardNativeRequest(StandardNativeOperation.QueryAllocatedRanges);
public sealed record StandardCloneRange(StandardNativeHandle Source, StandardNativeHandle Destination,
    long SourceOffset, long DestinationOffset, long Length)
    : StandardNativeRequest(StandardNativeOperation.CloneRange);
public sealed record StandardDisconnect() : StandardNativeRequest(StandardNativeOperation.Disconnect);

// Data is the bounded Windows NT information buffer for the requested information class,
// or read/range-query bytes. No pointer-valued structure is admitted on this boundary.
public sealed record StandardNativeReply(ulong RequestId, Guid OwnerEpoch, uint Status,
    ulong HandleId = 0, uint FileStatus = 0, uint GrantedAccess = 0, int Count = 0,
    ReadOnlyMemory<byte> Data = default);
public sealed record StandardNativeRetirement(bool OriginalOwnerAbsent, bool NamespaceAbsent,
    bool Clean, ulong AcceptedSequence, ulong DurableSequence, ulong CleanedSequence, uint Status);

public static class StandardNativeLimits
{
    public const int ProtocolVersion = 1;
    public const int MaxFrameBytes = 1 << 20;
    public const int MaxIoBytes = 65536;
    public const int MaxSmbIoBytes = 1 << 20;
    public const int MaxPathCodeUnits = 16384;
    public const int MaxOpenHandles = 4096;
    public const int MaxDirectoryEntries = 4096;
}
