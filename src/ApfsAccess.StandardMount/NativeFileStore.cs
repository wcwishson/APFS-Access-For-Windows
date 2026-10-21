using System.Net;
using System.IO.Enumeration;
using SMBLibrary;
using FileAttributes = SMBLibrary.FileAttributes;

namespace ApfsAccess.StandardMount;

public sealed class NativeFileStore : INTFileStore, ISMB2CloneFileStore, IAsyncDisposable
{
    private const NTStatus IoDeviceError = (NTStatus)0xC0000185;
    private const NTStatus DeviceNotReady = (NTStatus)0xC00000A3;
    private sealed class Client(object authentication)
    {
        internal readonly object Authentication = authentication;
        internal readonly Guid Epoch = Guid.NewGuid();
        internal int Opens;
    }
    private sealed class Open(NativeFileStore owner, Client client, StandardNativeHandle handle)
    {
        internal readonly NativeFileStore Owner = owner;
        internal readonly Client Client = client;
        internal readonly StandardNativeHandle Handle = handle;
        internal bool Cleaned;
    }
    private readonly object gate = new();
    private readonly IStandardNativeTransport transport;
    private readonly StandardNativeBinding binding;
    private readonly SemaphoreSlim retirementGate = new(1, 1);
    private readonly string principal;
    private readonly IStandardSmbHandleResolver? resolver;
    private readonly Dictionary<object, Client> clients = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<Open> opens = [];
    private ulong requestId;
    private int closed, protocolFailure, openCount;
    private StandardNativeRetirement? retirement;
    public bool HasFailed => Volatile.Read(ref protocolFailure) != 0;
    public int OpenCount => Volatile.Read(ref openCount);
    public StandardNativeBinding Binding => binding;

    public NativeFileStore(IStandardNativeTransport transport, string principal, IStandardSmbHandleResolver? resolver = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        var selected = transport.Binding;
        if (string.IsNullOrWhiteSpace(principal) || principal.Length > 64 || principal.Any(char.IsControl) ||
            selected.OwnerEpoch == Guid.Empty || string.IsNullOrEmpty(selected.SourceIdentity) ||
            string.IsNullOrEmpty(selected.VolumeIdentity) || selected.CheckpointXid == 0 ||
            !selected.Features.HasFlag(StandardNativeFeatures.OrdinaryIo) || ((ulong)selected.Features & ~127ul) != 0)
            throw new ArgumentException("A selected native owner and one authenticated principal are required.");
        this.transport = transport; binding = selected; this.principal = principal; this.resolver = resolver;
    }

    private bool Has(StandardNativeFeatures feature) => Binding.Features.HasFlag(feature);
    private bool Find(object value, out Open? result)
    {
        result = value as Open;
        return closed == 0 && !HasFailed && result is not null && ReferenceEquals(result.Owner, this) &&
            !result.Cleaned && opens.Contains(result);
    }
    private StandardNativeReply Call(Guid client, StandardNativeRequest request)
    {
        if (closed != 0) return new(requestId, Binding.OwnerEpoch, (uint)DeviceNotReady);
        if (HasFailed || requestId == ulong.MaxValue)
            return new(0, Binding.OwnerEpoch, (uint)IoDeviceError);
        var id = ++requestId;
        try
        {
            if (transport.Binding != binding) throw new IOException("Native owner selection changed.");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var reply = transport.InvokeAsync(new(id, client, request), timeout.Token).AsTask().GetAwaiter().GetResult();
            if (transport.Binding != binding || reply.RequestId != id || reply.OwnerEpoch != Binding.OwnerEpoch || reply.Count < 0 ||
                reply.Data.Length > StandardNativeLimits.MaxFrameBytes - 72)
                throw new IOException("Native reply binding or bounds invalid.");
            return reply;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Interlocked.Exchange(ref protocolFailure, 1);
            return new(id, Binding.OwnerEpoch, (uint)(e is OperationCanceledException ? NTStatus.STATUS_IO_TIMEOUT : IoDeviceError));
        }
    }
    private NTStatus With(object handle, Func<Open, NTStatus> action)
    {
        lock (gate) return Find(handle, out var h) ? action(h!) : NTStatus.STATUS_FILE_CLOSED;
    }
    private NTStatus CorruptReply()
    { Interlocked.Exchange(ref protocolFailure, 1); return IoDeviceError; }

    public NTStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess,
        FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
    {
        handle = null!; fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
        if (!StandardValidation.Text(path)) return NTStatus.STATUS_OBJECT_PATH_SYNTAX_BAD;
        lock (gate)
        {
            if (closed != 0 || HasFailed) return DeviceNotReady;
            if (securityContext?.AuthenticationContext is not {} authentication ||
                !string.Equals(securityContext.UserName, principal, StringComparison.OrdinalIgnoreCase) ||
                securityContext.ClientEndPoint is not {} endpoint || !IPAddress.IsLoopback(endpoint.Address))
                return NTStatus.STATUS_ACCESS_DENIED;
            if (opens.Count >= StandardNativeLimits.MaxOpenHandles) return NTStatus.STATUS_TOO_MANY_OPENED_FILES;
            if (!clients.TryGetValue(authentication, out var client))
            {
                if (clients.Count >= 16) return NTStatus.STATUS_INSUFFICIENT_RESOURCES;
                client = new(authentication); clients.Add(authentication, client);
            }
            var reply = Call(client.Epoch, new StandardOpen(path, (uint)desiredAccess, (uint)shareAccess,
                (uint)fileAttributes, (uint)createDisposition, (uint)createOptions));
            if (reply.Status != 0)
            {
                // A refused Open can still have admitted the epoch at the native boundary.
                // Keep it bounded and reusable until a real Disconnect or owner retirement.
                return (NTStatus)reply.Status;
            }
            if (reply.HandleId == 0 || reply.FileStatus > 3 ||
                opens.Any(h => h.Handle.Id == reply.HandleId)) return CorruptReply();
            var opened = new Open(this, client, new(Binding.OwnerEpoch, reply.HandleId));
            opens.Add(opened); client.Opens++; Interlocked.Increment(ref openCount);
            handle = opened; fileStatus = (FileStatus)reply.FileStatus; return NTStatus.STATUS_SUCCESS;
        }
    }

    public NTStatus CloseFile(object handle)
    {
        lock (gate)
        {
            if (closed != 0 || handle is not Open h || !ReferenceEquals(h.Owner, this) || !opens.Contains(h)) return NTStatus.STATUS_FILE_CLOSED;
            h.Cleaned = true;
            var cleanup = Call(h.Client.Epoch, new StandardHandleCall(StandardNativeOperation.Cleanup, h.Handle));
            var close = Call(h.Client.Epoch, new StandardHandleCall(StandardNativeOperation.Close, h.Handle));
            if (cleanup.Status != 0 || close.Status != 0)
            { Interlocked.Exchange(ref protocolFailure, 1); return (NTStatus)(cleanup.Status != 0 ? cleanup.Status : close.Status); }
            opens.Remove(h); h.Client.Opens--; Interlocked.Decrement(ref openCount);
            if (h.Client.Opens == 0)
            {
                var disconnected = Call(h.Client.Epoch, new StandardDisconnect());
                if (disconnected.Status != 0) { Interlocked.Exchange(ref protocolFailure, 1); return (NTStatus)disconnected.Status; }
                clients.Remove(h.Client.Authentication);
            }
            return NTStatus.STATUS_SUCCESS;
        }
    }
    public NTStatus ReadFile(out byte[] data, object handle, long offset, int count)
    {
        byte[] result = []; data = [];
        if (count < 0 || count > StandardNativeLimits.MaxSmbIoBytes || !StandardValidation.Range(offset, count)) return NTStatus.STATUS_INVALID_PARAMETER;
        var status = With(handle, h => {
            using var bytes = new MemoryStream(count);
            do {
                var size = Math.Min(StandardNativeLimits.MaxIoBytes, count - (int)bytes.Length);
                var r = Call(h.Client.Epoch, new StandardRead(h.Handle, offset + bytes.Length, size));
                if (r.Status == (uint)NTStatus.STATUS_END_OF_FILE && bytes.Length > 0) break;
                if (r.Status != 0) return (NTStatus)r.Status;
                if (r.Count > size || r.Count != r.Data.Length) return CorruptReply();
                bytes.Write(r.Data.Span);
                if (r.Count < size || size == 0) break;
            } while (bytes.Length < count);
            result = bytes.ToArray(); return NTStatus.STATUS_SUCCESS;
        });
        if (status == NTStatus.STATUS_SUCCESS) data = result;
        return status;
    }
    public NTStatus WriteFile(out int written, object handle, long offset, byte[] data)
    {
        var count = 0; written = 0;
        if (data is null || data.Length > StandardNativeLimits.MaxSmbIoBytes || !StandardValidation.Range(offset, data.Length)) return NTStatus.STATUS_INVALID_PARAMETER;
        var status = With(handle, h => {
            do {
                var size = Math.Min(StandardNativeLimits.MaxIoBytes, data.Length - count);
                var r = Call(h.Client.Epoch, new StandardWrite(h.Handle, offset + count, data.AsSpan(count, size).ToArray()));
                if (r.Count > size) return CorruptReply();
                count += r.Count;
                if (r.Status != 0) return (NTStatus)r.Status;
                if (r.Count < size || size == 0) break;
            } while (count < data.Length);
            // INTFileStore omits the individual SMB WriteThrough flag. A real
            // native flush after each successful write preserves that contract.
            return (NTStatus)Call(h.Client.Epoch, new StandardHandleCall(StandardNativeOperation.Flush, h.Handle)).Status;
        });
        written = count; return status;
    }
    public NTStatus FlushFileBuffers(object handle) => With(handle, h => (NTStatus)Call(h.Client.Epoch, new StandardHandleCall(StandardNativeOperation.Flush, h.Handle)).Status);
    public NTStatus LockFile(object handle, long offset, long length, bool exclusiveLock) => RangeLock(handle, offset, length, exclusiveLock, false);
    public NTStatus UnlockFile(object handle, long offset, long length) => RangeLock(handle, offset, length, false, true);
    private NTStatus RangeLock(object handle, long offset, long length, bool exclusive, bool unlock)
    {
        if (!StandardValidation.Range(offset, length) || length == 0) return NTStatus.STATUS_INVALID_PARAMETER;
        if (!Has(StandardNativeFeatures.ByteRangeLocks)) return NTStatus.STATUS_NOT_SUPPORTED;
        return With(handle, h => (NTStatus)Call(h.Client.Epoch, new StandardRangeLock(h.Handle, offset, length, exclusive, unlock)).Status);
    }

    public NTStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass)
    {
        FileInformation? parsed = null; result = null!;
        var status = With(handle, h => ParseReply(Call(h.Client.Epoch, new StandardQueryFile(h.Handle, (uint)informationClass)), bytes => {
            parsed = FileInformation.GetFileInformation(bytes, 0, informationClass);
            return parsed is not null && parsed.FileInformationClass == informationClass && parsed.Length == bytes.Length;
        }));
        if (status == NTStatus.STATUS_SUCCESS) result = parsed!;
        return status;
    }
    public NTStatus SetFileInformation(object handle, FileInformation information)
    {
        if (information is null) return NTStatus.STATUS_INVALID_PARAMETER;
        if (information is not (FileLinkInformationType2 or FileRenameInformationType2 or FileBasicInformation or
            FileDispositionInformation or FileAllocationInformation or FileEndOfFileInformation)) return NTStatus.STATUS_NOT_SUPPORTED;
        if (information is FileLinkInformationType2 link)
        {
            if (!Has(StandardNativeFeatures.HardLink)) return NTStatus.STATUS_NOT_SUPPORTED;
            if (link.RootDirectory != 0 || string.IsNullOrEmpty(link.FileName) || !StandardValidation.Text(link.FileName.StartsWith('\\') ? link.FileName : "\\" + link.FileName)) return NTStatus.STATUS_INVALID_PARAMETER;
        }
        if (information is FileRenameInformationType2 rename && (rename.RootDirectory != 0 || string.IsNullOrEmpty(rename.FileName) ||
            !StandardValidation.Text(rename.FileName.StartsWith('\\') ? rename.FileName : "\\" + rename.FileName))) return NTStatus.STATUS_INVALID_PARAMETER;
        byte[] bytes;
        try { bytes = information.GetBytes(); }
        catch (Exception e) when (e is ArgumentException or OverflowException) { return NTStatus.STATUS_INVALID_PARAMETER; }
        if (bytes.Length > StandardNativeLimits.MaxIoBytes) return NTStatus.STATUS_INVALID_PARAMETER;
        return With(handle, h => (NTStatus)Call(h.Client.Epoch, new StandardSetFile(h.Handle, (uint)information.FileInformationClass, bytes)).Status);
    }
    public NTStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, object handle, string pattern, FileInformationClass informationClass)
    {
        List<QueryDirectoryFileInformation> parsed = []; result = [];
        if (!StandardValidation.Text(pattern, true)) return NTStatus.STATUS_OBJECT_NAME_INVALID;
        var status = With(handle, h => ParseReply(Call(h.Client.Epoch, new StandardQueryDirectory(h.Handle, pattern, (uint)informationClass)), bytes => {
            parsed = QueryDirectoryFileInformation.ReadFileInformationList(bytes, 0, informationClass);
            return parsed.Count <= StandardNativeLimits.MaxDirectoryEntries && QueryDirectoryFileInformation.GetListLength(parsed) == bytes.Length &&
                parsed.All(entry => StandardValidation.Text(DirectoryName(entry), true));
        }));
        if (status == NTStatus.STATUS_SUCCESS)
        {
            var expression = FileSystemName.TranslateWin32Expression(pattern);
            result = parsed.Where(entry => FileSystemName.MatchesWin32Expression(expression, DirectoryName(entry),
                !Has(StandardNativeFeatures.CaseSensitiveNames))).ToList();
        }
        return status;
    }
    private static string? DirectoryName(QueryDirectoryFileInformation entry) => entry switch
    {
        FileDirectoryInformation r => r.FileName, FileFullDirectoryInformation r => r.FileName,
        FileBothDirectoryInformation r => r.FileName, FileIdBothDirectoryInformation r => r.FileName,
        FileIdFullDirectoryInformation r => r.FileName, FileNamesInformation r => r.FileName, _ => null
    };
    public NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass)
    {
        FileSystemInformation? parsed = null; result = null!;
        lock (gate)
        {
            if (closed != 0) return DeviceNotReady;
            var status = ParseReply(Call(Guid.Empty, new StandardQueryVolume((uint)informationClass)), bytes => {
                parsed = FileSystemInformation.GetFileSystemInformation(bytes, 0, informationClass);
                return parsed is not null && parsed.FileSystemInformationClass == informationClass && parsed.Length == bytes.Length &&
                    (parsed is not FileFsAttributeInformation attributes ||
                    (((uint)attributes.FileSystemAttributes & 1) != 0) == Has(StandardNativeFeatures.CaseSensitiveNames));
            });
            if (status == NTStatus.STATUS_SUCCESS) result = parsed!;
            return status;
        }
    }
    public NTStatus SetFileSystemInformation(FileSystemInformation information) => NTStatus.STATUS_NOT_SUPPORTED;
    public NTStatus GetSecurityInformation(out SecurityDescriptor descriptor, object handle, SecurityInformation information)
    {
        SecurityDescriptor? parsed = null; descriptor = null!;
        if (!Has(StandardNativeFeatures.Security)) return NTStatus.STATUS_NOT_SUPPORTED;
        var status = With(handle, h => ParseReply(Call(h.Client.Epoch, new StandardQuerySecurity(h.Handle, (uint)information)), bytes => {
            if (!StandardValidation.SelfRelativeDescriptor(bytes)) return false;
            parsed = new SecurityDescriptor(bytes, 0); return parsed.Length == bytes.Length;
        }));
        if (status == NTStatus.STATUS_SUCCESS) descriptor = parsed!;
        return status;
    }
    public NTStatus SetSecurityInformation(object handle, SecurityInformation information, SecurityDescriptor descriptor)
    {
        if (!Has(StandardNativeFeatures.Security)) return NTStatus.STATUS_NOT_SUPPORTED;
        if (descriptor is null) return NTStatus.STATUS_INVALID_PARAMETER;
        byte[] bytes;
        try { bytes = descriptor.GetBytes(); }
        catch (Exception e) when (e is ArgumentException or NullReferenceException or OverflowException) { return NTStatus.STATUS_INVALID_PARAMETER; }
        if (!StandardValidation.SelfRelativeDescriptor(bytes)) return NTStatus.STATUS_INVALID_PARAMETER;
        return With(handle, h => (NTStatus)Call(h.Client.Epoch, new StandardSetSecurity(h.Handle, (uint)information, bytes)).Status);
    }
    private NTStatus ParseReply(StandardNativeReply reply, Func<byte[], bool> parse)
    {
        if (reply.Status != 0) return (NTStatus)reply.Status;
        try { return parse(reply.Data.ToArray()) ? NTStatus.STATUS_SUCCESS : CorruptReply(); }
        catch (Exception e) when (e is not OutOfMemoryException) { return CorruptReply(); }
    }
    public NTStatus NotifyChange(out object handle, object fileHandle, NotifyChangeFilter filter, bool watchTree,
        int outputBufferSize, OnNotifyChangeCompleted callback, object context)
    { handle = null!; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus Cancel(object handle) => NTStatus.STATUS_NOT_SUPPORTED;

    public NTStatus DeviceIOControl(object handle, uint code, byte[] input, out byte[] output, int maxOutputLength)
    {
        byte[] result = []; output = [];
        var status = With(handle, h => {
            StandardNativeHandle? Resolve(StandardSmbFileId id) => resolver is not null && resolver.TryResolveSource(h, id, out var source) &&
                source is not null && Find(source, out var s) && ReferenceEquals(s!.Client, h.Client) ? s.Handle : null;
            var decoded = StandardControlCodec.Decode(code, input ?? [], h.Handle, maxOutputLength, resolver is null ? null : Resolve, out var request);
            if (decoded != NTStatus.STATUS_SUCCESS) return decoded;
            if (!Has(request is StandardCloneRange ? StandardNativeFeatures.Clone : StandardNativeFeatures.Sparse)) return NTStatus.STATUS_NOT_SUPPORTED;
            var r = Call(h.Client.Epoch, request!);
            if (r.Status != 0 && r.Status != (uint)NTStatus.STATUS_BUFFER_OVERFLOW) return (NTStatus)r.Status;
            if (r.Data.Length > maxOutputLength || request is StandardAllocatedRanges ranges && !StandardControlCodec.ValidRanges(r.Data.Span, ranges) ||
                request is not StandardAllocatedRanges && !r.Data.IsEmpty) return CorruptReply();
            result = r.Data.ToArray(); return (NTStatus)r.Status;
        });
        if (status is NTStatus.STATUS_SUCCESS or NTStatus.STATUS_BUFFER_OVERFLOW) output = result;
        return status;
    }
    public NTStatus CloneFileRange(object sourceHandle, object destinationHandle, long sourceOffset, long destinationOffset, long length)
    {
        if (!StandardValidation.Range(sourceOffset, length) || !StandardValidation.Range(destinationOffset, length)) return NTStatus.STATUS_INVALID_PARAMETER;
        if (!Has(StandardNativeFeatures.Clone)) return NTStatus.STATUS_NOT_SUPPORTED;
        lock (gate)
        {
            if (!Find(sourceHandle, out var source) || !Find(destinationHandle, out var destination) ||
                !ReferenceEquals(source!.Client, destination!.Client)) return NTStatus.STATUS_FILE_CLOSED;
            return (NTStatus)Call(destination.Client.Epoch, new StandardCloneRange(source.Handle, destination.Handle, sourceOffset, destinationOffset, length)).Status;
        }
    }

    public async ValueTask<StandardNativeRetirement> RetireAsync(CancellationToken cancellationToken)
    {
        await retirementGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
        lock (gate) { if (retirement is { OriginalOwnerAbsent: true, NamespaceAbsent: true }) return retirement; closed = 1; }
        // The supervised transport owns Stop/exit/retained-process-handle proof.
        // Releasing a managed dictionary is never owner or durability evidence.
        var result = await transport.RetireAsync(cancellationToken).ConfigureAwait(false);
        lock (gate)
        {
            retirement = HasFailed || !StandardValidation.Clean(result) ? result with { Clean = false } : result;
            if (result.OriginalOwnerAbsent) { opens.Clear(); clients.Clear(); Interlocked.Exchange(ref openCount, 0); }
            return retirement;
        }
        }
        finally { retirementGate.Release(); }
    }
    public async ValueTask DisposeAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var result = await RetireAsync(timeout.Token).ConfigureAwait(false);
        if (!result.OriginalOwnerAbsent) throw new IOException("Original native owner remains reserved.");
        await transport.DisposeAsync().ConfigureAwait(false);
    }
}
