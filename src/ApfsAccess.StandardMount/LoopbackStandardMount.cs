using System.Net;
using System.Security.Cryptography;
using SMBLibrary;
using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.Authentication.NTLM;
using SMBLibrary.Server;

namespace ApfsAccess.StandardMount;

public sealed record StandardShareOptions(string ShareName, int TcpPort)
{
    public string LoopbackAddress { get; init; } = "127.0.0.1";
    public string RemotePath => @"\\" + LoopbackAddress + @"\" + ShareName;
    public bool IsValid => TcpPort is > 1024 and <= 65535 && ShareName is { Length: > 0 and <= 64 } &&
        ShareName.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-') && ValidAddress(LoopbackAddress);
    internal static bool ValidAddress(string? text) => IPAddress.TryParse(text, out var address) &&
        address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && address.GetAddressBytes()[0] == 127 &&
        address.ToString() == text;
    public static StandardShareOptions Create(int port) => new("APFS_" + Guid.NewGuid().ToString("N"), port);
}

public sealed class StandardSmbCredential : IDisposable
{
    private string? password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    public string UserName { get; } = "apfs_" + Guid.NewGuid().ToString("N");
    internal string? PasswordFor(string user) => string.Equals(user, UserName, StringComparison.OrdinalIgnoreCase) ? password : null;
    internal string RequirePassword() => password ?? throw new ObjectDisposedException(nameof(StandardSmbCredential));
    public void Dispose() => password = null;
    public override string ToString() => "Ephemeral loopback authentication";
}

public interface IStandardMappingLease
{
    string RemotePath { get; }
    ValueTask ConnectAsync(StandardSmbCredential credential, CancellationToken cancellationToken);
    ValueTask<bool> RemoveOwnedMappingAsync(CancellationToken cancellationToken);
}
public interface IStandardMappingController
{
    IStandardMappingLease Reserve(StandardShareOptions options);
}
public interface IStandardSmbListener
{
    bool RequiresSigning { get; }
    bool IsStopped => false;
    void Start();
    void Stop();
}
public enum StandardMountPhase { Created, Starting, Serving, Stopping, Closed, Failed }
public sealed record StandardMountStatus(StandardMountPhase Phase, bool MappingPresent, int OpenHandles, bool NativeProtocolFailed);
public sealed record StandardMountRetirement(bool MappingAbsent, bool ListenerStopped, StandardNativeRetirement Native)
{
    public bool Clean => MappingAbsent && ListenerStopped && StandardValidation.Clean(Native);
}

internal sealed class LibraryLoopbackListener : SMBServer, IStandardSmbListener
{
    private readonly StandardShareOptions options;
    private System.Runtime.InteropServices.SafeHandle? listenerHandle;
    public bool RequiresSigning => RequireSigning;
    public bool IsStopped => listenerHandle is null ? ListenerClosed : listenerHandle.IsClosed;
    internal LibraryLoopbackListener(NativeFileStore store, StandardShareOptions options, StandardSmbCredential credential)
        : base(Shares(store, options, credential), new GSSProvider(new IndependentNTLMAuthenticationProvider(credential.PasswordFor)), true)
    {
        this.options = options;
        ConnectionRequested += (_, request) => request.Accept = IPAddress.IsLoopback(request.IPEndPoint.Address);
    }
    private static SMBShareCollection Shares(NativeFileStore store, StandardShareOptions options, StandardSmbCredential credential)
    {
        var share = new FileSystemShare(options.ShareName, store, CachingPolicy.NoCaching);
        share.AccessRequested += (_, request) => request.Allow = string.Equals(request.UserName, credential.UserName, StringComparison.OrdinalIgnoreCase);
        return new() { share };
    }
    public void Start()
    {
        try { Start(IPAddress.Parse(options.LoopbackAddress), SMBTransportType.DirectTCPTransport, options.TcpPort,
            false, true, true, TimeSpan.FromSeconds(30)); }
        finally { listenerHandle = RetainListenerHandle(); }
    }
}

public sealed class LoopbackStandardMount : IAsyncDisposable
{
    private readonly SemaphoreSlim lifecycle = new(1, 1);
    private readonly NativeFileStore store;
    private readonly IStandardMappingController mappings;
    private readonly IStandardSmbListener listener;
    private readonly StandardSmbCredential credential;
    private readonly StandardShareOptions options;
    private IStandardMappingLease? mapping;
    private bool listenerAttempted, listenerStopped;
    private int phase, mappingPresent;
    public StandardMountStatus CachedStatus => new((StandardMountPhase)Volatile.Read(ref phase), Volatile.Read(ref mappingPresent) != 0, store.OpenCount, store.HasFailed);

    public LoopbackStandardMount(IStandardNativeTransport transport, StandardShareOptions options, IStandardMappingController mappings,
        IStandardSmbHandleResolver? cloneResolver = null)
        : this(transport, options, mappings, cloneResolver, null) { }

    internal LoopbackStandardMount(IStandardNativeTransport transport, StandardShareOptions options, IStandardMappingController mappings,
        IStandardSmbHandleResolver? cloneResolver, Func<NativeFileStore, StandardShareOptions, StandardSmbCredential, IStandardSmbListener>? listenerFactory)
    {
        if (!options.IsValid) throw new ArgumentException("An explicit bounded loopback share is required.");
        ArgumentNullException.ThrowIfNull(mappings);
        this.options = options; this.mappings = mappings; credential = new();
        store = new(transport, credential.UserName, cloneResolver);
        listener = listenerFactory?.Invoke(store, options, credential) ?? new LibraryLoopbackListener(store, options, credential);
    }
    public async ValueTask StartAsync(CancellationToken cancellationToken)
    {
        await lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (phase != (int)StandardMountPhase.Created) throw new InvalidOperationException("This provider already owns a lifecycle.");
            Volatile.Write(ref phase, (int)StandardMountPhase.Starting);
            if (!listener.RequiresSigning) throw new NotSupportedException("A server-enforced signing policy is required.");
            mapping = mappings.Reserve(options);
            if (mapping.RemotePath != options.RemotePath) throw new IOException("Mapping identity differs from the owned share.");
            listenerAttempted = true; listener.Start();
            Volatile.Write(ref mappingPresent, 1);
            await mapping.ConnectAsync(credential, cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref mappingPresent, 1); Volatile.Write(ref phase, (int)StandardMountPhase.Serving);
        }
        catch { Volatile.Write(ref phase, (int)StandardMountPhase.Failed); throw; }
        finally { lifecycle.Release(); }
    }
    public async ValueTask<StandardMountRetirement> StopAsync(CancellationToken cancellationToken)
    {
        await lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Volatile.Write(ref phase, (int)StandardMountPhase.Stopping);
            var absent = mapping is null;
            if (mapping is not null)
            {
                try { absent = await mapping.RemoveOwnedMappingAsync(cancellationToken).ConfigureAwait(false); }
                catch (Exception e) when (e is IOException or OperationCanceledException) { absent = false; }
                if (absent) { mapping = null; Volatile.Write(ref mappingPresent, 0); }
            }
            if (!listenerAttempted) listenerStopped = true;
            if (!listenerStopped)
            {
                try { listener.Stop(); listenerStopped = listener.IsStopped; }
                catch (Exception e) when (e is IOException or InvalidOperationException or System.Net.Sockets.SocketException) { listenerStopped = false; }
            }
            var retired = await store.RetireAsync(cancellationToken).ConfigureAwait(false);
            var result = new StandardMountRetirement(absent, listenerStopped, retired);
            Volatile.Write(ref phase, (int)(result.Clean ? StandardMountPhase.Closed : StandardMountPhase.Failed));
            if (absent && listenerStopped) credential.Dispose();
            return result;
        }
        finally { lifecycle.Release(); }
    }
    public async ValueTask DisposeAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var result = await StopAsync(deadline.Token).ConfigureAwait(false);
        if (!result.MappingAbsent || !result.ListenerStopped || !result.Native.OriginalOwnerAbsent)
            throw new IOException("Standard provider ownership remains reserved.");
        await store.DisposeAsync().ConfigureAwait(false); credential.Dispose();
    }
}
