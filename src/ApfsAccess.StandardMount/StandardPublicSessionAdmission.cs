using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.StandardMount;

public enum StandardPublicSessionRefusal { SessionActive, OwnershipUncertain }

public sealed class StandardPublicSessionException(StandardPublicSessionRefusal reason, Exception? inner = null)
    : IOException(reason == StandardPublicSessionRefusal.SessionActive
        ? "Another public standard-share session is active. Close that command, wait for its clean terminal receipt, then retry."
        : "Public standard-share session ownership is unproved. Preserve the existing session and finish its retirement before retrying.", inner)
{
    public StandardPublicSessionRefusal Reason { get; } = reason;
}

// The single-instance pipe is an admission lease only. It accepts no connections
// or commands and carries no native handle, source identity or credential.
public sealed class StandardPublicSessionAdmission : IDisposable
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<StandardPublicSessionAdmission, byte> Retained = new();
    private NamedPipeServerStream? reservation;
    private StandardPublicSessionAdmission(NamedPipeServerStream reservation) => this.reservation = reservation;
    public static StandardPublicSessionAdmission Acquire()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var identity = WindowsIdentity.GetCurrent();
        var logonSid = ReadLogonSid(identity.AccessToken);
        var suffix = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(logonSid.Value)));
        try
        {
            return new(new NamedPipeServerStream("ApfsAccess.StandardShare.Admission." + suffix,
                PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 1, 1));
        }
        catch (UnauthorizedAccessException ex) { throw new StandardPublicSessionException(StandardPublicSessionRefusal.OwnershipUncertain, ex); }
        catch (IOException ex) when ((ex.HResult & 0xffff) is 5 or 231)
        {
            throw new StandardPublicSessionException((ex.HResult & 0xffff) == 231
                ? StandardPublicSessionRefusal.SessionActive : StandardPublicSessionRefusal.OwnershipUncertain, ex);
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct LogonGroup { internal uint Count; internal IntPtr Sid; internal uint Attributes; }
    private static SecurityIdentifier ReadLogonSid(SafeAccessTokenHandle token)
    {
        _ = GetTokenInformation(token, 28, IntPtr.Zero, 0, out var size);
        if (Marshal.GetLastWin32Error() != 122 || size < Marshal.SizeOf<LogonGroup>() || size > 4096)
            throw new StandardPublicSessionException(StandardPublicSessionRefusal.OwnershipUncertain);
        var bytes = Marshal.AllocHGlobal(size);
        try
        {
            if (!GetTokenInformation(token, 28, bytes, size, out var actual) || actual > size)
                throw new StandardPublicSessionException(StandardPublicSessionRefusal.OwnershipUncertain);
            var group = Marshal.PtrToStructure<LogonGroup>(bytes);
            if (group.Count != 1 || group.Sid == IntPtr.Zero || (group.Attributes & 0xc0000000) != 0xc0000000)
                throw new StandardPublicSessionException(StandardPublicSessionRefusal.OwnershipUncertain);
            var sid = new SecurityIdentifier(group.Sid);
            if (sid.BinaryLength != 20 || !sid.Value.StartsWith("S-1-5-5-", StringComparison.Ordinal))
                throw new StandardPublicSessionException(StandardPublicSessionRefusal.OwnershipUncertain);
            return sid;
        }
        finally { Marshal.FreeHGlobal(bytes); }
    }
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass,
        IntPtr data, int length, out int required);
    public void RetainUntilProcessExit() => Retained.TryAdd(this, 0);
    public void Dispose()
    {
        Interlocked.Exchange(ref reservation, null)?.Dispose();
        Retained.TryRemove(this, out _);
    }
}
