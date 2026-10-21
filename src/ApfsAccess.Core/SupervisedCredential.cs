using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

// Owns the only supervisor copy. No managed strings/arrays contain frame bytes.
public sealed partial class SupervisedCredential : IDisposable
{
    private const int Capacity = 8 + 1024 + 1;
    private nint memory;
    private int length;
    public SafeFileHandle? Reader { get; private set; }
    private SafeFileHandle? writer;

    public static SupervisedCredential Receive(nint input, CancellationToken cancellation, Action checkOwner,
        int timeoutMs = 5000)
    {
        var frame = new SupervisedCredential();
        try
        {
            using var ownedInput = new SafeFileHandle(input, true);
            if (GetFileType(input) != 3 || !GetNamedPipeInfo(input, out var flags, 0, 0, 0) || (flags & 4) != 0)
                throw Failure("PipeRequired");
            // Take ownership of the caller's stdin; it can never enter the child's handle list.
            if (!SetHandleInformation(input, 1, 0)) throw Failure("InputHandle");
            frame.memory = VirtualAlloc(0, Capacity, 0x3000, 4);
            if (frame.memory == 0 || !VirtualLock(frame.memory, Capacity)) throw Failure("SecureAllocation");
            var watch = Stopwatch.StartNew();
            var received = 0;
            var expected = 8;
            var header = false;
            while (true)
            {
                cancellation.ThrowIfCancellationRequested();
                checkOwner();
                if (watch.ElapsedMilliseconds >= timeoutMs) throw Failure("Timeout");
                if (!PeekNamedPipe(input, 0, 0, 0, out var available, 0))
                {
                    if (Marshal.GetLastWin32Error() != 109) throw Failure("ReadFailure");
                    if (!header || received != expected) throw Failure("TruncatedFrame");
                    frame.length = expected;
                    return frame;
                }
                if (available == 0) { Thread.Sleep(5); continue; }
                var count = Math.Min(available, (uint)(expected + (header ? 1 : 0) - received));
                if (!ReadFile(input, frame.memory + received, count, out var got, 0) || got == 0)
                    throw Failure("TruncatedFrame");
                received += checked((int)got);
                if (!header && received == 8)
                {
                    if (Marshal.ReadInt32(frame.memory) != 0x31435041) throw Failure("InvalidFrame");
                    var size = unchecked((uint)Marshal.ReadInt32(frame.memory, 4));
                    if (size > 1024) throw Failure("OversizedFrame");
                    if (size == 0) throw Failure("InvalidFrame");
                    expected = 8 + (int)size;
                    header = true;
                }
                else if (header)
                {
                    if (received > expected) throw Failure("InvalidFrame");
                    for (var i = 8; i < received; i++)
                        if (Marshal.ReadByte(frame.memory, i) == 0) throw Failure("InvalidFrame");
                }
            }
        }
        catch { frame.Dispose(); throw; }
    }

    public static nint TakeStandardInput()
    {
        var input = GetStdHandle(-10);
        if (!SetStdHandle(-10, 0)) throw Failure("InputHandle");
        return input;
    }

    public void CreateChildPipe()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User?.Value ?? throw Failure("PipeIdentity");
        // Explicit owner is required even for elevated tokens whose default owner is Administrators.
        var sddl = $"O:{user}D:P(A;;GA;;;{user})(A;;GA;;;SY)";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out var descriptor, out _))
            throw Failure("PipeSecurity");
        try
        {
            var security = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
            var name = @"\\.\pipe\ApfsAccess.Credential." + Guid.NewGuid().ToString("N");
            // One local byte-pipe instance, bounded nonblocking server writes, no inheritable writer.
            writer = CreateNamedPipeW(name, 2 | 0x80000, 1 | 8, 1, 4096, 4096, 0, ref security);
            if (writer.IsInvalid) throw Failure("PipeCreation");
            security.Inherit = true;
            Reader = CreateFileW(name, 0x80000000, 0, ref security, 3, 0, 0);
            if (Reader.IsInvalid) throw Failure("PipeConnection");
            if (!ConnectNamedPipe(writer, 0) && Marshal.GetLastWin32Error() != 535)
                throw Failure("PipeConnection");
        }
        finally { LocalFree(descriptor); }
    }

    public void ReleaseLocalReader() { Reader?.Dispose(); Reader = null; }

    public void Send(CancellationToken cancellation, Action checkOwnerAndChild)
    {
        try
        {
            cancellation.ThrowIfCancellationRequested();
            checkOwnerAndChild();
            // Entire maximum frame fits in the empty 4096-byte kernel buffer. PIPE_NOWAIT
            // makes an unexpected shortage/failure refuse immediately, never block the owner.
            var watch = Stopwatch.StartNew();
            if (writer is null || !WriteFile(writer, memory, (uint)length, out var written, 0) || written != length)
                throw Failure("WriteFailure");
            if (watch.ElapsedMilliseconds >= 1000) throw Failure("WriteDeadline");
            cancellation.ThrowIfCancellationRequested();
            checkOwnerAndChild();
        }
        finally { Dispose(); } // Close the sole writer for EOF and wipe before publishing launch proof.
    }

    public void Dispose()
    {
        ReleaseLocalReader();
        writer?.Dispose(); writer = null;
        if (memory == 0) return;
        // Interop writes cannot be optimized away as dead managed stores.
        for (var i = 0; i < Capacity; i++) Marshal.WriteByte(memory, i, 0);
        VirtualUnlock(memory, Capacity);
        VirtualFree(memory, 0, 0x8000);
        memory = 0; length = 0;
    }

    private static IOException Failure(string reason) => new("Credential transport refused: " + reason);
    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes
    { internal int Length; internal nint Descriptor; [MarshalAs(UnmanagedType.Bool)] internal bool Inherit; }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern nint GetStdHandle(int kind);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetStdHandle(int kind, nint handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint GetFileType(nint handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetHandleInformation(nint handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeInfo(nint handle, out uint flags, nint output, nint input, nint instances);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool PeekNamedPipe(nint handle, nint buffer, uint size, nint read, out uint available, nint remaining);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ReadFile(nint handle, nint buffer, uint count, out uint read, nint overlapped);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool WriteFile(SafeFileHandle handle, nint buffer, uint count, out uint written, nint overlapped);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern SafeFileHandle CreateNamedPipeW(string name, uint access, uint mode, uint instances, uint output, uint input, uint timeout, ref SecurityAttributes security);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, ref SecurityAttributes security, uint creation, uint flags, nint template);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ConnectNamedPipe(SafeFileHandle pipe, nint overlapped);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out nint descriptor, out uint size);
    [DllImport("kernel32.dll")] private static extern nint LocalFree(nint memory);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern nint VirtualAlloc(nint address, nuint size, uint allocation, uint protection);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool VirtualLock(nint address, nuint size);
    [DllImport("kernel32.dll")] private static extern bool VirtualUnlock(nint address, nuint size);
    [DllImport("kernel32.dll")] private static extern bool VirtualFree(nint address, nuint size, uint kind);
}
