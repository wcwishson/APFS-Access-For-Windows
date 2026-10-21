using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

internal sealed class NativeImageKeyManagementLaunch : IDisposable
{
    private readonly List<SafeFileHandle> directories = [];
    private SafeFileHandle? source;
    internal ImageKeyManagementRequest Request { get; }
    internal string RecoveryDirectory { get; private set; } = "";
    internal string OperationDirectory { get; private set; } = "";
    private NativeImageKeyManagementLaunch(ImageKeyManagementRequest request) => Request = request;

    internal static NativeImageKeyManagementLaunch Prepare(ImageKeyManagementRequest request,
        string recoveryRoot, string operationRoot, CancellationToken token)
    {
        if (!OperatingSystem.IsWindows() || !request.IsValid()) throw new ArgumentException("A current private image endpoint is required.");
        var launch = new NativeImageKeyManagementLaunch(request);
        try
        {
            foreach (var path in new[] { request.Expected.ImagePath, recoveryRoot, operationRoot })
            {
                NativeSnapshotBrowseLaunch.ValidateLocalPath(path);
                if (new DriveInfo(Path.GetPathRoot(path)!).DriveType != DriveType.Fixed)
                    throw new IOException("Key management requires local fixed-drive storage.");
            }
            launch.PinDirectory(Path.GetDirectoryName(request.Expected.ImagePath)!, false, token);
            launch.source = CreateFileW(request.Expected.ImagePath, 0x80, 3, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
            launch.RequireUnchanged();
            var p = request.Expected;
            var stable = FormattableString.Invariant($"encrypted-owner-recovery-v1\n{p.SourceId}\n{p.ContainerUuid}\n{p.VolumeUuid}\n{p.VolumeObjectId}");
            var key = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(stable))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            launch.RecoveryDirectory = Path.Combine(recoveryRoot, "encrypted", key);
            launch.OperationDirectory = Path.Combine(operationRoot, Guid.Parse(request.OperationId).ToString("N"));
            if (launch.RecoveryDirectory.Length > 105 || launch.OperationDirectory.Length > 200)
                throw new IOException("Key management storage path exceeds its supported bound.");
            launch.PinDirectory(recoveryRoot, false, token); launch.PinDirectory(operationRoot, true, token);
            launch.PinDirectory(launch.RecoveryDirectory, true, token);
            if (!CreateDirectoryW(launch.OperationDirectory, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
            launch.PinDirectory(launch.OperationDirectory, false, token); return launch;
        }
        catch { launch.Dispose(); throw; }
    }

    internal void RequireUnchanged()
    {
        var held = source; ObjectDisposedException.ThrowIf(held is null || held.IsClosed, this);
        if (held.IsInvalid || GetFileType(held) != 1 || !GetFileInformationByHandle(held, out var info) ||
            (info.Attributes & 0x450) != 0 || info.Links != 1 ||
            !GetFileInformationByHandleEx(held, 1, out var standard, (uint)Marshal.SizeOf<StandardInfo>()) ||
            standard.EndOfFile < 0 || standard.Directory != 0 || standard.DeletePending != 0 || standard.Links != 1)
            throw new IOException("The selected image is no longer an ordinary single-link file.");
        var bytes = ((ulong)info.SizeHigh << 32) | info.SizeLow;
        var p = Request.Expected;
        var identity = FormattableString.Invariant($"image-writer-v1:{info.Serial}:{((ulong)info.IndexHigh << 32) | info.IndexLow}:{bytes}:{p.StoreOffset}:{p.StoreSize}");
        var path = new StringBuilder(32768);
        var count = GetFinalPathNameByHandleW(held, path, (uint)path.Capacity, 0);
        if ((ulong)standard.EndOfFile != bytes || identity != p.SourceId || p.StoreOffset > bytes || p.StoreSize > bytes - p.StoreOffset ||
            count == 0 || count >= path.Capacity || !string.Equals(path.ToString(), @"\\?\" + p.ImagePath, StringComparison.OrdinalIgnoreCase))
            throw new IOException("The image identity, path or selected window changed.");
    }

    internal IReadOnlyList<string> Arguments(string lifetime, HostStartupGate startup)
    {
        RequireUnchanged();
        var p = Request.Expected;
        var args = new List<string> { "--action", Request.Action.ToString(), "--operation-id", Request.OperationId,
            "--image", p.ImagePath, "--source-id", p.SourceId, "--store-offset", Number(p.StoreOffset), "--store-size", Number(p.StoreSize),
            "--container-uuid", Guid.Parse(p.ContainerUuid).ToString("N"), "--volume-uuid", Guid.Parse(p.VolumeUuid).ToString("N"),
            "--volume-oid", Number(p.VolumeObjectId), "--checkpoint-xid", Number(p.CheckpointXid),
            "--recovery-directory", RecoveryDirectory, "--parent-pid", Environment.ProcessId.ToString(CultureInfo.InvariantCulture),
            "--lifetime-file", lifetime, "--startup-gate-file", startup.FilePath, "--startup-gate-token", startup.AuthorizationToken,
            "--receipt-file", Path.Combine(OperationDirectory, "receipt.json") };
        if (p.Keybag is { } bag)
            args.AddRange(["--container-bag-oid", Number(bag.ContainerBagOid), "--container-bag-xid", Number(bag.ContainerBagXid),
                "--volume-bag-oid", Number(bag.VolumeBagOid), "--volume-bag-xid", Number(bag.VolumeBagXid),
                "--user-uuid", Guid.Parse(bag.UserUuid).ToString("N"), "--bag-length", bag.BagLength]);
        return args;
    }

    internal SafeFileHandle PinExecutable(string path, CancellationToken token)
    {
        NativeSnapshotBrowseLaunch.ValidateLocalPath(path); PinDirectory(Path.GetDirectoryName(path)!, false, token);
        var file = CreateFileW(path, 0x80000000, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        if (file.IsInvalid || !GetFileInformationByHandle(file, out var info) || (info.Attributes & 0x450) != 0 || GetFileType(file) != 1)
        { file.Dispose(); throw new IOException("A pinned ordinary native key-management executable is required."); }
        return file;
    }

    internal FileStream OpenReceipt()
    {
        RequireUnchanged();
        var file = CreateFileW(Path.Combine(OperationDirectory, "receipt.json"), 0x80000000, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        if (file.IsInvalid || !GetFileInformationByHandle(file, out var info) || (info.Attributes & 0x450) != 0 || info.Links != 1 || GetFileType(file) != 1)
        { file.Dispose(); throw new IOException("A regular native receipt from this operation is required."); }
        return new FileStream(file, FileAccess.Read);
    }

    private void PinDirectory(string path, bool create, CancellationToken token)
    {
        NativeSnapshotBrowseLaunch.ValidateLocalPath(path);
        for (var end = 2;;)
        {
            token.ThrowIfCancellationRequested();
            var prefix = path[..(end == 2 ? 3 : end)];
            if (create && !Directory.Exists(prefix) && !CreateDirectoryW(prefix, IntPtr.Zero) && Marshal.GetLastWin32Error() != 183)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var held = CreateFileW(prefix, 0x81, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero); directories.Add(held);
            if (held.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!GetFileInformationByHandle(held, out var info) || (info.Attributes & 0x410) != 0x10)
                throw new IOException("Key management ancestors must be ordinary pinned directories.");
            if (end == path.Length) break;
            end = path.IndexOf('\\', end == 2 ? 3 : end + 1); if (end < 0) end = path.Length;
        }
    }
    public void Dispose()
    {
        source?.Dispose(); source = null;
        foreach (var held in directories) held.Dispose(); directories.Clear();
    }
    private static string Number(ulong value) => value.ToString(CultureInfo.InvariantCulture);
    [StructLayout(LayoutKind.Sequential)] private struct FileInformation
    {
        public uint Attributes, CreateLow, CreateHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Serial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)] private struct StandardInfo
    {
        public long AllocationSize, EndOfFile; public uint Links; public byte DeletePending, Directory;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation info);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, out StandardInfo info, uint bytes);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint GetFileType(SafeFileHandle file);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder name, uint size, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, IntPtr security);
}
