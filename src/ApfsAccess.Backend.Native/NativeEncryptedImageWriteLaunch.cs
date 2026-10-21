using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

// This pins selectors and source identity. Only the native owner can prepare a mutation.
public sealed class NativeEncryptedImageWriteLaunch : IDisposable
{
    private readonly List<SafeFileHandle> ancestors = [];
    private SafeFileHandle? source;
    private SafeFileHandle? verificationSource;
    private string? recoveryDirectory, recoveryRoot;
    public EncryptedImageProfile Profile { get; }
    private NativeEncryptedImageWriteLaunch(EncryptedImageProfile profile) => Profile = profile;

    public static NativeEncryptedImageWriteLaunch Prepare(EncryptedImageProfile profile, CancellationToken token = default)
    {
        if (!profile.Writable || !profile.IsValid()) throw new ArgumentException("Select an explicit writable encrypted image profile.");
        var pin = new NativeEncryptedImageWriteLaunch(profile);
        try
        {
            if (!OperatingSystem.IsWindows() || new DriveInfo(Path.GetPathRoot(profile.ImagePath)!).DriveType != DriveType.Fixed)
                throw new IOException("Encrypted writing requires an ordinary local fixed-drive image.");
            for (var directory = new FileInfo(profile.ImagePath).Directory; directory is not null; directory = directory.Parent)
            {
                token.ThrowIfCancellationRequested();
                var held = CreateFileW(directory.FullName, 0x81, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                pin.ancestors.Add(held);
                if (held.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                if (!GetFileInformationByHandle(held, out var info) || (info.Attributes & 0x410) != 0x10)
                    throw new IOException("Encrypted image ancestors must be ordinary pinned directories.");
            }
            // Attribute-only handles coexist with the native zero-share data handle.
            // Windows can still rename this file; RequireUnchanged detects that,
            // and native admission must compare the same stable file identity.
            pin.source = CreateFileW(profile.ImagePath, 0x80, 3, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
            if (pin.source.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            pin.RequireUnchanged(); token.ThrowIfCancellationRequested(); return pin;
        }
        catch { pin.Dispose(); throw; }
    }

    public void RequireUnchanged()
    {
        var held = source;
        ObjectDisposedException.ThrowIf(held is null || held.IsClosed, this);
        RequireSourceHandle(held);
        var path = new StringBuilder(32768);
        var count = GetFinalPathNameByHandleW(held, path, (uint)path.Capacity, 0);
        if (count == 0 || count >= path.Capacity || !string.Equals(path.ToString(), @"\\?\" + Profile.ImagePath, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Encrypted image path no longer names the selected file.");
    }

    private void RequireSourceHandle(SafeFileHandle held)
    {
        if (!GetFileInformationByHandle(held, out var info) || GetFileType(held) != 1 ||
            (info.Attributes & 0x450) != 0 || info.Links != 1 ||
            !GetFileInformationByHandleEx(held, 1, out var standard, (uint)Marshal.SizeOf<StandardInfo>()) ||
            standard.Directory != 0 || standard.DeletePending != 0 || standard.Links != 1)
            throw new IOException("Encrypted writer requires the same single-link regular image.");
        var bytes = ((ulong)info.SizeHigh << 32) | info.SizeLow;
        if (standard.EndOfFile < 0 || (ulong)standard.EndOfFile != bytes)
            throw new IOException("Encrypted image size changed during source capture.");
        var identity = FormattableString.Invariant($"image-writer-v1:{info.Serial}:{((ulong)info.IndexHigh << 32) | info.IndexLow}:{bytes}:{Profile.StoreOffset}:{Profile.StoreSize}");
        if (identity != Profile.SourceId || Profile.StoreOffset > bytes || Profile.StoreSize > bytes - Profile.StoreOffset)
            throw new IOException("Encrypted image identity or selected window changed.");
    }

    public string RecoveryDirectory(string configuredRoot)
    {
        RequireUnchanged();
        configuredRoot = NativeSnapshotBrowseLaunch.ValidateLocalPath(configuredRoot);
        if (recoveryDirectory is not null)
        {
            if (!string.Equals(configuredRoot, recoveryRoot, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Recovery storage cannot change while this source registration is held.");
            return recoveryDirectory;
        }
        if (new DriveInfo(Path.GetPathRoot(configuredRoot)!).DriveType != DriveType.Fixed ||
            !Directory.Exists(configuredRoot) || (File.GetAttributes(configuredRoot) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Configure an existing ordinary encrypted recovery directory.");
        var stable = FormattableString.Invariant($"encrypted-owner-recovery-v1\n{Profile.SourceId}\n{Profile.ContainerUuid}\n{Profile.VolumeUuid}\n{Profile.VolumeObjectId}");
        var key = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(stable))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var result = Path.Combine(configuredRoot, "encrypted", key);
        // The spool's longest authenticated cleanup-marker path is root + 105 characters.
        if (result.Length > 105) throw new IOException("Encrypted recovery root exceeds the supported 105-character path bound.");
        var first = ancestors.Count;
        try { PinRecoveryDirectory(result); }
        catch
        {
            for (var i = ancestors.Count - 1; i >= first; --i) { ancestors[i].Dispose(); ancestors.RemoveAt(i); }
            throw;
        }
        recoveryRoot = configuredRoot; recoveryDirectory = result; return result;
    }

    private void PinRecoveryDirectory(string path)
    {
        for (var end = 2; ; )
        {
            var prefix = path[..(end == 2 ? 3 : end)];
            if (!Directory.Exists(prefix) && !CreateDirectoryW(prefix, IntPtr.Zero) && Marshal.GetLastWin32Error() != 183)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var held = CreateFileW(prefix, 0x81, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            ancestors.Add(held);
            if (held.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!GetFileInformationByHandle(held, out var info) || (info.Attributes & 0x410) != 0x10)
                throw new IOException("Encrypted recovery ancestors must be ordinary pinned directories.");
            if (end == path.Length) break;
            end = path.IndexOf('\\', end == 2 ? 3 : end + 1);
            if (end < 0) end = path.Length;
        }
    }

    // Verification keeps its own real data lease. The stable writer identity
    // is checked first; the returned mtime identity remains pinned until Dispose.
    public string CaptureReadOnlyVerificationIdentity()
    {
        RequireUnchanged();
        if (verificationSource is null)
        {
            var held = File.OpenHandle(Profile.ImagePath, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.RandomAccess);
            try { RequireSourceHandle(held); RequireUnchanged(); verificationSource = held; }
            catch { held.Dispose(); throw; }
        }
        return NativeApfsBackend.ImageIdentity(verificationSource);
    }

    public IReadOnlyList<string> BuildHostArguments(string mount, string recovery, string status, string lifetime,
        string gate, string gateToken, int parentPid)
    {
        RequireUnchanged();
        foreach (var path in new[] { mount, recovery, status, lifetime, gate }) NativeSnapshotBrowseLaunch.ValidateLocalPath(path);
        if (recoveryDirectory is null || !string.Equals(recovery, recoveryDirectory, StringComparison.OrdinalIgnoreCase) ||
            !Directory.Exists(recovery) || recovery.Length > 105 || parentPid <= 0 ||
            gateToken.Length is not (32 or 64) || gateToken.Any(c => !char.IsAsciiHexDigit(c)))
            throw new ArgumentException("Encrypted writing requires bounded recovery storage and authenticated startup.");
        var args = new List<string> { "--device", Profile.ImagePath, "--device-offset", Number(Profile.StoreOffset),
            "--readwrite", "--write-backend", "Disabled", "--encrypted-write-root", recovery,
            "--mount", mount, "--status-file", status, "--lifetime-file", lifetime,
            "--parent-pid", parentPid.ToString(CultureInfo.InvariantCulture), "--startup-gate-file", gate, "--startup-gate-token", gateToken };
        args.AddRange(Profile.HostArguments()); return args;
    }

    public void Dispose()
    {
        verificationSource?.Dispose(); verificationSource = null;
        source?.Dispose(); source = null;
        foreach (var held in ancestors) held.Dispose(); ancestors.Clear();
    }
    private static string Number(ulong value) => value.ToString(CultureInfo.InvariantCulture);
    [StructLayout(LayoutKind.Sequential)] private struct FileInformation
    {
        public uint Attributes, CreateLow, CreateHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Serial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)] private struct StandardInfo
    {
        public long AllocationSize, EndOfFile;
        public uint Links;
        public byte DeletePending, Directory;
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
