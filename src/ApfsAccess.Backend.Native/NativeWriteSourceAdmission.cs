using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

// Discovery hint only. MetadataStore still proves source identity and native
// feature admission on the handles used for the actual transaction.
internal static class NativeWriteSourceAdmission
{
    private const uint FileReadAttributes = 0x80;
    private const uint ShareReadWriteDelete = 7;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private const uint FileTypeDisk = 1;
    private const uint VolumeNameGuid = 1;
    private const int FileBasicInfoClass = 0;
    private const int FileStandardInfoClass = 1;
    private const int FileIdInfoClass = 18;
    private const string UnverifiedSource =
        "Native writes in this build require a verified local image file. Physical-device write validation is not complete.";

    public static string? GetBlockReason(string source)
        => GetBlockReason(source, null);

    public static string? GetBlockReason(string source, ServiceHostOptions? options)
    {
        // Raw-physical pilot spelling: \\.\PhysicalDriveN admits at the
        // spelling layer only when raw-physical writes are explicitly enabled
        // AND the exact device is hardware-pilot allow-listed; the opened
        // handle must then prove a real disk device. This never authorizes a
        // write by itself: catalog capability, promotion evidence, and native
        // readiness are still enforced downstream.
        if (IsRawPhysicalDriveSpelling(source))
        {
            if (!IsAllowListedRawDrive(source, options))
            {
                return UnverifiedSource;
            }

            using var handle = CreateFileW(source, FileReadAttributes, ShareReadWriteDelete,
                0, OpenExisting, BackupSemantics, 0);
            if (handle.IsInvalid || GetFileType(handle) != FileTypeDisk)
            {
                return UnverifiedSource;
            }

            return null;
        }

        return GetImageBlockReason(source);
    }

    // Pure spelling + allow-list match for the raw-physical pilot path. No
    // handle is opened here, so this is safe to unit test without hardware.
    // Both \\.\ and \\?\ spellings denote the same device, so matching
    // canonicalizes to the \\.\ form on both sides before comparing.
    internal static bool IsAllowListedRawDrive(string source, ServiceHostOptions? options)
        => IsRawPhysicalDriveSpelling(source) &&
           options?.NativeWriteAllowRawPhysicalDevices == true &&
           options.NativeWriteHardwarePilotDeviceAllowList is { Length: > 0 } allowList &&
           IsHardwarePilotAllowListed(
               allowList.Select(CanonicalizeRawDriveSpelling).ToArray(),
               CanonicalizeRawDriveSpelling(source));

    internal static string CanonicalizeRawDriveSpelling(string source)
        => source.StartsWith(@"\\?\", StringComparison.Ordinal)
            ? @"\\.\" + source[4..]
            : source;

    internal static bool IsRawPhysicalDriveSpelling(string source)
    {
        // The codebase treats \\.\ and \\?\ PhysicalDrive spellings as the
        // same raw device (see WriteGatePolicy.IsRawPhysicalDevice); the
        // handle proof below decides openability per spelling.
        var path = source.StartsWith(@"\\?\", StringComparison.Ordinal)
            ? @"\\.\" + source[4..]
            : source;
        if (!path.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase))
            return false;
        var tail = path[@"\\.\PhysicalDrive".Length..];
        return tail.Length > 0 && tail.All(char.IsAsciiDigit);
    }

    private static bool IsHardwarePilotAllowListed(IReadOnlyList<string> allowList, string deviceId)
    {
        foreach (var entry in allowList)
        {
            if (string.IsNullOrWhiteSpace(entry))
                continue;
            var token = entry.Trim();
            if (string.Equals(token, deviceId, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static string? GetImageBlockReason(string source)
    {
        // Avoid connecting to named pipes or other device endpoints during discovery.
        // This spelling check only refuses; the opened handle must prove admission.
        var localPath = source.StartsWith(@"\\?\", StringComparison.Ordinal)
            ? source[4..] : source;
        if (!OperatingSystem.IsWindows() || localPath.Length < 4 ||
            !char.IsAsciiLetter(localPath[0]) || localPath[1] != ':' ||
            (localPath[2] != '\\' && localPath[2] != '/'))
        {
            return UnverifiedSource;
        }

        using var handle = CreateFileW(source, FileReadAttributes, ShareReadWriteDelete,
            0, OpenExisting, OpenReparsePoint | BackupSemantics, 0);
        if (handle.IsInvalid || GetFileType(handle) != FileTypeDisk ||
            !GetFileInformationByHandleEx(handle, FileStandardInfoClass, out FileStandardInfo standard,
                (uint)Marshal.SizeOf<FileStandardInfo>()) ||
            standard.Directory || standard.DeletePending || standard.NumberOfLinks == 0 ||
            !GetFileInformationByHandleEx(handle, FileBasicInfoClass, out FileBasicInfo basic,
                (uint)Marshal.SizeOf<FileBasicInfo>()) ||
            (basic.Attributes & (FileAttributes.Directory | FileAttributes.Device |
                FileAttributes.ReparsePoint)) != 0 ||
            !GetFileInformationByHandleEx(handle, FileIdInfoClass, out FileIdInfo _,
                (uint)Marshal.SizeOf<FileIdInfo>()))
        {
            return UnverifiedSource;
        }

        var finalPath = new StringBuilder(512);
        var length = GetFinalPathNameByHandleW(handle, finalPath, (uint)finalPath.Capacity, VolumeNameGuid);
        if (length >= finalPath.Capacity && length < 32768)
        {
            finalPath.EnsureCapacity((int)length + 1);
            length = GetFinalPathNameByHandleW(handle, finalPath, (uint)finalPath.Capacity, VolumeNameGuid);
        }
        if (length == 0 || length >= finalPath.Capacity)
        {
            return UnverifiedSource;
        }
        var resolved = finalPath.ToString();
        var volumeEnd = resolved.IndexOf(@"}\", StringComparison.Ordinal);
        if (!resolved.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase) ||
            volumeEnd < 0 || volumeEnd + 2 >= resolved.Length ||
            resolved.IndexOf(':', volumeEnd + 2) >= 0)
        {
            return UnverifiedSource;
        }
        return (basic.Attributes & FileAttributes.ReadOnly) != 0
            ? "The image file is read only. Native writes are unavailable while its read-only attribute is set."
            : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileStandardInfo
    {
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)] public bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] public bool Directory;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInfo
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public FileAttributes Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;
        public ulong FileIdHigh;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
        nint security, uint creation, uint flags, nint template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind,
        out FileStandardInfo information, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind,
        out FileBasicInfo information, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind,
        out FileIdInfo information, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle,
        StringBuilder path, uint size, uint flags);
}
