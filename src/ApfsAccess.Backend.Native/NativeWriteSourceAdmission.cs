using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

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
