using System.Runtime.InteropServices;
using System.Text.Json;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class EncryptedImageWriteLaunchTests
{
    internal static string DirectoryPath()
    {
        // Leave room for the production recovery namespace and cleanup marker.
        var root = Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_ENCRYPTED_LAUNCH_TEST_ROOT")
            ?? @"D:\ApfsAccessScratch\EW", Guid.NewGuid().ToString("N")[..16]);
        Directory.CreateDirectory(root);
        return root;
    }

    internal static EncryptedImageProfile Profile(string path, ulong offset = 0, ulong? length = null)
    {
        using var handle = File.OpenHandle(path);
        var observed = NativeApfsBackend.ImageIdentity(handle).Split(':');
        var bytes = checked((ulong)RandomAccess.GetLength(handle));
        var size = length ?? bytes - offset;
        return new(path, $"image-writer-v1:{observed[1]}:{observed[2]}:{bytes}:{offset}:{size}", offset, size,
            "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222",
            1026, 7, 0, 2, 0, 2, "33333333-3333-3333-3333-333333333333", "includes-header") { Writable = true };
    }

    [Fact]
    public void MetadataPinCoexistsWithNativeExclusiveWriterAndDetectsRenamedOrReplacedPath()
    {
        if (!OperatingSystem.IsWindows()) return;
        var directory = DirectoryPath();
        var path = Path.Combine(directory, "image.apfs");
        File.WriteAllBytes(path, new byte[8192]);
        var profile = Profile(path);
        using (var pin = NativeEncryptedImageWriteLaunch.Prepare(profile))
        {
            using (var writer = CreateFileW(path, 0xc0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero))
            {
                Assert.False(writer.IsInvalid, "metadata-only pins must permit the real zero-share writer");
                pin.RequireUnchanged();
            }
            // A same-size write changes mtime but must not change the writer's stable source identity.
            using (var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                writer.WriteByte(0x5a);
            pin.RequireUnchanged();
            File.Move(path, path + ".renamed");
            Assert.Throws<IOException>(() => pin.RequireUnchanged());
            File.WriteAllBytes(path, new byte[8192]);
            Assert.Throws<IOException>(() => pin.RequireUnchanged());
            Assert.Throws<IOException>(() => NativeEncryptedImageWriteLaunch.Prepare(profile));
        }
        File.Move(path, path + ".after");
        Assert.True(File.Exists(path + ".renamed"));
    }

    [Fact]
    public void VerificationHasSeparatePinnedReadIdentityAndBlocksEveryWriterUntilDispose()
    {
        if (!OperatingSystem.IsWindows()) return;
        var path = Path.Combine(DirectoryPath(), "image.apfs");
        File.WriteAllBytes(path, new byte[8192]);
        var profile = Profile(path);
        using (var pin = NativeEncryptedImageWriteLaunch.Prepare(profile))
        {
            var identity = pin.CaptureReadOnlyVerificationIdentity();
            Assert.StartsWith("windows-file:", identity);
            Assert.NotEqual(profile.SourceId, identity);
            using var independent = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            Assert.Equal(NativeApfsBackend.ImageIdentity(independent), identity);
            Assert.Equal(identity, pin.CaptureReadOnlyVerificationIdentity());
            using var denied = CreateFileW(path, 0xc0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
            Assert.True(denied.IsInvalid);
            Assert.Equal(32, Marshal.GetLastWin32Error());
            Assert.Throws<IOException>(() => File.OpenHandle(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
            Assert.Throws<IOException>(() => File.Move(path, path + ".replaced"));
        }
        using var admitted = CreateFileW(path, 0xc0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        Assert.False(admitted.IsInvalid);
    }

    [Fact]
    public void StaleIdentityWindowHardLinkAndCancellationRefuseWithoutChangingBytes()
    {
        if (!OperatingSystem.IsWindows()) return;
        var path = Path.Combine(DirectoryPath(), "image.apfs");
        var bytes = Enumerable.Range(0, 8192).Select(i => (byte)i).ToArray();
        File.WriteAllBytes(path, bytes);
        var profile = Profile(path);
        var other = path + ".other";
        File.WriteAllBytes(other, bytes);
        Assert.Throws<IOException>(() => NativeEncryptedImageWriteLaunch.Prepare(profile with { ImagePath = other }));
        Assert.Throws<IOException>(() => NativeEncryptedImageWriteLaunch.Prepare(Profile(path, 8192, 4096)));
        using (var canceled = new CancellationTokenSource())
        {
            canceled.Cancel();
            Assert.ThrowsAny<OperationCanceledException>(() => NativeEncryptedImageWriteLaunch.Prepare(profile, canceled.Token));
        }
        Assert.True(CreateHardLinkW(path + ".link", path, IntPtr.Zero));
        Assert.Throws<IOException>(() => NativeEncryptedImageWriteLaunch.Prepare(profile));
        Assert.Equal(bytes, File.ReadAllBytes(path));
        Assert.Equal(bytes, File.ReadAllBytes(other));
    }

    [Fact]
    public void RecoveryDirectoryBindsStableSourceAndVolumeButNotOwnCheckpointOrPasswordEra()
    {
        if (!OperatingSystem.IsWindows()) return;
        var directory = DirectoryPath();
        var path = Path.Combine(directory, "image.apfs");
        File.WriteAllBytes(path, new byte[8192]);
        var profile = Profile(path);
        using var pin = NativeEncryptedImageWriteLaunch.Prepare(profile);
        var recovery = pin.RecoveryDirectory(directory);
        Assert.True(recovery.Length <= 105);
        Assert.Equal(recovery, pin.RecoveryDirectory(directory));
        var alternate = Path.Combine(directory, "other"); Directory.CreateDirectory(alternate);
        Assert.Throws<IOException>(() => pin.RecoveryDirectory(alternate));
        using var next = NativeEncryptedImageWriteLaunch.Prepare(profile with { CheckpointXid = 8, ContainerBagXid = 8, VolumeBagXid = 8 });
        Assert.Equal(recovery, next.RecoveryDirectory(directory));
        using var selected = NativeEncryptedImageWriteLaunch.Prepare(profile with { VolumeObjectId = 1027 });
        Assert.NotEqual(recovery, selected.RecoveryDirectory(directory));
        Assert.Throws<IOException>(() => Directory.Move(recovery, recovery + ".moved"));
        var longRoot = Path.Combine(directory, new string('a', 40));
        Directory.CreateDirectory(longRoot);
        Assert.Throws<IOException>(() => pin.RecoveryDirectory(longRoot));
        Assert.Empty(Directory.EnumerateFileSystemEntries(longRoot));
        var arguments = pin.BuildHostArguments(Path.Combine(directory, "mount"), recovery, Path.Combine(directory, "status.json"),
            Path.Combine(directory, "lifetime"), Path.Combine(directory, "gate"), new string('a', 64), Environment.ProcessId);
        Assert.Contains("--readwrite", arguments); Assert.DoesNotContain("--readonly", arguments);
        Assert.Throws<ArgumentException>(() => pin.BuildHostArguments(Path.Combine(directory, "mount"), alternate,
            Path.Combine(directory, "status.json"), Path.Combine(directory, "lifetime"), Path.Combine(directory, "gate"), new string('a', 64), Environment.ProcessId));
    }

    [Fact]
    public void ExplicitWritableProfileRoundTripsWithoutChangingLegacyReadOnlyContract()
    {
        var path = Path.Combine(DirectoryPath(), "image.apfs");
        File.WriteAllBytes(path, new byte[8192]);
        var writable = Profile(path);
        Assert.True(writable.IsValid());
        using var handle = File.OpenHandle(path);
        var readOnly = writable with { Writable = false, SourceId = NativeApfsBackend.ImageIdentity(handle) + ":scope:0:8192" };
        var options = new JsonSerializerOptions { IgnoreReadOnlyProperties = true };
        var roJson = JsonSerializer.Serialize(readOnly, options);
        Assert.DoesNotContain("Writable", roJson);
        var legacy = roJson;
        var digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(legacy))).ToLowerInvariant();
        Assert.Equal("selected-v1:" + digest, readOnly.Contract);
        var encoded = JsonSerializer.Serialize(writable, options);
        Assert.Contains("\"Writable\":true", encoded);
        var roundtrip = JsonSerializer.Deserialize<EncryptedImageProfile>(encoded)!;
        Assert.Equal(writable, roundtrip);
        Assert.True(roundtrip.IsValid());
        Assert.Equal(MountAccessMode.ReadWrite, roundtrip.AccessMode);
        Assert.False((writable with { SourceId = readOnly.SourceId }).IsValid());
        Assert.False((readOnly with { SourceId = writable.SourceId }).IsValid());
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string link, string existing, IntPtr security);
}
