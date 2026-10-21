#if APFSACCESS_STANDARD_MOUNT
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;
using ApfsAccess.Core;

namespace ApfsAccess.Cli.Tests;

public sealed class StandardShareCommandTests
{
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Volume = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static ApfsObserverEvidence Evidence()
    {
        var c = new ApfsContainerRecord("apfs-container:" + Container, Container, 4096, ["store"], ["volume"], false,
            "42", [], [], [], []);
        var v = new ApfsVolumeRecord("volume", Volume, "101", c.Id, "Data", true, ["data"], 64, null, "sensitive", "none",
            false, [], [], [], "9", "42", []);
        return new(ApfsTopology.EvidenceFormat, 1, ApfsTopology.ObserverId, "1.0.0", "collect", "managed-discovery", false,
            new("image", "image", 4 << 20, "full", "hash"), new([], [], [new("store", "", "", c.Id, 0, 4 << 20)], [c], [v], []), []);
    }
    private static NativeStandardSelection Select(ApfsObserverEvidence e, string? container = null, string oid = "101") =>
        NativeStandardOwner.Select(e, "image", 4 << 20, "hash", container ?? "apfs-container:" + Container, oid, new string('1', 80));

    [Fact]
    public void ObservedSelectionUsesExistingCanonicalRecoveryNamespace()
    {
        var selection = Select(Evidence());
        Assert.Equal(42ul, selection.CheckpointXid);
        Assert.Equal($"apfs-vol:{Container}:101:{Volume}", selection.VolumeIdentity);
        Assert.Equal(NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, Container, 101, true), selection.RecoveryIdentity);
    }

    [Fact]
    public void StaleSourceAndForeignSelectionRefuseBeforeOwnerLaunch()
    {
        var e = Evidence();
        Assert.Throws<IOException>(() => Select(e, "apfs-container:" + new string('c', 32)));
        Assert.Throws<IOException>(() => Select(e, oid: "102"));
        foreach (var source in new[] { e.Source with { Path = "other" }, e.Source with { SizeBytes = 4096 },
            e.Source with { Sha256 = "other" }, e.Source with { HashScope = "none" } })
            Assert.Throws<IOException>(() => Select(e with { Source = source }));
    }

    [Fact]
    public void UnsupportedProfilesNeverBecomeAnOrdinaryWriter()
    {
        var e = Evidence(); var v = e.Topology.Volumes[0]; var c = e.Topology.Containers[0];
        foreach (var volume in new[] { v with { Locked = true }, v with { EncryptionMode = "password" },
            v with { Roles = ["system"] }, v with { ReadonlyFeatureBits = ["sealed"] }, v with { UnknownFeatureBits = ["unknown"] } })
            Assert.Throws<IOException>(() => Select(e with { Topology = e.Topology with { Volumes = [volume] } }));
        Assert.Throws<IOException>(() => Select(e with { Topology = e.Topology with { Containers = [c with { Fusion = true }] } }));
        Assert.Throws<IOException>(() => Select(e with { Topology = e.Topology with { Stores = [e.Topology.Stores[0] with { OffsetBytes = 4096 }] } }));
    }

    [Fact]
    public void WriterDirectoryPinsAllowAtomicChildRenameButBlockAncestorRename()
    {
        if (!OperatingSystem.IsWindows()) return;
        var folder = Path.Combine(@"D:\ApfsAccessScratch", "standard-pin-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        var before = Path.Combine(folder, "before"); var after = Path.Combine(folder, "after");
        File.WriteAllText(before, "original registration bytes");
        var pins = NativeStandardOwner.PinWritableAncestors(before);
        try
        {
            File.Move(before, after);
            Assert.Equal("original registration bytes", File.ReadAllText(after));
            Assert.Throws<IOException>(() => Directory.Move(folder, folder + "-moved"));
        }
        finally { foreach (var pin in pins) pin.Dispose(); }
        File.Delete(after); Directory.Delete(folder);
    }

    [Fact]
    public void PeerVolumesAndUnprovedMembershipRefuseBeforeLaunch()
    {
        var e = Evidence(); var c = e.Topology.Containers[0]; var v = e.Topology.Volumes[0];
        var peer = v with { Id = "peer", ObjectId = "102", Locked = true, EncryptionMode = "password" };
        Assert.Throws<IOException>(() => Select(e with { Topology = e.Topology with { Volumes = [v, peer] } }));
        foreach (var ids in new IReadOnlyList<string>[] { [], [v.Id, "peer"], ["foreign"] })
            Assert.Throws<IOException>(() => Select(e with { Topology = e.Topology with { Containers = [c with { VolumeIds = ids }] } }));
        Assert.Throws<IOException>(() => Select(e with { Topology = e.Topology with { Containers = [c with { StoreIds = ["store", "foreign"] }] } }));
    }

    [Fact]
    public async Task FailedLaunchRetainsActualDirectoryPinsUntilOriginalOwnerRelease()
    {
        if (!OperatingSystem.IsWindows()) return;
        var folder = Path.Combine(@"D:\ApfsAccessScratch", "standard-failed-pin-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        var pins = NativeStandardOwner.PinWritableAncestors(Path.Combine(folder, "held"));
        var originalHandles = pins.Select(pin => pin.DangerousGetHandle()).ToArray();
        var proof = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var released = false;
        var cleanup = NativeStandardOwner.ReleaseAfterOwnerAsync(proof.Task, () => {
            foreach (var pin in pins) pin.Dispose(); released = true;
        });
        try
        {
            Assert.False(cleanup.IsCompleted); Assert.False(released);
            foreach (var handle in originalHandles)
            {
                var path = new System.Text.StringBuilder(1024);
                Assert.True(GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, 0) > 0);
                Assert.StartsWith(@"\\?\D:\", path.ToString(), StringComparison.OrdinalIgnoreCase);
            }
            Assert.Throws<IOException>(() => Directory.Move(folder, folder + "-moved"));
        }
        finally { proof.TrySetResult(); await cleanup; }
        Assert.True(released);
        Assert.All(pins, pin => Assert.True(pin.IsClosed, "An original directory pin remained open after cleanup completed."));
        foreach (var handle in originalHandles)
        {
            var path = new System.Text.StringBuilder(1024);
            var length = GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, 0);
            var error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            Assert.Equal(0u, length);
            Assert.Equal(6, error); // ERROR_INVALID_HANDLE independently proves OS release.
        }
        try
        {
            Directory.Move(folder, folder + "-moved");
            Directory.Delete(folder + "-moved");
        }
        catch (IOException error) when (error.HResult == unchecked((int)0x80070020))
        {
            Console.WriteLine($"Directory rename remains unavailable after all original kernel handles closed: {folder}; 0x{error.HResult:X8}. Holder not identified; directory preserved.");
        }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(nint handle, System.Text.StringBuilder path, uint count, uint flags);

    [Theory]
    [InlineData("--allow-raw-physical-write")]
    [InlineData("--recovery-identity")]
    [InlineData("--native-host")]
    [InlineData("--readonly-fallback")]
    public void ForeignAuthorityAndFallbackFlagsAreNotPublicInputs(string flag)
        => Assert.Throws<ArgumentException>(() => StandardShareCommand.Parse(["mount", flag, "value"]));
}
#endif
