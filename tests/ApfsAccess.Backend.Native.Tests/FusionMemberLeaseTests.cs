namespace ApfsAccess.Backend.Native.Tests;

// Atomic two-file lifecycle boundary for a Fusion member pair: both handles
// or neither, deny-write while held, idempotent release with no leaked
// handle, advisory stale tripwire. Never interprets APFS bytes.
public sealed class FusionMemberLeaseTests
{
    [Fact]
    public void Acquire_HoldsBothDeniesWritersReleasesCleanly()
    {
        using var temp = DTempDirectory.Create("fusion-lease");
        var storeA = Path.Combine(temp.Path, "main.apfs");
        var storeB = Path.Combine(temp.Path, "tier2.apfs");
        File.WriteAllBytes(storeA, new byte[4096]);
        File.WriteAllBytes(storeB, new byte[4096]);

        Assert.True(FusionMemberLease.TryAcquire(storeA, storeB, out var lease, out var error), error);
        Assert.NotNull(lease);
        try
        {
            Assert.True(lease!.VerifyUnchanged(out error), error);
            // Overlapping writers fail at the OS while the lease is held.
            Assert.Throws<IOException>(() =>
            {
                using (File.Open(storeA, FileMode.Open, FileAccess.Write, FileShare.Read)) { }
            });
            Assert.Throws<IOException>(() =>
            {
                using (File.Open(storeB, FileMode.Open, FileAccess.Write, FileShare.Read)) { }
            });
        }
        finally
        {
            lease!.Dispose();
            lease.Dispose();
        }

        // After release both files reopen exclusively: no leaked handle.
        using (File.Open(storeA, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
        using (File.Open(storeB, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
    }

    [Fact]
    public void Acquire_MissingSecondaryReleasesPrimary()
    {
        using var temp = DTempDirectory.Create("fusion-lease-rollback");
        var storeA = Path.Combine(temp.Path, "main.apfs");
        var missingB = Path.Combine(temp.Path, "absent.apfs");
        File.WriteAllBytes(storeA, new byte[4096]);

        Assert.False(FusionMemberLease.TryAcquire(storeA, missingB, out var lease, out var error));
        Assert.Null(lease);
        Assert.False(string.IsNullOrWhiteSpace(error));

        // The half-open primary was released: exclusive open succeeds.
        using (File.Open(storeA, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
    }

    [Fact]
    public void Acquire_RejectsSamePathAndBlankPaths()
    {
        Assert.False(FusionMemberLease.TryAcquire(@"D:\f\a.apfs", @"D:\f\a.apfs", out _, out var error));
        Assert.False(string.IsNullOrWhiteSpace(error));
        Assert.False(FusionMemberLease.TryAcquire("", @"D:\f\b.apfs", out _, out error));
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void VerifyUnchanged_NeverHealthyAfterRelease()
    {
        using var temp = DTempDirectory.Create("fusion-lease-stale");
        var storeA = Path.Combine(temp.Path, "main.apfs");
        var storeB = Path.Combine(temp.Path, "tier2.apfs");
        File.WriteAllBytes(storeA, new byte[4096]);
        File.WriteAllBytes(storeB, new byte[4096]);

        Assert.True(FusionMemberLease.TryAcquire(storeA, storeB, out var lease, out _));
        Assert.NotNull(lease);
        lease!.Dispose();

        // Post-release growth is allowed again, and the released lease must
        // never report healthy (fail closed, never stale-healthy).
        using (var append = new FileStream(storeB, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
        {
            append.Write(new byte[512]);
        }

        Assert.False(lease.VerifyUnchanged(out var error));
        Assert.False(string.IsNullOrWhiteSpace(error));
    }
}
