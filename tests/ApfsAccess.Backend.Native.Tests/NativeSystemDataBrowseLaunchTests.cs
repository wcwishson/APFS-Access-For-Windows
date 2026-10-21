using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeSystemDataBrowseLaunchTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "system-data-lease-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "pair with spaces.apfs");
    private const string Container = "apfs-container:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    public NativeSystemDataBrowseLaunchTests() { Directory.CreateDirectory(directory); File.WriteAllBytes(Image, Enumerable.Range(0, 4096).Select(i => (byte)i).ToArray()); }
    public void Dispose() => Directory.Delete(directory, true);
    private NativeSystemDataBrowseLaunch Prepare(CancellationToken token = default) => NativeSystemDataBrowseLaunch.Prepare(Image, Container, new string('d', 32), "101", "102", "20", token);

    [Fact]
    public void SourceIsPinnedUntilDisposedAndSelectionDoesNotClaimNativeAdmission()
    {
        var owner = Prepare();
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Image))), owner.Selection.SourceSha256);
        Assert.Equal(4096, owner.Selection.SourceSizeBytes);
        Assert.Throws<IOException>(() => { using var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); });
        Assert.Throws<IOException>(() => File.Move(Image, Image + ".moved"));
        var capability = JsonSerializer.SerializeToElement(NativeSystemDataBrowseLaunch.Capability);
        Assert.Equal("required", capability.GetProperty("nativeAdmission").GetString());
        Assert.Equal("unverified", capability.GetProperty("genuineMacCorpus").GetString());
        Assert.False(capability.GetProperty("unifiedMutations").GetBoolean());
        owner.Dispose(); owner.Dispose();
        using var released = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.None);
        Assert.Throws<ObjectDisposedException>(() => owner.RequireSource());
    }

    [Fact]
    public void ExistingWriterAndCancellationNeverLeakAReadLease()
    {
        using (var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) Assert.Throws<IOException>(() => Prepare());
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); Assert.ThrowsAny<OperationCanceledException>(() => Prepare(cancelled.Token));
        using var released = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.None);
    }

    [Fact]
    public void HostArgumentsBindBothVolumesGroupAndCheckpointWithoutWritableLegacyAuthority()
    {
        using var owner = Prepare();
        var args = owner.BuildHostArguments(Path.Combine(directory, "mount"), Path.Combine(directory, "status"), Path.Combine(directory, "lifetime"),
            Path.Combine(directory, "gate"), new string('b', 64), Environment.ProcessId).ToArray();
        string Value(string flag) => args[Array.IndexOf(args, flag) + 1];
        Assert.Contains("--system-data-image", args); Assert.Contains("--readonly", args); Assert.Equal("Disabled", Value("--write-backend"));
        Assert.Equal(Image, Value("--device")); Assert.Equal("0", Value("--device-offset")); Assert.Equal(new string('a', 32), Value("--container-id"));
        Assert.Equal("101", Value("--volume-oid")); Assert.Equal("102", Value("--system-data-data-oid")); Assert.Equal(new string('d', 32), Value("--system-data-group"));
        Assert.Equal("20", Value("--system-data-checkpoint-xid"));
        foreach (var forbidden in new[] { "--readwrite", "--recovery-identity", "--encrypted-image", "--container-manifest", "--allow-raw-physical-write" }) Assert.DoesNotContain(forbidden, args);
    }

    [Theory]
    [InlineData("systemDataRoute", "NotAdmitted")]
    [InlineData("systemDataAuthority", "CallerRecords")]
    [InlineData("systemDataGenuineMacCorpus", "Verified")]
    [InlineData("systemDataCheckpointXid", "21")]
    [InlineData("systemDataSystemOid", "102")]
    [InlineData("systemDataDataOid", "101")]
    [InlineData("systemDataGroup", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")]
    [InlineData("snapshotContainerId", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")]
    [InlineData("writeBackend", "Native")]
    public void SubstitutedReadyScopeCannotAdmit(string field, string value)
    {
        using var owner = Prepare(); var status = Status(); Assert.True(owner.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), 123));
        status[field] = value; Assert.False(owner.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), 123));
    }

    [Theory]
    [InlineData("hostPid", 124)]
    [InlineData("systemDataPairs", 0)]
    [InlineData("systemDataPairs", 1025)]
    [InlineData("walAcceptedSequence", 1)]
    [InlineData("walApfsDurableSequence", 1)]
    [InlineData("walCleanupSequence", 1)]
    public void BoundsOrForeignJournalDebtCannotAdmit(string field, int value)
    {
        using var owner = Prepare(); var status = Status(); status[field] = value; Assert.False(owner.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), 123));
    }

    [Fact]
    public void WritableUnreadyMissingAndDuplicatePropertiesCannotAdmit()
    {
        using var owner = Prepare(); var status = Status(); status["systemDataWritable"] = true;
        Assert.False(owner.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), 123)); status = Status(); status["mountReady"] = false;
        Assert.False(owner.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), 123)); status = Status(); status.Remove("systemDataAuthority");
        Assert.False(owner.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), 123));
        var json = Status().ToJsonString(); using var duplicate = JsonDocument.Parse(json[..^1] + ",\"systemDataPairs\":19}");
        Assert.False(owner.MatchesReadyStatus(duplicate.RootElement, 123));
    }

    [Theory]
    [InlineData("101", "20", "dddddddddddddddddddddddddddddddd")]
    [InlineData("0102", "20", "dddddddddddddddddddddddddddddddd")]
    [InlineData("102", "0", "dddddddddddddddddddddddddddddddd")]
    [InlineData("102", "18446744073709551616", "dddddddddddddddddddddddddddddddd")]
    [InlineData("102", "20", "00000000000000000000000000000000")]
    public void InvalidRequestedScopeNeverCreatesAnOwner(string data, string xid, string group)
        => Assert.Throws<ArgumentException>(() => NativeSystemDataBrowseLaunch.Prepare(Image, Container, group, "101", data, xid));

    private static JsonObject Status() => JsonSerializer.SerializeToNode(new { hostPid = 123, mountReady = true, volumeLabel = "System label",
        systemDataRoute = "ImageTableReadOnly", systemDataAuthority = "CanonicalSystemTable", systemDataWritable = false, systemDataGenuineMacCorpus = "Unverified",
        explicitReadOnly = true, writeBackend = "Disabled", systemDataCheckpointXid = "20", systemDataSystemOid = "101", systemDataDataOid = "102",
        systemDataGroup = new string('d', 32), snapshotContainerId = new string('a', 32), systemDataPairs = 19,
        walAcceptedSequence = 0, walApfsDurableSequence = 0, walCleanupSequence = 0 })!.AsObject();
}
