using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class VolumeDriveLetterAssignmentsTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "drive-letter-tests-" + Guid.NewGuid().ToString("N"));
    private readonly Guid _first = Guid.NewGuid();
    private readonly Guid _second = Guid.NewGuid();
    private string StatePath => Path.Combine(_directory, "letters.json");
    private static string Id(ulong oid) => ApfsTopology.BuildVolumeId(new string('a', 32), oid);
    private static VolumeInfo Volume(ulong oid) => new("opaque-" + oid, "disk", "Same name", false, CatalogVolumeId: Id(oid));
    private static ApfsVolumeRecord Record(ulong oid, string uuid) => new(
        Id(oid), uuid, oid.ToString(), "apfs-container:" + new string('a', 32), "Same name", true,
        [], 0, null, "sensitive", "none", false, [], [], [], "1", "1");

    public VolumeDriveLetterAssignmentsTests() => Directory.CreateDirectory(_directory);

    private VolumeDriveLetterAssignments Store(params ApfsVolumeRecord[]? records)
    {
        var store = new VolumeDriveLetterAssignments(StatePath);
        store.UpdateCatalog(records is { Length: > 0 } ? records : [Record(1, _first.ToString("D")), Record(2, _second.ToString("D"))]);
        return store;
    }

    private static FirstFreeMountPolicy Policy(VolumeDriveLetterAssignments store, params string[] pool)
        => new(pool.Length == 0 ? ["P", "Q", "R"] : pool, store);

    [Fact]
    public void RuntimeSnapshotReplacesAssociationsAndRequiresExactUuid()
    {
        var store = Store();
        Assert.True(store.SetPreference(_first, 'R'));
        IMountPolicy policy = Policy(store);
        var volume = Volume(1) with { CatalogVolumeUuid = _first.ToString("D") };
        policy.UpdateDiscovery([volume]);
        Assert.Equal('R', policy.SelectDriveLetter(volume, new HashSet<char>()));
        Assert.Equal('P', policy.SelectDriveLetter(volume with { CatalogVolumeUuid = _second.ToString("D") }, new HashSet<char>()));
        Assert.Equal('P', policy.SelectDriveLetter(volume with { CatalogVolumeUuid = null }, new HashSet<char>()));
        policy.UpdateDiscovery([]);
        Assert.Equal('P', policy.SelectDriveLetter(volume, new HashSet<char>()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public void RuntimeInvalidUuidAndCatalogIdentityNeverPersist(string? uuid)
    {
        var store = new VolumeDriveLetterAssignments(StatePath);
        IMountPolicy policy = Policy(store);
        var volume = Volume(1) with { CatalogVolumeUuid = uuid };
        policy.UpdateDiscovery([volume]);
        Assert.Equal('P', policy.SelectDriveLetter(volume, new HashSet<char>()));
        foreach (var id in new[] { null, "opaque", _first.ToString("D"), Id(0) })
        {
            volume = volume with { CatalogVolumeId = id, CatalogVolumeUuid = _first.ToString("D") };
            policy.UpdateDiscovery([volume]);
            Assert.Equal('P', policy.SelectDriveLetter(volume, new HashSet<char>()));
        }
        Assert.False(File.Exists(StatePath));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void RuntimeDuplicatesDisableAllRowsEvenWhenOtherMemberIsIneligible(bool duplicateUuid)
    {
        var store = Store();
        Assert.True(store.SetPreference(_first, 'R'));
        var before = File.ReadAllBytes(StatePath);
        IMountPolicy policy = Policy(store);
        var first = Volume(1) with { CatalogVolumeUuid = _first.ToString("D") };
        var second = Volume(2) with
        {
            DeviceId = "other-device",
            CatalogVolumeId = duplicateUuid ? null : first.CatalogVolumeId,
            CatalogVolumeUuid = duplicateUuid ? _first.ToString("N").ToUpperInvariant() : "invalid",
        };
        policy.UpdateDiscovery([first, second]);
        Assert.Equal('P', policy.SelectDriveLetter(first, new HashSet<char>()));
        Assert.Equal('Q', policy.SelectDriveLetter(second, new HashSet<char> { 'P' }));
        Assert.Equal(before, File.ReadAllBytes(StatePath));
    }

    [Fact]
    public void FreshPreferencesSurviveReloadReorderAndReplugWithSameNames()
    {
        var policy = Policy(Store());
        Assert.Equal('P', policy.SelectDriveLetter(Volume(1), new HashSet<char>()));
        Assert.Equal('Q', policy.SelectDriveLetter(Volume(2), new HashSet<char> { 'p' }));
        var reloaded = Store(Record(2, _second.ToString("N").ToUpperInvariant()), Record(1, _first.ToString("D")));
        var reordered = Policy(reloaded);
        Assert.Equal('Q', reordered.SelectDriveLetter(Volume(2) with { DeviceId = "replugged", VolumeId = "changed" }, new HashSet<char>()));
        Assert.Equal('P', reordered.SelectDriveLetter(Volume(1), new HashSet<char> { 'Q' }));
        Assert.Equal(2, JsonDocument.Parse(File.ReadAllText(StatePath)).RootElement.EnumerateObject().Count());
    }

    [Fact]
    public void OccupiedPreferenceUsesTemporaryLetterAndRetriesWithoutDisplacement()
    {
        var store = Store();
        Assert.True(store.SetPreference(_first, 'q'));
        var before = File.ReadAllBytes(StatePath);
        var policy = Policy(store);
        var occupied = new HashSet<char> { 'q', 'p' };
        Assert.Equal('R', policy.SelectDriveLetter(Volume(1), occupied));
        Assert.Equal(new HashSet<char> { 'q', 'p' }, occupied);
        Assert.Equal(before, File.ReadAllBytes(StatePath));
        Assert.Equal('Q', Policy(Store()).SelectDriveLetter(Volume(1), new HashSet<char>()));
    }

    [Fact]
    public void CatalogRoutingIdCanChangeWhileActualUuidKeepsPreference()
    {
        var store = Store();
        Assert.True(store.SetPreference(_first, 'R'));
        store.UpdateCatalog([Record(3, _first.ToString("N"))]);
        Assert.Equal('R', Policy(store).SelectDriveLetter(Volume(3), new HashSet<char>()));
        Assert.Equal('P', Policy(store).SelectDriveLetter(Volume(1), new HashSet<char>()));
        store.UpdateCatalog([]);
        Assert.Equal('P', Policy(store).SelectDriveLetter(Volume(3), new HashSet<char>()));
    }

    [Fact]
    public void PoolBoundsAndExhaustionPreserveOriginalPreference()
    {
        var store = Store();
        Assert.True(store.SetPreference(_first, 'Z'));
        var before = File.ReadAllBytes(StatePath);
        var policy = Policy(store, "P", "Q");
        Assert.Equal('Q', policy.SelectDriveLetter(Volume(1), new HashSet<char> { 'p' }));
        Assert.Throws<InvalidOperationException>(() => policy.SelectDriveLetter(Volume(1), new HashSet<char> { 'p', 'q' }));
        Assert.Equal(before, File.ReadAllBytes(StatePath));
        Assert.Equal('Z', Policy(Store(), "Z").SelectDriveLetter(Volume(1), new HashSet<char>()));
    }

    [Fact]
    public void TwoVolumesMaySharePreferenceButNeverAnOccupiedLetter()
    {
        var store = Store();
        Assert.True(store.SetPreference(_first, 'Q'));
        Assert.True(store.SetPreference(_second, 'Q'));
        var policy = Policy(store);
        Assert.Equal('Q', policy.SelectDriveLetter(Volume(1), new HashSet<char>()));
        Assert.Equal('P', policy.SelectDriveLetter(Volume(2), new HashSet<char> { 'Q' }));
        Assert.Equal('Q', Policy(Store()).SelectDriveLetter(Volume(2), new HashSet<char>()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-uuid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public void MissingOrInvalidActualUuidDoesNotPersist(string? uuid)
    {
        var store = Store(Record(1, uuid!));
        Assert.Equal('P', Policy(store).SelectDriveLetter(Volume(1), new HashSet<char>()));
        Assert.False(File.Exists(StatePath));
    }

    [Fact]
    public void LegacyAndOpaqueIdsAreNeverReinterpretedAsVolumeUuids()
    {
        var store = Store();
        var policy = Policy(store);
        foreach (var id in new[] { _first.ToString("D"), Id(1), "disk|Same name" })
        {
            Assert.Equal('P', policy.SelectDriveLetter(new(id, "disk", "Same name", false), new HashSet<char>()));
            Assert.Equal('P', policy.SelectDriveLetter(Volume(1) with { CatalogVolumeId = _first.ToString("D") }, new HashSet<char>()));
        }
        Assert.False(File.Exists(StatePath));
    }

    [Fact]
    public void DuplicateUuidOrCatalogIdDisablesEveryAmbiguousMember()
    {
        var store = Store(Record(1, _first.ToString("D")), Record(2, _first.ToString("N")));
        Assert.Equal('P', Policy(store).SelectDriveLetter(Volume(1), new HashSet<char>()));
        Assert.Equal('Q', Policy(store).SelectDriveLetter(Volume(2), new HashSet<char> { 'P' }));
        store.UpdateCatalog([Record(1, _first.ToString("D")), Record(1, _second.ToString("D"))]);
        Assert.Equal('P', Policy(store).SelectDriveLetter(Volume(1), new HashSet<char>()));
        Assert.False(File.Exists(StatePath));
    }

    [Theory]
    [InlineData("{")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{\"bad-id\":\"P\"}")]
    [InlineData("{\"11111111-1111-1111-1111-111111111111\":\"PP\"}")]
    [InlineData("{\"11111111-1111-1111-1111-111111111111\":\"P\",\"11111111111111111111111111111111\":\"Q\"}")]
    public void MalformedPersistenceIsLeftByteForByteIntact(string json)
    {
        File.WriteAllText(StatePath, json);
        var store = Store();
        Assert.Equal('P', Policy(store).SelectDriveLetter(Volume(1), new HashSet<char>()));
        Assert.False(store.SetPreference(_first, 'Q'));
        Assert.Equal(json, File.ReadAllText(StatePath));
    }

    [Fact]
    public void IndependentlyLoadedStoresMergeLatestPreferences()
    {
        var first = Store();
        var second = Store();
        Assert.True(first.SetPreference(_first, 'Q'));
        Assert.True(second.SetPreference(_second, 'R'));
        Assert.True(first.SetPreference(_first, 'P'));
        var policy = Policy(Store());
        Assert.Equal('P', policy.SelectDriveLetter(Volume(1), new HashSet<char>()));
        Assert.Equal('R', policy.SelectDriveLetter(Volume(2), new HashSet<char>()));
    }

    [Fact]
    public void ConcurrentWritersDoNotLoseSuccessfulUpdates()
    {
        var ids = Enumerable.Range(0, 12).Select(_ => Guid.NewGuid()).ToArray();
        var results = ids.AsParallel().Select(id => (id, saved: new VolumeDriveLetterAssignments(StatePath).SetPreference(id, 'Q'))).ToArray();
        using var json = JsonDocument.Parse(File.ReadAllText(StatePath));
        Assert.Contains(results, result => result.saved);
        foreach (var result in results.Where(result => result.saved))
            Assert.Equal("Q", json.RootElement.GetProperty(result.id.ToString("D")).GetString());
    }

    [Fact]
    public void LockedDestinationFailsWithoutDamageAndMountingFallsBack()
    {
        var store = Store();
        Assert.True(store.SetPreference(_first, 'Q'));
        var before = File.ReadAllBytes(StatePath);
        using (var held = new FileStream(StatePath, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Assert.False(store.SetPreference(_second, 'R'));
            Assert.Equal('P', Policy(store).SelectDriveLetter(Volume(1), new HashSet<char>()));
        }
        Assert.Equal(before, File.ReadAllBytes(StatePath));
        Assert.True(store.SetPreference(_second, 'R'));
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
    }

    [Fact]
    public void ReplacementAfterPriorSelectionIsReloadedInsteadOfOverwritten()
    {
        var store = Store();
        Assert.Equal('P', Policy(store).SelectDriveLetter(Volume(1), new HashSet<char>()));
        var replacement = Path.Combine(_directory, "replacement.json");
        File.WriteAllText(replacement, JsonSerializer.Serialize(new Dictionary<Guid, string> { [_second] = "R" }));
        File.Move(replacement, StatePath, true);
        Assert.True(store.SetPreference(_first, 'Q'));
        Assert.Equal('R', Policy(store).SelectDriveLetter(Volume(2), new HashSet<char>()));
    }

    [Fact]
    public void FailedAtomicReplacementPreservesFileAndRemovesTemporaryFile()
    {
        var store = Store();
        Assert.True(store.SetPreference(_first, 'Q'));
        var before = File.ReadAllBytes(StatePath);
        using (var reader = new FileStream(StatePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            Assert.False(store.SetPreference(_second, 'R'));
        Assert.Equal(before, File.ReadAllBytes(StatePath));
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
        Assert.False(File.Exists(StatePath + ".lock"));
    }

    [Fact]
    public void ReplacingHardLinkedStateDoesNotModifyOtherLink()
    {
        var store = Store();
        Assert.True(store.SetPreference(_first, 'Q'));
        var otherLink = Path.Combine(_directory, "other-link.json");
        Assert.True(CreateHardLinkW(otherLink, StatePath, IntPtr.Zero));
        var before = File.ReadAllBytes(otherLink);
        Assert.True(store.SetPreference(_second, 'R'));
        Assert.Equal(before, File.ReadAllBytes(otherLink));
        Assert.Equal('R', Policy(Store()).SelectDriveLetter(Volume(2), new HashSet<char>()));
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string fileName, string existingFileName, IntPtr securityAttributes);

    [Fact]
    public void RedirectedDestinationAndAncestorAreRefused()
    {
        var target = Path.Combine(_directory, "target.json");
        File.WriteAllText(target, "{}");
        File.CreateSymbolicLink(StatePath, target);
        Assert.False(Store().SetPreference(_first, 'Q'));
        Assert.Equal("{}", File.ReadAllText(target));
        Assert.NotNull(new FileInfo(StatePath).LinkTarget);
        var redirected = Path.Combine(_directory, "redirected");
        Directory.CreateSymbolicLink(redirected, _directory);
        Assert.False(new VolumeDriveLetterAssignments(Path.Combine(redirected, "other.json")).SetPreference(_first, 'Q'));
        Assert.False(File.Exists(Path.Combine(_directory, "other.json")));
    }

    [Fact]
    public void MissingDirectoryAndPreexistingLockFailConservatively()
    {
        Assert.False(new VolumeDriveLetterAssignments(Path.Combine(_directory, "missing", "letters.json")).SetPreference(_first, 'P'));
        File.WriteAllText(StatePath + ".lock", "existing");
        Assert.Equal('P', Policy(Store()).SelectDriveLetter(Volume(1), new HashSet<char>()));
        Assert.False(File.Exists(StatePath));
        Assert.Equal("existing", File.ReadAllText(StatePath + ".lock"));
    }

    public void Dispose()
    {
        // All test paths are unique children of the caller's D: TEMP directory.
        var redirected = Path.Combine(_directory, "redirected");
        if (Directory.Exists(redirected)) Directory.Delete(redirected);
        Directory.Delete(_directory, recursive: true);
    }
}
