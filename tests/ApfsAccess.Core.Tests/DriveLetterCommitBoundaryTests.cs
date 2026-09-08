using System.Reflection;
using System.Text.Json;

namespace ApfsAccess.Core.Tests;

public sealed class DriveLetterCommitBoundaryTests : IDisposable
{
    [Fact]
    public void PreparedSelectionCannotRetargetReplacementUuid()
    {
        var first = Guid.NewGuid();
        var replacement = Guid.NewGuid();
        var volume = new VolumeInfo("route", "disk", "Name", false,
            CatalogVolumeId: ApfsTopology.BuildVolumeId(new string('a', 32), 1), CatalogVolumeUuid: first.ToString("N"));
        var store = new VolumeDriveLetterAssignments(State);
        var policy = new FirstFreeMountPolicy(["R", "T"], store);
        policy.UpdateDiscovery([volume]);
        var select = policy.PrepareDriveLetterSelection(volume, new HashSet<char>());
        policy.UpdateDiscovery([volume with { CatalogVolumeUuid = replacement.ToString("N") }]);
        Assert.Equal('R', select(CancellationToken.None));
        Assert.True(store.TryGetPreference(first, out var saved));
        Assert.Equal('R', saved);
        Assert.True(store.TryGetPreference(replacement, out var other));
        Assert.Null(other);
    }

    private readonly string _root = Path.Combine(Path.GetTempPath(), "commit-boundary-" + Guid.NewGuid().ToString("N"));
    private string State => Path.Combine(_root, "letters.json");
    public DriveLetterCommitBoundaryTests() => Directory.CreateDirectory(_root);
    public void Dispose() => Directory.Delete(_root, true);

    [Fact]
    public void CancellationAfterStateUpdateButBeforeAtomicRenamePreservesFileAndCleansLeaseAndTemporary()
    {
        var uuid = Guid.NewGuid();
        var store = new VolumeDriveLetterAssignments(State);
        Assert.True(store.SetPreference(uuid, 'R'));
        var before = File.ReadAllBytes(State);
        using var cancel = new CancellationTokenSource();
        // Exercise the actual checked-path/flush/rename implementation. Cancelling
        // in its existing update delegate forces the final pre-rename check after
        // the new temporary file has been serialized and flushed, without test hooks.
        Func<Dictionary<Guid, char>, bool> update = state =>
        {
            state[uuid] = 'T';
            cancel.Cancel();
            return true;
        };
        var method = typeof(VolumeDriveLetterAssignments).GetMethod("WithState", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var error = Assert.Throws<TargetInvocationException>(() => method.Invoke(store, [update, cancel.Token]));
        Assert.IsAssignableFrom<OperationCanceledException>(error.InnerException);
        Assert.Equal(before, File.ReadAllBytes(State));
        Assert.False(File.Exists(State + ".lock"));
        Assert.Empty(Directory.GetFiles(_root, ".drive-letters-*.tmp"));
        Assert.True(store.SetPreference(uuid, 'S'));
    }

    [Fact]
    public void AdmittedPreferenceRemainsBoundToUuidAndPostCommitCancellationDoesNotRetargetIt()
    {
        var first = Guid.NewGuid();
        var replacement = Guid.NewGuid();
        var volume = new VolumeInfo("route", "disk", "Name", false,
            CatalogVolumeId: ApfsTopology.BuildVolumeId(new string('a', 32), 1), CatalogVolumeUuid: first.ToString("N"));
        var store = new VolumeDriveLetterAssignments(State);
        var policy = new FirstFreeMountPolicy(["R", "S", "T"], store);
        policy.UpdateDiscovery([volume]);
        var commit = policy.PrepareDriveLetterPreference(volume, first, 'T');
        policy.UpdateDiscovery([volume with { CatalogVolumeUuid = replacement.ToString("N") }]);
        using var cancel = new CancellationTokenSource();
        var result = commit(cancel.Token);
        cancel.Cancel();
        Assert.True(result.Success);
        using var json = JsonDocument.Parse(File.ReadAllBytes(State));
        Assert.Equal("T", json.RootElement.GetProperty(first.ToString("D")).GetString());
        Assert.False(json.RootElement.TryGetProperty(replacement.ToString("D"), out _));
        Assert.False(policy.GetDriveLetterPreference(volume, null).CanEdit);
    }
}
