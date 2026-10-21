using System.Text.Json;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Cli.Tests;

public sealed class FusionPublicMountTests
{
    private static readonly string Root = Path.Combine("D:\\ApfsAccessScratch\\WindowsClosure\\fusion-namespace-20261017\\managed-fixtures", Guid.NewGuid().ToString("N"));
    private static FusionImageSelection Pair()
    {
        var dir = Path.Combine(Root, Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        var a = Path.Combine(dir, "main.apfs"); var b = Path.Combine(dir, "tier.apfs");
        File.WriteAllBytes(a, new byte[8192]); File.WriteAllBytes(b, new byte[8192]);
        return new(new('a', 32), new('b', 32), new('c', 32), 101, 20,
            [new(a, "main", "main-store", 4096, 4096), new(b, "tier2", "tier-store", 4096, 4096)]);
    }
    [Fact] public void CapturesBothExactIdentitiesAndReleasesOnlyAtNativeHandoff()
    {
        var pair = Pair(); using var launch = NativeFusionImageLaunch.Prepare(pair);
        Assert.Equal(2, launch.Members.Count); Assert.All(launch.Members, m => Assert.Equal(5, m.Identity.Split(':').Length));
        foreach (var m in pair.Members) Assert.Throws<IOException>(() => File.OpenHandle(m.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None));
        var original = launch.Selection.Members[0]; pair.Members[0] = pair.Members[1]; launch.Selection.Members[0] = pair.Members[1];
        Assert.Equal(original, launch.Selection.Members[0]);
        var dir = Path.GetDirectoryName(original.Path)!;
        var args = launch.BuildHostArguments(Path.Combine(dir, "mount"), dir, Path.Combine(dir, "status"), Path.Combine(dir, "life"), Path.Combine(dir, "gate"), new('a', 64), Environment.ProcessId);
        Assert.Contains("--fusion-write-root", args); Assert.Contains("--fusion-identity-b", args); Assert.DoesNotContain("--device", args);
        launch.ReleaseForNativeOwner(); Assert.Throws<InvalidOperationException>(() => launch.ReleaseForNativeOwner());
        foreach (var m in launch.Members) using (File.OpenHandle(m.Selection.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
    }
    [Theory] [InlineData("role")] [InlineData("path")] [InlineData("store")] [InlineData("window")] [InlineData("uuid")]
    public void InvalidPairCannotBecomeLaunch(string defect)
    {
        var p = Pair();
        p = defect switch {
            "role" => p with { Members = [p.Members[0], p.Members[1] with { Role = "main" }] },
            "path" => p with { Members = [p.Members[0], p.Members[1] with { Path = p.Members[0].Path }] },
            "store" => p with { Members = [p.Members[0], p.Members[1] with { StoreId = p.Members[0].StoreId }] },
            "window" => p with { Members = [p.Members[0], p.Members[1] with { StoreOffset = 8192 }] },
            _ => p with { FusionUuid = new('0', 32) }
        };
        Assert.ThrowsAny<Exception>(() => NativeFusionImageLaunch.Prepare(p));
        foreach (var m in p.Members) using (File.OpenHandle(m.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
    }
    [Fact] public void MissingSecondMemberUnwindsFirstLease()
    {
        var pair = Pair(); File.Move(pair.Members[1].Path, pair.Members[1].Path + ".held-out");
        Assert.ThrowsAny<IOException>(() => NativeFusionImageLaunch.Prepare(pair));
        using var first = File.OpenHandle(pair.Members[0].Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    }
    [Fact] public void DuplicateJsonSelectorRefusesBeforeSourceOpening()
    {
        var pair = Pair(); var path = Path.Combine(Path.GetDirectoryName(pair.Members[0].Path)!, "selection.json");
        File.WriteAllText(path, "{\"containerUuid\":\"a\",\"containerUuid\":\"b\"}");
        Assert.Throws<ArgumentException>(() => FusionMountCommand.ReadSelection(path));
    }
    [Fact] public void SelectionFileRoundTripPreservesPairOrderAndWindows()
    {
        var pair = Pair(); var path = Path.Combine(Path.GetDirectoryName(pair.Members[0].Path)!, "selection.json");
        File.WriteAllText(path, JsonSerializer.Serialize(pair, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
        var read = FusionMountCommand.ReadSelection(path); Assert.Equal(pair.Members, read.Members); Assert.Equal(pair.CheckpointXid, read.CheckpointXid);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public void NativeStatusBindsRolesAndRejectsCrossMemberIdentitySubstitution(bool reverse)
    {
        var pair = Pair(); if (reverse) pair = pair with { Members = [pair.Members[1], pair.Members[0]] };
        using var launch = NativeFusionImageLaunch.Prepare(pair); launch.ReleaseForNativeOwner();
        var members = launch.Members.OrderBy(m => m.Selection.Role == "main" ? 0 : 1).Select(m => new Dictionary<string, object> {
            ["member"] = m.Selection.Path, ["identity"] = m.Identity, ["role"] = m.Selection.Role,
            ["store-id"] = m.Selection.StoreId, ["store-offset"] = m.Selection.StoreOffset.ToString(),
            ["store-size"] = m.Selection.StoreSize.ToString(), ["state"] = "HeldExclusive" }).ToArray();
        var status = new Dictionary<string, object> {
            ["hostPid"] = Environment.ProcessId, ["mountReady"] = true, ["fusionWritable"] = true,
            ["fusionHealth"] = "ReadWrite", ["fusionMissingMemberMask"] = 0, ["fusionContainerUuid"] = pair.ContainerUuid,
            ["fusionVolumeOid"] = "101", ["fusionCheckpointXid"] = 20, ["fusionAcceptedSequence"] = 2,
            ["fusionDurableSequence"] = 2, ["fusionCleanupSequence"] = 2, ["fusionMembers"] = members,
            ["fusionSelection"] = new Dictionary<string, object> { ["uuid"] = pair.FusionUuid, ["volume-uuid"] = pair.VolumeUuid,
                ["checkpoint-xid"] = "20", ["role-convention"] = "linux-apfs-last-byte-low-bit" } };
        Assert.True(launch.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), Environment.ProcessId));
        (members[0]["identity"], members[1]["identity"]) = (members[1]["identity"], members[0]["identity"]);
        Assert.False(launch.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), Environment.ProcessId));
        (members[0]["identity"], members[1]["identity"]) = (members[1]["identity"], members[0]["identity"]);
        status["fusionCleanupSequence"] = 0;
        Assert.False(launch.MatchesReadyStatus(JsonSerializer.SerializeToElement(status), Environment.ProcessId));
    }
}
