using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// Authoritative Fusion member-set identity + complete-set admission gate.
// FusionMemberSet.TryCreate is the single shared derivation (backend bind,
// service, CLI, tray, recovery); FusionAdmission.Evaluate is the single
// mount gate. Tier roles and content identity stay native.
public sealed class FusionMemberSetTests
{
    private const string ContainerHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Fact]
    public void TryCreate_ValidPair_YieldsCanonicalDeterministicSet()
    {
        using var temp = DTempDirectory.Create("fusionset-valid");
        var storeA = Path.Combine(temp.Path, "z-main.apfs");
        var storeB = Path.Combine(temp.Path, "a-tier2.apfs");
        var evidence = NativeApfsObserver.ParseAndValidateEvidence(
            ObserverEvidenceJson.BuildFusionPair(
                ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)], storeA, storeB));

        Assert.True(FusionMemberSet.TryCreate(evidence, storeA, storeB, out var set, out var error), error);
        Assert.NotNull(set);
        Assert.Equal(ContainerHex, set!.ContainerUuid);
        Assert.Equal("20", set.CheckpointXid);
        Assert.Equal(storeA, set.PrimaryPath);
        Assert.Equal(2, set.Members.Count);
        // Canonical StoreId order regardless of path order.
        Assert.Equal(
            [$"apfs-store:{ContainerHex}-a", $"apfs-store:{ContainerHex}-b"],
            set.Members.Select(static m => m.StoreId).OrderBy(static id => id, StringComparer.Ordinal));
        Assert.All(set.Members, static m => Assert.True(m.SizeBytes > 0));

        // Swapped inputs deterministically fail instead of swapping members.
        Assert.False(FusionMemberSet.TryCreate(evidence, storeB, storeA, out _, out _));
    }

    [Theory]
    [InlineData(true, false, false, false)]
    [InlineData(false, true, false, false)]
    [InlineData(false, false, true, false)]
    [InlineData(false, false, false, true)]
    public void TryCreate_RefusesDefectiveSets(bool samePath, bool collectMode, bool nonFusion, bool unknownDisk)
    {
        using var temp = DTempDirectory.Create("fusionset-refuse");
        var storeA = Path.Combine(temp.Path, "main.apfs");
        var storeB = Path.Combine(temp.Path, "tier2.apfs");
        string json = collectMode
            ? ObserverEvidenceJson.BuildSingleContainer(
                ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)])
            : ObserverEvidenceJson.BuildFusionPair(
                ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)], storeA, storeB);
        if (nonFusion)
        {
            json = json.Replace("\"fusion\":true", "\"fusion\":false", StringComparison.Ordinal);
        }

        var bindA = storeA;
        var bindB = samePath ? storeA : storeB;
        if (unknownDisk)
        {
            bindA = Path.Combine(temp.Path, "other.apfs");
        }

        var evidence = NativeApfsObserver.ParseAndValidateEvidence(json);
        Assert.False(FusionMemberSet.TryCreate(evidence, bindA, bindB, out var set, out var error));
        Assert.Null(set);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void Admit_CompleteSetPassesWithExactReason()
    {
        var container = FusionContainer(ContainerHex, "20",
            [$"apfs-store:{ContainerHex}-a", $"apfs-store:{ContainerHex}-b"]);
        var set = ProvenSet(ContainerHex, "20");

        var decision = FusionAdmission.Evaluate(container, set);

        Assert.True(decision.Complete);
        Assert.Equal("FusionCompleteSet", decision.ReasonCode);
    }

    [Fact]
    public void Admit_NonFusionPassesThroughAsSingleStore()
    {
        var container = FusionContainer(ContainerHex, "20", [$"apfs-store:{ContainerHex}"]);
        var plain = container with { Fusion = false };

        var decision = FusionAdmission.Evaluate(plain, null);

        Assert.True(decision.Complete);
        Assert.Equal("SingleStore", decision.ReasonCode);
    }

    [Theory]
    [InlineData("FusionIncompleteMemberSet", null, null, null)]
    [InlineData("FusionContainerMismatch", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", null, null)]
    [InlineData("FusionStoreMismatch", null, "apfs-store:other", null)]
    [InlineData("FusionGenerationMismatch", null, null, "21")]
    public void Admit_RefusesIncompleteMismatchedOrStaleSets(
        string reason, string? setUuid, string? setStore, string? setXid)
    {
        var container = FusionContainer(ContainerHex, "20",
            [$"apfs-store:{ContainerHex}-a", $"apfs-store:{ContainerHex}-b"]);
        FusionMemberSet? set = reason == "FusionIncompleteMemberSet"
            ? null
            : ProvenSet(setUuid ?? ContainerHex, setXid ?? "20", setStore);

        var decision = FusionAdmission.Evaluate(container, set);

        Assert.False(decision.Complete);
        Assert.Equal(reason, decision.ReasonCode);
        Assert.False(string.IsNullOrWhiteSpace(decision.Message));
    }

    private static ApfsContainerRecord FusionContainer(string uuid, string xid, string[] storeIds) => new(
        $"apfs-container:{uuid}", uuid, 4096, storeIds, ["apfs-vol:Data"],
        true, xid, ["0x1"], [], []);

    private static FusionMemberSet ProvenSet(string uuid, string xid, string? replaceFirstStore = null)
    {
        var storeA = $"apfs-store:{ContainerHex}-a";
        var storeB = $"apfs-store:{ContainerHex}-b";
        return new FusionMemberSet(uuid, xid, @"D:\fusion\main.apfs",
        [
            new FusionMemberRecord(@"D:\fusion\main.apfs", replaceFirstStore ?? storeA, 8388608, null),
            new FusionMemberRecord(@"D:\fusion\tier2.apfs", storeB, 8388608, null),
        ]);
    }
}
