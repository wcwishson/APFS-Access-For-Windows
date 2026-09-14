using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

// Task 9: the Fusion admission gate is pure and total — malformed inputs
// must yield explicit refusal decisions, never throw. A gate that throws
// on JSON-shaped nulls (missing arrays, null members) is not fail-closed:
// deserialized evidence can carry exactly those shapes.
public sealed class FusionAdmissionTests
{
    private const string ContainerUuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Xid = "20";

    private static readonly string[] DefaultStores = ["apfs-store:main", "apfs-store:tier2"];

    private static readonly FusionMemberRecord[] DefaultMembers =
    [
        new FusionMemberRecord(@"D:\member-a.img", "apfs-store:main", 100, null),
        new FusionMemberRecord(@"D:\member-b.img", "apfs-store:tier2", 50, null),
    ];

    private static ApfsContainerRecord Container(
        bool fusion = true,
        string? uuid = ContainerUuid,
        string? xid = Xid,
        IReadOnlyList<string>? storeIds = null,
        bool nullStores = false)
        => new("apfs-container:" + ContainerUuid, uuid!, 4096,
            nullStores ? null! : storeIds ?? DefaultStores, [], fusion, xid!,
            [], [], []);

    private static FusionMemberSet Set(
        string? containerUuid = ContainerUuid,
        string? xid = Xid,
        IReadOnlyList<FusionMemberRecord>? members = null,
        bool nullMembers = false)
        => new(containerUuid!, xid!, @"D:\member-a.img",
            nullMembers ? null! : members ?? DefaultMembers);

    [Fact]
    public void Evaluate_NullContainer_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => FusionAdmission.Evaluate(null!, Set()));
    }

    [Fact]
    public void Evaluate_NonFusionContainer_PassesThrough()
    {
        var decision = FusionAdmission.Evaluate(Container(fusion: false), null);
        Assert.True(decision.Complete);
        Assert.Equal("SingleStore", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_FusionWithoutSet_Refuses()
    {
        var decision = FusionAdmission.Evaluate(Container(), null);
        Assert.False(decision.Complete);
        Assert.Equal("FusionIncompleteMemberSet", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_CompleteSet_Admits()
    {
        var decision = FusionAdmission.Evaluate(Container(), Set());
        Assert.True(decision.Complete);
        Assert.Equal("FusionCompleteSet", decision.ReasonCode);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    public void Evaluate_WrongMemberCount_Refuses(int count)
    {
        var members = Enumerable.Range(0, count)
            .Select(i => new FusionMemberRecord($@"D:\m{i}.img", $"apfs-store:{i}", 100, null))
            .ToArray();
        var decision = FusionAdmission.Evaluate(Container(), Set(members: members));
        Assert.False(decision.Complete);
        Assert.Equal("FusionIncompleteMemberSet", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_NullMembers_RefusesInsteadOfThrowing()
    {
        var decision = FusionAdmission.Evaluate(Container(), Set(nullMembers: true));
        Assert.False(decision.Complete);
        Assert.Equal("FusionIncompleteMemberSet", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_NullMemberElement_RefusesInsteadOfThrowing()
    {
        var decision = FusionAdmission.Evaluate(Container(),
            Set(members: [new FusionMemberRecord(@"D:\m.img", "apfs-store:main", 100, null), null!]));
        Assert.False(decision.Complete);
        Assert.Equal("FusionIncompleteMemberSet", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_NullStoreIds_RefusesInsteadOfThrowing()
    {
        var decision = FusionAdmission.Evaluate(Container(nullStores: true), Set());
        Assert.False(decision.Complete);
        Assert.Equal("FusionStoreMismatch", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_StoreMismatch_Refuses()
    {
        var decision = FusionAdmission.Evaluate(
            Container(storeIds: ["apfs-store:main", "apfs-store:other"]), Set());
        Assert.False(decision.Complete);
        Assert.Equal("FusionStoreMismatch", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_ContainerMismatch_Refuses()
    {
        var decision = FusionAdmission.Evaluate(Container(), Set(containerUuid: new string('c', 32)));
        Assert.False(decision.Complete);
        Assert.Equal("FusionContainerMismatch", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_NullUuidsOnBothSides_RefusesInsteadOfPassing()
    {
        var decision = FusionAdmission.Evaluate(Container(uuid: null), Set(containerUuid: null));
        Assert.False(decision.Complete);
        Assert.Equal("FusionContainerMismatch", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_GenerationMismatch_Refuses()
    {
        var decision = FusionAdmission.Evaluate(Container(), Set(xid: "21"));
        Assert.False(decision.Complete);
        Assert.Equal("FusionGenerationMismatch", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_NullGenerationsOnBothSides_RefusesInsteadOfPassing()
    {
        var decision = FusionAdmission.Evaluate(Container(xid: null), Set(xid: null));
        Assert.False(decision.Complete);
        Assert.Equal("FusionGenerationMismatch", decision.ReasonCode);
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("   ")]
    public void Evaluate_WhitespaceUuidsOnBothSides_Refuse(string blank)
    {
        var decision = FusionAdmission.Evaluate(Container(uuid: blank), Set(containerUuid: blank));
        Assert.False(decision.Complete);
        Assert.Equal("FusionContainerMismatch", decision.ReasonCode);
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("   ")]
    public void Evaluate_WhitespaceGenerationsOnBothSides_Refuse(string blank)
    {
        var decision = FusionAdmission.Evaluate(Container(xid: blank), Set(xid: blank));
        Assert.False(decision.Complete);
        Assert.Equal("FusionGenerationMismatch", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_DuplicateMemberStores_Refuses()
    {
        var dup = new FusionMemberRecord(@"D:\m.img", "apfs-store:main", 100, null);
        var decision = FusionAdmission.Evaluate(Container(), Set(members: [dup, dup]));
        Assert.False(decision.Complete);
        Assert.Equal("FusionIncompleteMemberSet", decision.ReasonCode);
    }

    [Fact]
    public void Evaluate_DuplicateContainerStores_Refuses()
    {
        var decision = FusionAdmission.Evaluate(
            Container(storeIds: ["apfs-store:main", "apfs-store:main"]), Set());
        Assert.False(decision.Complete);
        Assert.Equal("FusionStoreMismatch", decision.ReasonCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Evaluate_BlankMemberStoreId_Refuses(string? storeId)
    {
        var decision = FusionAdmission.Evaluate(Container(),
            Set(members: [
                new FusionMemberRecord(@"D:\m.img", "apfs-store:main", 100, null),
                new FusionMemberRecord(@"D:\n.img", storeId!, 50, null),
            ]));
        Assert.False(decision.Complete);
        Assert.Equal("FusionIncompleteMemberSet", decision.ReasonCode);
    }
}
