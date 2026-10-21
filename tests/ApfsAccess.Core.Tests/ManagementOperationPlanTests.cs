using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

// Task 11 Step 2: verify-plan-confirm-apply semantics. Plans bind the exact
// operation target plus the observed checkpoint generation to a server-side
// single-use token. These pins prove fail-closed issuance (unsupported
// operations, bad identity, drive-letter defaulting, zero-XID, capacity
// change, lifetime bounds, registry bound) and fail-closed apply (unknown /
// expired / replayed tokens, tampered identity, checkpoint drift), with the
// registry copy as the sole authority.
public sealed class ManagementOperationPlanTests
{
    private static readonly Guid Container = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid Volume = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private const string Device = "device-1";
    private const ulong Oid = 24;
    private const ulong Xid = 90;

    private static ManagementPlanRegistry Registry(DateTimeOffset now)
    {
        var current = now;
        return new ManagementPlanRegistry(() => current);
    }

    private static ManagementPlanVerdict Issue(
        ManagementPlanRegistry registry,
        ManagementOperationKind operation = ManagementOperationKind.RenameVolume,
        string? deviceId = Device,
        Guid? container = null,
        Guid? volume = null,
        ulong oid = Oid,
        ulong xid = Xid,
        long capacity = 0,
        TimeSpan? ttl = null,
        Func<DateTimeOffset>? clock = null)
        => ManagementOperationPlans.TryIssue(operation, deviceId, container ?? Container,
            volume ?? Volume, oid, xid, capacity, registry, ttl, clock);

    private static ManagementApplyRequest ApplyFor(ManagementOperationPlan plan, ulong? xid = null)
        => new(plan.ConfirmationToken, plan.DeviceId, plan.ContainerUuid,
            plan.VolumeUuid, plan.VolumeObjectId, xid ?? plan.ObservedCheckpointXid);

    [Fact]
    public void Apply_WrongOperationDoesNotConsumeTheBoundToken()
    {
        var registry = Registry(DateTimeOffset.UtcNow);
        var plan = Issue(registry).Plan!;
        var wrong = registry.TryConsume(ApplyFor(plan), ManagementOperationKind.SetQuotaReserve);
        Assert.False(wrong.Ok);
        Assert.Equal(ManagementOperationPlans.OperationMismatch, wrong.Code);
        Assert.Equal(1, registry.LiveCount);
        Assert.True(registry.TryConsume(ApplyFor(plan), ManagementOperationKind.RenameVolume).Ok);
        Assert.False(registry.TryConsume(ApplyFor(plan), ManagementOperationKind.RenameVolume).Ok);
    }

    [Fact]
    public void Issue_RenameAndQuota_AcceptedWithBoundToken()
    {
        foreach (var operation in new[] { ManagementOperationKind.RenameVolume, ManagementOperationKind.SetQuotaReserve })
        {
            var registry = Registry(DateTimeOffset.UtcNow);
            var verdict = Issue(registry, operation);
            Assert.True(verdict.Ok, verdict.Detail);
            Assert.NotNull(verdict.Plan);
            Assert.Equal(ManagementOperationPlans.Issued, verdict.Code);
            Assert.StartsWith("mgmt-plan-v1:", verdict.Plan.PlanId, StringComparison.Ordinal);
            Assert.Equal(64, verdict.Plan.ConfirmationToken.Length);
            Assert.True(verdict.Plan.ConfirmationToken.All(char.IsAsciiHexDigit));
            Assert.Equal(1, registry.LiveCount);
        }
    }

    [Theory]
    [InlineData(ManagementOperationKind.Unknown)]
    [InlineData((ManagementOperationKind)99)]
    public void Issue_WithoutPlannerEntryPoint_Refused(ManagementOperationKind operation)
    {
        var verdict = Issue(Registry(DateTimeOffset.UtcNow), operation);
        Assert.False(verdict.Ok);
        Assert.Equal(ManagementOperationPlans.UnsupportedOperation, verdict.Code);
        Assert.Null(verdict.Plan);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Issue_BadDeviceIdentity_Refused(string? deviceId)
    {
        var verdict = Issue(Registry(DateTimeOffset.UtcNow), deviceId: deviceId);
        Assert.False(verdict.Ok);
        Assert.Equal(ManagementOperationPlans.InvalidIdentity, verdict.Code);
    }

    [Theory]
    [InlineData("E:")]
    [InlineData("e:")]
    [InlineData(@"F:\")]
    [InlineData("G:/")]
    public void Issue_DriveLetterIdentity_Refused(string deviceId)
    {
        var verdict = Issue(Registry(DateTimeOffset.UtcNow), deviceId: deviceId);
        Assert.False(verdict.Ok);
        Assert.Equal(ManagementOperationPlans.DriveLetterIdentity, verdict.Code);
    }

    [Fact]
    public void Issue_PhysicalAndImageDeviceShapes_Accepted()
    {
        foreach (var deviceId in new[] { @"\\.\PhysicalDrive2", "device-1", "apfs-store:raw", @"D:\images\source.apfs" })
        {
            var verdict = Issue(Registry(DateTimeOffset.UtcNow), deviceId: deviceId);
            Assert.True(verdict.Ok, deviceId);
        }
    }

    [Fact]
    public void Issue_EmptyGuidOrZeroOidOrZeroXid_Refused()
    {
        Assert.Equal(ManagementOperationPlans.InvalidIdentity,
            Issue(Registry(DateTimeOffset.UtcNow), container: Guid.Empty).Code);
        Assert.Equal(ManagementOperationPlans.InvalidIdentity,
            Issue(Registry(DateTimeOffset.UtcNow), volume: Guid.Empty).Code);
        Assert.Equal(ManagementOperationPlans.InvalidIdentity,
            Issue(Registry(DateTimeOffset.UtcNow), oid: 0).Code);
        Assert.Equal(ManagementOperationPlans.InvalidCheckpoint,
            Issue(Registry(DateTimeOffset.UtcNow), xid: 0).Code);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(-4096)]
    [InlineData(long.MaxValue)]
    public void Issue_NonzeroCapacityChange_Refused(long capacity)
    {
        var verdict = Issue(Registry(DateTimeOffset.UtcNow), capacity: capacity);
        Assert.False(verdict.Ok);
        Assert.Equal(ManagementOperationPlans.CapacityChangeUnsupported, verdict.Code);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(29)]
    [InlineData(901)]
    public void Issue_LifetimeOutsideBounds_Refused(int seconds)
    {
        var verdict = Issue(Registry(DateTimeOffset.UtcNow), ttl: TimeSpan.FromSeconds(seconds));
        Assert.False(verdict.Ok);
        Assert.Equal(ManagementOperationPlans.InvalidLifetime, verdict.Code);
    }

    [Fact]
    public void Issue_TokensAreUniquePerPlan()
    {
        var registry = Registry(DateTimeOffset.UtcNow);
        var tokens = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < 8; i++)
            Assert.True(tokens.Add(Issue(registry).Plan!.ConfirmationToken));
    }

    [Fact]
    public void Registry_RefusesBeyondBound()
    {
        var registry = Registry(DateTimeOffset.UtcNow);
        for (var i = 0; i < ManagementOperationPlans.MaximumLivePlans; i++)
            Assert.True(Issue(registry).Ok);
        var overflow = Issue(registry);
        Assert.False(overflow.Ok);
        Assert.Equal(ManagementOperationPlans.RegistryFull, overflow.Code);
    }

    [Fact]
    public void Consume_MatchingApply_SucceedsOnceThenUnknown()
    {
        var registry = Registry(DateTimeOffset.UtcNow);
        var plan = Issue(registry).Plan!;
        var first = registry.TryConsume(ApplyFor(plan));
        Assert.True(first.Ok, first.Detail);
        Assert.Equal(plan.PlanId, first.Plan!.PlanId);
        Assert.Equal(0, registry.LiveCount);
        var replay = registry.TryConsume(ApplyFor(plan));
        Assert.False(replay.Ok);
        Assert.Equal(ManagementOperationPlans.UnknownToken, replay.Code);
    }

    [Fact]
    public void Consume_UnknownToken_Refused()
    {
        var registry = Registry(DateTimeOffset.UtcNow);
        var verdict = registry.TryConsume(new ManagementApplyRequest(
            new string('a', 64), Device, Container, Volume, Oid, Xid));
        Assert.False(verdict.Ok);
        Assert.Equal(ManagementOperationPlans.UnknownToken, verdict.Code);
    }

    [Theory]
    [InlineData("device-2")]
    [InlineData("DEVICE-1")]
    public void Consume_TamperedDevice_Refused(string deviceId)
    {
        var registry = Registry(DateTimeOffset.UtcNow);
        var plan = Issue(registry).Plan!;
        var verdict = registry.TryConsume(ApplyFor(plan) with { DeviceId = deviceId });
        Assert.False(verdict.Ok);
        Assert.Equal(ManagementOperationPlans.IdentityMismatch, verdict.Code);
        Assert.Equal(1, registry.LiveCount);
    }

    [Fact]
    public void Consume_TamperedVolumeIdentity_Refused()
    {
        var registry = Registry(DateTimeOffset.UtcNow);
        var plan = Issue(registry).Plan!;
        foreach (var tampered in new[]
        {
            ApplyFor(plan) with { ContainerUuid = Guid.NewGuid() },
            ApplyFor(plan) with { VolumeUuid = Guid.NewGuid() },
            ApplyFor(plan) with { VolumeObjectId = plan.VolumeObjectId + 1 },
        })
        {
            var verdict = registry.TryConsume(tampered);
            Assert.False(verdict.Ok);
            Assert.Equal(ManagementOperationPlans.IdentityMismatch, verdict.Code);
        }
        Assert.Equal(1, registry.LiveCount);
    }

    [Fact]
    public void Consume_CheckpointDrift_FailsClosedButTokenStaysLive()
    {
        var registry = Registry(DateTimeOffset.UtcNow);
        var plan = Issue(registry).Plan!;
        var stale = registry.TryConsume(ApplyFor(plan, xid: plan.ObservedCheckpointXid + 1));
        Assert.False(stale.Ok);
        Assert.Equal(ManagementOperationPlans.StaleCheckpoint, stale.Code);
        var fresh = registry.TryConsume(ApplyFor(plan));
        Assert.True(fresh.Ok, fresh.Detail);
    }

    [Fact]
    public void Consume_ExpiredPlan_RefusedAndSwept()
    {
        var start = new DateTimeOffset(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);
        var current = start;
        var registry = new ManagementPlanRegistry(() => current);
        var plan = ManagementOperationPlans.TryIssue(ManagementOperationKind.RenameVolume,
            Device, Container, Volume, Oid, Xid, 0, registry,
            TimeSpan.FromSeconds(30), () => start).Plan!;
        current = start.AddSeconds(31);
        var verdict = registry.TryConsume(ApplyFor(plan));
        Assert.False(verdict.Ok);
        Assert.Equal(ManagementOperationPlans.ExpiredPlan, verdict.Code);
        Assert.Equal(0, registry.LiveCount);
    }

    [Fact]
    public void PlanId_BindsContentDeterministically()
    {
        var at = new DateTimeOffset(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);
        var first = ManagementOperationPlans.ComputePlanId(ManagementOperationKind.RenameVolume,
            Device, Container, Volume, Oid, Xid, 0, at, TimeSpan.FromMinutes(5));
        var second = ManagementOperationPlans.ComputePlanId(ManagementOperationKind.RenameVolume,
            Device, Container, Volume, Oid, Xid, 0, at, TimeSpan.FromMinutes(5));
        Assert.Equal(first, second);
        var drifted = ManagementOperationPlans.ComputePlanId(ManagementOperationKind.RenameVolume,
            Device, Container, Volume, Oid, Xid + 1, 0, at, TimeSpan.FromMinutes(5));
        Assert.NotEqual(first, drifted);
    }
}
