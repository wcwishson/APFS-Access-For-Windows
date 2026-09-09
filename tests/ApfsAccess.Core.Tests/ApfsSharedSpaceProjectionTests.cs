using System.Text.Json;

namespace ApfsAccess.Core.Tests;

public sealed class ApfsSharedSpaceProjectionTests
{
    [Fact]
    public void TypedProjectionRoundTripsUInt64AndNullWithoutPrecisionLoss()
    {
        var amount = new ApfsSpaceAmount(ulong.MaxValue / 4096, ulong.MaxValue - 4095);
        var projection = new ApfsSharedSpaceProjection("apfs-container:" + new string('a',32), ulong.MaxValue, 4096,
            amount, new(0,0), amount,
            [new("apfs-vol:" + new string('a',32) + ":101", 101, new(0,0), null, amount, new(0,0), new(0,0), null, null)]);
        var json = JsonSerializer.Serialize(projection);
        Assert.Contains("\"checkpointXid\":\"18446744073709551615\"", json);
        var parsed = JsonSerializer.Deserialize<ApfsSharedSpaceProjection>(json)!;
        Assert.Equal(projection.CheckpointXid, parsed.CheckpointXid);
        Assert.Equal(amount, parsed.Total);
        Assert.Equal(amount, parsed.Volumes[0].Quota);
        Assert.Null(parsed.Volumes[0].Reserve);
        Assert.Null(parsed.Volumes[0].Snapshot);
        Assert.Null(parsed.Volumes[0].Purgeable);
        Assert.Equal(0UL, parsed.Free.Bytes);
    }

    [Theory]
    [InlineData("0")][InlineData("\"00\"")][InlineData("\"+1\"")][InlineData("\"-1\"")]
    [InlineData("\"18446744073709551616\"")][InlineData("null")][InlineData("\"1.0\"")]
    public void AmountRequiresCanonicalUInt64Strings(string blocks)
        => Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ApfsSpaceAmount>("{\"blocks\":" + blocks + ",\"bytes\":\"0\"}"));

    [Theory]
    [InlineData("{}")][InlineData("{\"blocks\":\"0\"}")]
    [InlineData("{\"blocks\":\"0\",\"bytes\":\"0\",\"extra\":0}")]
    public void PartialOrUnknownAmountFieldsRejected(string json)
        => Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ApfsSpaceAmount>(json));
}
