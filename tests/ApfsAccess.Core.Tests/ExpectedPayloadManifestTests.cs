using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class ExpectedPayloadManifestTests
{
    [Fact]
    public void KnownExternalDigestMatchesExactCompleteInventoryWithoutPromotingNativeAuthority()
    {
        var node = ExpectedPayloadTestData.Manifest(); var manifest = ExpectedPayloadTestData.Parse(node);
        var report = ExpectedPayloadTestData.ParseReport(ExpectedPayloadTestData.Report());
        var result = manifest.Compare(report);
        Assert.Equal("MatchingProvidedManifest", result.Outcome); Assert.True(result.MatchingProvidedManifest);
        Assert.Equal(2, result.ComparedEntryCount); Assert.Equal(2, result.MatchedEntryCount);
        Assert.True(result.CompleteInventoryCoverage); Assert.Empty(result.Mismatches);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(node.ToJsonString()))), result.ManifestSha256);
        Assert.Contains("caller", result.ExpectedSource); Assert.Contains("not authenticated", result.Trust);
        Assert.False(report.Json.GetProperty("wholeVolumeVerified").GetBoolean());
        Assert.False(report.Json.GetProperty("payloadContentHashesVerified").GetBoolean());
        Assert.Equal("NotSupplied", report.PayloadInventory!.ExpectedComparison);
        Assert.All(report.PayloadInventory.Entries, e => Assert.Null(e.ExpectedSha256));
    }

    [Theory]
    [InlineData("hash", "HashMismatch")] [InlineData("size", "SizeMismatch")] [InlineData("both", "SizeAndHashMismatch")]
    public void ChangedObservationBytesOrSizeCannotMatch(string change, string code)
    {
        var node = ExpectedPayloadTestData.Report(); var p = node["payloadInventory"]!; var row = p["entries"]![0]!;
        if (change != "size") row["observedSha256"] = Convert.ToHexStringLower(SHA256.HashData("abd"u8));
        if (change != "hash") { row["logicalSizeBytes"] = "4"; row["logicalBytesRead"] = "4"; p["logicalBytesRead"] = "4"; }
        var result = ExpectedPayloadTestData.Parse(ExpectedPayloadTestData.Manifest()).Compare(ExpectedPayloadTestData.ParseReport(node));
        Assert.False(result.MatchingProvidedManifest); Assert.Equal(code, Assert.Single(result.Mismatches).Code);
        Assert.True(result.CompleteInventoryCoverage); Assert.Equal(1, result.MatchedEntryCount);
    }

    [Theory]
    [InlineData("missing")] [InlineData("extra")] [InlineData("stream")] [InlineData("inode")]
    [InlineData("case")] [InlineData("normalization")] [InlineData("kind")]
    public void ExactIdentityAndWholeInventoryCoverageAreRequired(string change)
    {
        var node = ExpectedPayloadTestData.Manifest(); var entries = node["entries"]!.AsArray();
        switch (change)
        {
            case "missing": entries.Add(ExpectedPayloadTestData.Expected("file-data", "9007199254740994", "90", null, "0", ExpectedPayloadTestData.EmptyDigest)); break;
            case "extra": entries.RemoveAt(1); break;
            case "stream": entries[0]!["streamOid"] = "18446744073709551614"; break;
            case "inode": entries[0]!["inodeOid"] = "9007199254740994"; break;
            case "case": entries[1]!["nameUtf8"] = "com.apple.empty"; break;
            case "normalization": entries[1]!["nameUtf8"] = "com.apple.E\u0301mpty"; break;
            case "kind": entries[0]!["kind"] = "xattr"; entries[0]!["nameUtf8"] = "file-data"; break;
        }
        var result = ExpectedPayloadTestData.Parse(node).Compare(ExpectedPayloadTestData.ParseReport(ExpectedPayloadTestData.Report()));
        Assert.False(result.MatchingProvidedManifest); Assert.False(result.CompleteInventoryCoverage);
        Assert.NotEmpty(result.Mismatches); Assert.Equal("Mismatch", result.Outcome);
    }

    [Theory]
    [InlineData("sourceIdentity", "image:different-held-owner")]
    [InlineData("sourceKind", "retained-admitted-raw")]
    [InlineData("containerUuid", "cccccccccccccccccccccccccccccccc")]
    [InlineData("volumeUuid", "cccccccccccccccccccccccccccccccc")]
    [InlineData("volumeOid", "102")] [InlineData("checkpointXid", "21")]
    [InlineData("storeOffsetBytes", "1")] [InlineData("storeSizeBytes", "2097151")]
    public void EveryScopeFieldIncludingOpaqueOwnerMustMatch(string field, string value)
    {
        var node = ExpectedPayloadTestData.Manifest(); node["scope"]![field] = value;
        var result = ExpectedPayloadTestData.Parse(node).Compare(ExpectedPayloadTestData.ParseReport(ExpectedPayloadTestData.Report()));
        Assert.Equal("Refused", result.Outcome); Assert.Equal("ScopeMismatch", Assert.Single(result.Mismatches).Code);
        Assert.Equal(0, result.ComparedEntryCount); Assert.False(result.CompleteInventoryCoverage);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void DuplicateAndStreamAliasExpectationsAreRejected(bool alias)
    {
        foreach (var index in new[] { 0, 1 })
        {
            var node = ExpectedPayloadTestData.Manifest(); var duplicate = node["entries"]![index]!.DeepClone();
            if (alias) duplicate["streamOid"] = "999";
            node["entries"]!.AsArray().Add(duplicate);
            Assert.Throws<InvalidDataException>(() => ExpectedPayloadTestData.Parse(node));
        }
    }

    [Theory]
    [InlineData("root")] [InlineData("scope")] [InlineData("entry")]
    public void SchemaIsClosedAndRejectsDuplicateProperties(string location)
    {
        var node = ExpectedPayloadTestData.Manifest();
        var target = location == "root" ? node : location == "scope" ? node["scope"]! : node["entries"]![0]!;
        target["path"] = "C:\\not-an-identity";
        Assert.Throws<InvalidDataException>(() => ExpectedPayloadTestData.Parse(node));
        var json = ExpectedPayloadTestData.Manifest().ToJsonString();
        var key = location == "root" ? "\"version\":1" : location == "scope" ? "\"volumeOid\":\"101\"" : "\"kind\":\"file-data\"";
        json = json.Replace(key, key + "," + key, StringComparison.Ordinal);
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        Assert.Throws<InvalidDataException>(() => ExpectedPayloadManifest.Parse(ExpectedPayloadInput.Read(stream, ExpectedPayloadManifest.MaximumManifestBytes)));
    }

    [Theory]
    [InlineData("entries")] [InlineData("name")] [InlineData("utf8name")] [InlineData("description")]
    [InlineData("size")] [InlineData("oid")] [InlineData("hash")] [InlineData("name-null")] [InlineData("name-nul")]
    [InlineData("file-name")] [InlineData("coverage")] [InlineData("unknown-kind")]
    public void MalformedOrOversizeFieldsAreRejected(string change)
    {
        var node = ExpectedPayloadTestData.Manifest(); var row = node["entries"]![1]!;
        switch (change)
        {
            case "entries": node["entries"] = new JsonArray(Enumerable.Range(1, 1025).Select(i => (JsonNode?)ExpectedPayloadTestData.Expected("file-data", $"{i}", $"{i}", null, "0", ExpectedPayloadTestData.EmptyDigest)).ToArray()); break;
            case "name": row["nameUtf8"] = new string('a', 4097); break;
            case "utf8name": row["nameUtf8"] = new string('\u4e2d', 1366); break;
            case "description": node["expectedSource"] = new string('a', 1025); break;
            case "size": row["logicalSizeBytes"] = "268435456"; break;
            case "oid": row["inodeOid"] = "01"; break;
            case "hash": row["expectedSha256"] = new string('Z', 64); break;
            case "name-null": row["nameUtf8"] = null; break;
            case "name-nul": row["nameUtf8"] = "bad\0name"; break;
            case "file-name": node["entries"]![0]!["nameUtf8"] = "abc"; break;
            case "coverage": node["coverage"] = "selected-files"; break;
            case "unknown-kind": row["kind"] = "directory"; break;
        }
        Assert.Throws<InvalidDataException>(() => ExpectedPayloadTestData.Parse(node));
    }

    [Fact]
    public void InputsAreBoundedStrictUtf8AndDetectSameSizeReplacement()
    {
        using var oversized = new MemoryStream(new byte[ExpectedPayloadManifest.MaximumManifestBytes + 1]);
        Assert.Throws<InvalidDataException>(() => ExpectedPayloadInput.Read(oversized, ExpectedPayloadManifest.MaximumManifestBytes));
        foreach (var bytes in new[] { new byte[] { 0xff }, "{"u8.ToArray(), "{\"format\":\"\\uD800\"}"u8.ToArray() })
        {
            using var malformed = new MemoryStream(bytes);
            Assert.Throws<InvalidDataException>(() => ExpectedPayloadManifest.Parse(ExpectedPayloadInput.Read(malformed, ExpectedPayloadManifest.MaximumManifestBytes)));
        }
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(ExpectedPayloadTestData.Manifest().ToJsonString()));
        var input = ExpectedPayloadInput.Read(stream, ExpectedPayloadManifest.MaximumManifestBytes);
        stream.Position = 0; stream.WriteByte((byte)'[');
        Assert.Throws<InvalidDataException>(() => input.EnsureUnchanged());
    }

    [Fact]
    public void UppercaseExpectedHexMatchesAfterDigestOnlyNormalization()
    {
        var node = ExpectedPayloadTestData.Manifest();
        foreach (var row in node["entries"]!.AsArray())
            row!["expectedSha256"] = row["expectedSha256"]!.GetValue<string>().ToUpperInvariant();
        var manifest = ExpectedPayloadTestData.Parse(node);
        Assert.Equal(ExpectedPayloadTestData.AbcDigest, manifest.Entries[0].ExpectedSha256);
        Assert.Equal("com.apple.Empty", manifest.Entries[1].NameUtf8);
        Assert.Equal("image:opaque-held-owner", manifest.Scope.SourceIdentity);
        Assert.True(manifest.Compare(ExpectedPayloadTestData.ParseReport(ExpectedPayloadTestData.Report())).MatchingProvidedManifest);
        var bytes = Encoding.UTF8.GetBytes(node.ToJsonString());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), manifest.ManifestSha256);
    }

    [Theory]
    [InlineData("\\uD800")] [InlineData("\\uDC00")] [InlineData("\\uD800x")]
    public void UnpairedSurrogateEscapesInXattrNamesCannotBeDecodedLossily(string escape)
    {
        var json = ExpectedPayloadTestData.Manifest().ToJsonString()
            .Replace("\"com.apple.Empty\"", "\"" + escape + "\"", StringComparison.Ordinal);
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        Assert.Throws<InvalidDataException>(() => ExpectedPayloadManifest.Parse(
            ExpectedPayloadInput.Read(stream, ExpectedPayloadManifest.MaximumManifestBytes)));
    }

    [Fact]
    public void PartialMissingAndForgedCompleteInventoriesNeverBecomeMatches()
    {
        var manifest = ExpectedPayloadTestData.Parse(ExpectedPayloadTestData.Manifest());
        var report = ExpectedPayloadTestData.ParseReport(ExpectedPayloadTestData.Report());
        var s = report.Scope; var scope = new ExpectedPayloadScope(s.SourceIdentity, s.SourceKind, s.ContainerUuid, s.VolumeUuid,
            s.VolumeOid, s.CheckpointXid, s.StoreOffsetBytes, s.StoreSizeBytes);
        foreach (var inventory in new[] { null, report.PayloadInventory! with { EnumerationComplete = false },
            report.PayloadInventory! with { ReadComplete = false }, report.PayloadInventory! with { HashesObserved = false } })
        { var result = manifest.Compare(scope, inventory); Assert.Equal("Incomplete", result.Outcome); Assert.False(result.MatchingProvidedManifest); }
        Assert.Throws<InvalidDataException>(() => manifest.Compare(scope, report.PayloadInventory! with { EntryCount = "1" }));
    }

    [Fact]
    public void BoundJsonIsRevalidatedInsteadOfTrustingReplaceableRecordProperties()
    {
        var manifest = ExpectedPayloadTestData.Parse(ExpectedPayloadTestData.Manifest());
        var report = ExpectedPayloadTestData.ParseReport(ExpectedPayloadTestData.Report());
        Assert.True(manifest.Compare(report with { PayloadInventory = null, Scope = report.Scope with { SourceIdentity = "forged" } }).MatchingProvidedManifest);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void BoundPartialReadOrEnumerationCannotCompareEvenMatchingRequestedRows(bool enumerationIncomplete)
    {
        var result = ExpectedPayloadTestData.Parse(ExpectedPayloadTestData.Manifest())
            .Compare(ExpectedPayloadTestData.ParseReport(ExpectedPayloadTestData.PartialReport(enumerationIncomplete)));
        Assert.Equal("Incomplete", result.Outcome); Assert.Equal(0, result.ComparedEntryCount);
        Assert.False(result.CompleteInventoryCoverage); Assert.False(result.MatchingProvidedManifest);
    }

    [Fact]
    public void ComparisonOrderIsIndependentOfManifestRowOrderAndPreservesUtf8Identity()
    {
        var original = ExpectedPayloadTestData.Manifest(); var reversed = ExpectedPayloadTestData.Manifest();
        var rows = reversed["entries"]!.AsArray(); var first = rows[0]!.DeepClone(); var second = rows[1]!.DeepClone();
        rows.Clear(); rows.Add(second); rows.Add(first);
        original["entries"]![0]!["expectedSha256"] = new string('1', 64);
        reversed["entries"]![1]!["expectedSha256"] = new string('1', 64);
        var report = ExpectedPayloadTestData.ParseReport(ExpectedPayloadTestData.Report());
        var a = ExpectedPayloadTestData.Parse(original).Compare(report); var b = ExpectedPayloadTestData.Parse(reversed).Compare(report);
        Assert.Equal(a.Mismatches, b.Mismatches); Assert.NotEqual(a.ManifestSha256, b.ManifestSha256);
        var decomposed = ExpectedPayloadTestData.Manifest(); var observed = ExpectedPayloadTestData.Report();
        decomposed["entries"]![1]!["nameUtf8"] = "e\u0301";
        observed["payloadInventory"]!["entries"]![1]!["nameUtf8"] = "\u00e9";
        Assert.False(ExpectedPayloadTestData.Parse(decomposed).Compare(ExpectedPayloadTestData.ParseReport(observed)).MatchingProvidedManifest);
    }

    [Fact]
    public void DetectsInputChangesDuringReadAndBoundsStreamsWhoseLengthUnderreports()
    {
        using var changed = new ChangingStream();
        Assert.Throws<InvalidDataException>(() => ExpectedPayloadInput.Read(changed, 100));
        using var oversized = new UnderreportedStream(new byte[101]);
        Assert.Throws<InvalidDataException>(() => ExpectedPayloadInput.Read(oversized, 100));
    }

    [Fact]
    public void EmptyAndMaximumInventoryBoundsAreComparableWithoutWeakeningCoverage()
    {
        foreach (var count in new[] { 0, 1024 })
        {
            var manifest = ExpectedPayloadTestData.Manifest(); var report = ExpectedPayloadTestData.Report();
            var expectedRows = new JsonArray(); var observedRows = new JsonArray();
            for (var i = 1; i <= count; ++i)
            {
                var size = i == count ? "268435456" : "0";
                var digest = i == count ? ExpectedPayloadTestData.AbcDigest : ExpectedPayloadTestData.EmptyDigest;
                expectedRows.Add(ExpectedPayloadTestData.Expected("file-data", $"{i}", $"{i}", null, size, digest));
                observedRows.Add(new JsonObject { ["kind"] = "file-data", ["inodeOid"] = $"{i}", ["streamOid"] = $"{i}",
                    ["nameUtf8"] = null, ["logicalSizeBytes"] = size, ["logicalBytesRead"] = size, ["readOutcome"] = "Complete",
                    ["observedSha256"] = digest, ["expectedSha256"] = null });
            }
            manifest["entries"] = expectedRows; var p = report["payloadInventory"]!;
            p["entries"] = observedRows; p["entryCount"] = $"{count}"; p["logicalBytesRead"] = count == 0 ? "0" : "268435456";
            var result = ExpectedPayloadTestData.Parse(manifest).Compare(ExpectedPayloadTestData.ParseReport(report));
            Assert.True(result.MatchingProvidedManifest); Assert.Equal(count, result.MatchedEntryCount);
        }
    }

    [Fact]
    public void MaximumUtf8NameAndSharedStreamsRemainSeparateExactEntries()
    {
        var manifest = ExpectedPayloadTestData.Manifest(); var report = ExpectedPayloadTestData.Report();
        var name = new string('\u4e2d', 1365) + "a";
        manifest["entries"]![1]!["nameUtf8"] = name;
        report["payloadInventory"]!["entries"]![1]!["nameUtf8"] = name;
        var extra = ExpectedPayloadTestData.Expected("xattr", "9007199254740994", "0", name, "0", ExpectedPayloadTestData.EmptyDigest);
        manifest["entries"]!.AsArray().Add(extra);
        var observedExtra = report["payloadInventory"]!["entries"]![1]!.DeepClone(); observedExtra["inodeOid"] = "9007199254740994";
        report["payloadInventory"]!["entries"]!.AsArray().Add(observedExtra); report["payloadInventory"]!["entryCount"] = "3";
        var result = ExpectedPayloadTestData.Parse(manifest).Compare(ExpectedPayloadTestData.ParseReport(report));
        Assert.True(result.MatchingProvidedManifest); Assert.Equal(3, result.MatchedEntryCount);
    }
    private sealed class ChangingStream : MemoryStream
    {
        private int readPass;
        public ChangingStream() : base("abc"u8.ToArray()) { }
        public override long Position { get => base.Position; set { base.Position = value; if (++readPass == 2) { base.WriteByte((byte)'d'); base.Position = 0; } } }
    }
    private sealed class UnderreportedStream(byte[] bytes) : MemoryStream(bytes)
    { public override long Length => 1; }

    [Theory]
    [InlineData("verified")] [InlineData("whole")] [InlineData("expected")] [InlineData("entry-expected")]
    [InlineData("duplicate")] [InlineData("selection")]
    public void ExistingNegativeNativeWirePinsRemainEnforced(string change)
    {
        var node = ExpectedPayloadTestData.Report();
        switch (change)
        {
            case "verified": node["payloadContentHashesVerified"] = true; break;
            case "whole": node["wholeVolumeVerified"] = true; break;
            case "expected": node["payloadInventory"]!["expectedComparison"] = "Match"; break;
            case "entry-expected": node["payloadInventory"]!["entries"]![0]!["expectedSha256"] = ExpectedPayloadTestData.AbcDigest; break;
            case "duplicate": node["payloadInventory"]!["entries"]![1] = node["payloadInventory"]!["entries"]![0]!.DeepClone(); break;
            case "selection": node["selected"]!["scope"]!["checkpointXid"] = "21"; break;
        }
        var forged = new LiveVolumeVerificationReport(ExpectedPayloadTestData.ParseReport(ExpectedPayloadTestData.Report()).Scope,
            "Complete", 0, JsonSerializer.SerializeToElement(node));
        Assert.Throws<InvalidDataException>(() => ExpectedPayloadTestData.Parse(ExpectedPayloadTestData.Manifest()).Compare(forged));
    }
}
