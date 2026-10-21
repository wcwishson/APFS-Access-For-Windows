using System.Text.Json.Nodes;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class RetainedOwnershipVerificationTests
{
    private static ApfsImageVerificationResult Parse(JsonObject report, string fixture = "ordinary", int exit = 0,
        ApfsImageVerificationRequest? request = null) => NativeApfsImageVerifier.ParseReport(report.ToJsonString(), exit,
            request ?? RetainedOwnershipNativeReports.Request(fixture), RetainedOwnershipNativeReports.Identity(fixture));

    [Theory]
    [InlineData("ordinary", 0, ApfsVerificationOutcome.Complete)]
    [InlineData("snapshot", 0, ApfsVerificationOutcome.Complete)]
    [InlineData("orphan", 3, ApfsVerificationOutcome.Incomplete)]
    [InlineData("wrong-volume", 4, ApfsVerificationOutcome.Refused)]
    [InlineData("ordinary-default", 0, ApfsVerificationOutcome.Complete)]
    public void ActualNativeReportsDecodeWithoutManagedPlanConstruction(string name, int exit, ApfsVerificationOutcome outcome)
    {
        var raw = RetainedOwnershipNativeReports.Read(name);
        var result = Parse(raw, name, exit);
        Assert.Equal(outcome, result.Outcome); Assert.Equal(exit, result.NativeExitCode);
        Assert.Equal(raw.ToJsonString(), JsonNode.Parse(result.Report.GetRawText())!.ToJsonString());
        Assert.False(result.Report.GetProperty("wholeVolumeVerified").GetBoolean());
        Assert.False(result.Report.GetProperty("payloadContentHashesVerified").GetBoolean());
        if (name == "ordinary-default") Assert.Equal(3, result.Report.GetProperty("version").GetInt32());
        else
        {
            Assert.Equal(4, result.Report.GetProperty("version").GetInt32());
            if (exit == 0)
            {
                var retained = result.Report.GetProperty("retainedOwnership");
                Assert.Equal("6", retained.GetProperty("allocatedInternalBlocks").GetString());
                Assert.Equal("98", retained.GetProperty("reservedMainBlocks").GetString());
                Assert.Equal(System.Text.Json.JsonValueKind.Null, retained.GetProperty("snapshotTotalBytes").ValueKind);
                Assert.Equal(System.Text.Json.JsonValueKind.Null, retained.GetProperty("purgeableBytes").ValueKind);
            }
            else Assert.Equal(System.Text.Json.JsonValueKind.Null, result.Report.GetProperty("retainedOwnership").ValueKind);
        }
        if (name == "orphan") Assert.Contains(result.Report.GetProperty("findings").EnumerateArray(), f => f.GetProperty("code").GetInt32() == 26);
    }

    [Theory]
    [InlineData("source-path")] [InlineData("source-identity")] [InlineData("source-lease")] [InlineData("source-kind")]
    [InlineData("volume")] [InlineData("container")] [InlineData("oid")] [InlineData("checkpoint")] [InlineData("offset")] [InlineData("size")]
    [InlineData("selected-volume")] [InlineData("read-only")] [InlineData("whole-claim")] [InlineData("hash-claim")]
    [InlineData("scope-flag")] [InlineData("version")] [InlineData("unknown-root")] [InlineData("repair-prefix")]
    public void ForgedScopeAndAuthorityNeverDecodeAsComplete(string change)
    {
        var r = RetainedOwnershipNativeReports.Read(); var scope = r["requestedScope"]!;
        switch (change)
        {
            case "source-path": r["source"]!["path"] = @"D:\other.apfs"; break;
            case "source-identity":
                Assert.NotEqual("windows-file:9:9:2097152:9", r["source"]!["identity"]!.GetValue<string>());
                r["source"]!["identity"] = "windows-file:9:9:2097152:9"; break;
            case "source-lease": r["source"]!["lease"] = "unleased"; break;
            case "source-kind": r["source"]!["kind"] = "physical"; break;
            case "volume": scope["volumeUuid"] = new string('c', 32); break;
            case "container": scope["containerUuid"] = new string('c', 32); break;
            case "oid": scope["volumeOid"] = "102"; break;
            case "checkpoint": scope["checkpointXid"] = "32"; break;
            case "offset": scope["storeOffsetBytes"] = "4096"; break;
            case "size": scope["storeSizeBytes"] = "2093056"; break;
            case "selected-volume": r["selected"]!["volumeUuid"] = new string('c', 32); break;
            case "read-only": r["readOnly"] = false; break;
            case "whole-claim": r["wholeVolumeVerified"] = true; break;
            case "hash-claim": r["payloadContentHashesVerified"] = true; break;
            case "scope-flag": scope["accountRetainedOwnership"] = false; break;
            case "version": r["version"] = 3; break;
            case "unknown-root": r["reclaimableBytes"] = "4096"; break;
            default: r["repair"]!["planId"] = r["repair"]!["planId"]!.GetValue<string>().Replace("ownership-v1|", "v2|", StringComparison.Ordinal); break;
        }
        Assert.Throws<InvalidDataException>(() => Parse(r));
    }

    [Theory]
    [InlineData("overlap")] [InlineData("cross-overlap")] [InlineData("adjacent")] [InlineData("unordered")]
    [InlineData("zero-count")] [InlineData("past-end")] [InlineData("overflow")] [InlineData("empty-metadata")]
    [InlineData("selected-not-owned")] [InlineData("unknown-range-field")]
    public void RetainedRangesMustBeCanonicalDisjointAndOwnSelectedRoots(string change)
    {
        var r = RetainedOwnershipNativeReports.Read(); var a = r["retainedOwnership"]!;
        var metadata = a["metadataRanges"]!.AsArray(); var payload = a["payloadRanges"]!.AsArray();
        switch (change)
        {
            case "overlap": metadata[1]!["physicalBlock"] = "0"; break;
            case "cross-overlap": payload[0]!["physicalBlock"] = "2"; break;
            case "adjacent": payload[1]!["physicalBlock"] = "2"; break;
            case "unordered": payload[0]!["physicalBlock"] = "221"; break;
            case "zero-count": metadata[0]!["blockCount"] = "0"; break;
            case "past-end": payload[2]!["physicalBlock"] = "512"; break;
            case "overflow": payload[2]!["blockCount"] = "18446744073709551615"; break;
            case "empty-metadata": metadata.Clear(); break;
            case "selected-not-owned": metadata[7]!["physicalBlock"] = "140"; break;
            default: metadata[0]!["kind"] = "reclaimable"; break;
        }
        Assert.Throws<InvalidDataException>(() => Parse(r));
    }

    [Theory]
    [InlineData("main-partition")] [InlineData("internal-partition")] [InlineData("partition-overflow")]
    [InlineData("main-capacity")] [InlineData("owned-count")] [InlineData("residual")]
    [InlineData("snapshot-total")] [InlineData("purgeable")] [InlineData("snapshot-exclusive")]
    [InlineData("snapshot-bytes")] [InlineData("snapshot-payload")] [InlineData("snapshot-volume-duplicate")]
    [InlineData("snapshot-volume-missing")] [InlineData("current-metadata-exceeds-retained")]
    [InlineData("current-payload-exceeds-retained")] [InlineData("graph-partition-total")]
    public void CountsAndUnknownAmountsMustNotContradictOwnedRanges(string change)
    {
        var r = RetainedOwnershipNativeReports.Read(); var a = r["retainedOwnership"]!; var census = r["allocationCensus"]!;
        var usage = a["snapshotPayloadUsage"]!.AsArray();
        switch (change)
        {
            case "main-partition": a["allocatedMainBlocks"] = "139"; break;
            case "internal-partition": a["allocatedInternalBlocks"] = "7"; break;
            case "partition-overflow": a["reservedMainBlocks"] = "18446744073709551615"; break;
            case "main-capacity": a["allocatedMainBlocks"] = "513"; a["reservedMainBlocks"] = "473"; break;
            case "owned-count": a["ownedMainBlocks"] = "41"; a["reservedMainBlocks"] = "97"; break;
            case "residual": census["unattributedMainBlocks"] = "1"; census["unattributedMainRanges"] = new JsonArray(new JsonObject { ["physicalBlock"] = "400", ["blockCount"] = "1" }); break;
            case "snapshot-total": a["snapshotTotalBytes"] = "0"; break;
            case "purgeable": a["purgeableBytes"] = "4096"; break;
            case "snapshot-exclusive": usage[0]!["exclusiveBlocks"] = "1"; usage[0]!["exclusiveBytes"] = "4096"; break;
            case "snapshot-bytes": usage[0]!["referencedBytes"] = "4096"; break;
            case "snapshot-payload": usage[0]!["referencedBlocks"] = "4"; usage[0]!["referencedBytes"] = "16384"; break;
            case "snapshot-volume-duplicate": usage.Add(usage[0]!.DeepClone()); break;
            case "snapshot-volume-missing": usage[0]!["volumeOid"] = "102"; break;
            case "current-metadata-exceeds-retained": census["currentMetadataBlocks"] = "500"; break;
            case "current-payload-exceeds-retained": census["currentPayloadBlocks"] = "4"; break;
            default: a["ownedMainBlocks"] = "39"; a["reservedMainBlocks"] = "99"; break;
        }
        // None of these fields is part of the repair plan binding: a refusal must come from strict decoding.
        Assert.Throws<InvalidDataException>(() => Parse(r));
    }

    [Theory]
    [InlineData("zero")] [InlineData("leading-zero")] [InlineData("overflow")] [InlineData("number")]
    [InlineData("duplicate")] [InlineData("reversed")] [InlineData("after-endpoint")] [InlineData("missing-endpoint")]
    public void RetainedCheckpointIdsAreCanonicalOrderedAndEndpointBound(string change)
    {
        var r = RetainedOwnershipNativeReports.Read(); var xids = r["retainedOwnership"]!["checkpointXids"]!.AsArray();
        switch (change)
        {
            case "zero": xids[0] = "0"; break;
            case "leading-zero": xids[0] = "020"; break;
            case "overflow": xids[0] = "18446744073709551616"; break;
            case "number": xids[0] = 20; break;
            case "duplicate": xids[1] = "20"; break;
            case "reversed": xids[0] = "31"; break;
            case "after-endpoint": xids[2] = "32"; break;
            default: xids.RemoveAt(2); break;
        }
        Assert.Throws<InvalidDataException>(() => Parse(r));
    }

    [Theory]
    [InlineData(12, "implemented")] [InlineData(13, "required")] [InlineData(12, "state")]
    [InlineData(13, "state")] [InlineData(15, "implemented")] [InlineData(16, "state")]
    public void CompleteV4RequiresExactCoverageAndNoCryptoOrFusionClaim(int check, string field)
    {
        var r = RetainedOwnershipNativeReports.Read();
        var coverage = Assert.Single(r["coverage"]!.AsArray(), c => c!["check"]!.GetValue<int>() == check)!;
        if (field == "state") coverage[field] = 1;
        else coverage[field] = !coverage[field]!.GetValue<bool>();
        Assert.Throws<InvalidDataException>(() => Parse(r));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void OptInIsExactAndLegacyReportCannotSatisfyAccounting(bool legacy)
    {
        var r = RetainedOwnershipNativeReports.Read(legacy ? "ordinary-default" : "ordinary");
        Assert.Throws<InvalidDataException>(() => Parse(r, request: RetainedOwnershipNativeReports.Request() with { AccountRetainedOwnership = legacy }));
    }

    [Fact]
    public void IncompleteCannotPublishPartialOwnership()
    {
        var r = RetainedOwnershipNativeReports.Read("orphan");
        r["retainedOwnership"] = RetainedOwnershipNativeReports.Read()["retainedOwnership"]!.DeepClone();
        Assert.Throws<InvalidDataException>(() => Parse(r, "orphan", 3));
    }

    [Theory]
    [InlineData(26, 12)] [InlineData(27, 13)]
    [InlineData(3, 12)] [InlineData(3, 13)] [InlineData(4, 12)] [InlineData(4, 13)]
    [InlineData(5, 12)] [InlineData(5, 13)] [InlineData(6, 12)] [InlineData(6, 13)]
    [InlineData(7, 12)] [InlineData(7, 13)]
    public void CompletedObservationsWithSeparateAccountingFaultRequireExplicitContext(int code, int check)
    {
        var native = RetainedOwnershipNativeReports.Read("orphan");
        var finding = native["findings"]![0]!; finding["code"] = code; finding["check"] = check;
        using var document = System.Text.Json.JsonDocument.Parse(native.ToJsonString());
        var inventory = document.RootElement.GetProperty("payloadInventory");
        var findings = document.RootElement.GetProperty("findings");
        Assert.Throws<InvalidDataException>(() => ApfsAccess.Core.CurrentPayloadInventory.Parse(inventory, 2, 2, true, findings));
        Assert.Throws<InvalidDataException>(() => ApfsAccess.Core.CurrentPayloadInventory.Parse(inventory, 2, 2, true, findings, retainedAccounting: false));
        var parsed = ApfsAccess.Core.CurrentPayloadInventory.Parse(inventory, 2, 2, true, findings, retainedAccounting: true);
        Assert.True(parsed.EnumerationComplete); Assert.True(parsed.ReadComplete); Assert.True(parsed.HashesObserved);
        Assert.Equal("NotSupplied", parsed.ExpectedComparison);
        Assert.Throws<InvalidDataException>(() => ApfsAccess.Core.CurrentPayloadInventory.Parse(inventory, 3, 2, true, findings, retainedAccounting: true));
    }

    [Theory]
    [InlineData(26, 13)] [InlineData(27, 12)] [InlineData(3, 7)] [InlineData(6, 21)]
    [InlineData(7, 19)] [InlineData(8, 13)] [InlineData(17, 13)]
    public void ExplicitAccountingContextDoesNotAdmitCurrentGraphOrAdmissionFailures(int code, int check)
    {
        var native = RetainedOwnershipNativeReports.Read("orphan");
        native["findings"]![0]!["code"] = code; native["findings"]![0]!["check"] = check;
        using var document = System.Text.Json.JsonDocument.Parse(native.ToJsonString());
        Assert.Throws<InvalidDataException>(() => ApfsAccess.Core.CurrentPayloadInventory.Parse(
            document.RootElement.GetProperty("payloadInventory"), 2, 2, true, document.RootElement.GetProperty("findings"), retainedAccounting: true));
    }

    [Theory]
    [InlineData("anchor")] [InlineData("internal-exceeds-main")]
    [InlineData("peer-order")] [InlineData("peer-cumulative")]
    public void NativePartitionOrderingAndAnchorAreRequired(string change)
    {
        var r = RetainedOwnershipNativeReports.Read(); var a = r["retainedOwnership"]!;
        switch (change)
        {
            case "anchor":
                a["metadataRanges"]!.AsArray().RemoveAt(0);
                a["metadataRanges"]!.AsArray().Add(new JsonObject { ["physicalBlock"] = "222", ["blockCount"] = "1" });
                break;
            case "internal-exceeds-main": a["allocatedInternalBlocks"] = "139"; a["deferredInternalBlocks"] = "133"; break;
            case "peer-order": a["snapshotPayloadUsage"]!.AsArray().Add(new JsonObject {
                ["volumeOid"] = "100", ["referencedBlocks"] = "0", ["exclusiveBlocks"] = "0", ["referencedBytes"] = "0", ["exclusiveBytes"] = "0" }); break;
            default:
                a["snapshotPayloadUsage"]![0]!["referencedBlocks"] = "2";
                a["snapshotPayloadUsage"]![0]!["referencedBytes"] = "8192";
                a["snapshotPayloadUsage"]!.AsArray().Add(new JsonObject {
                    ["volumeOid"] = "102", ["referencedBlocks"] = "2", ["exclusiveBlocks"] = "0", ["referencedBytes"] = "8192", ["exclusiveBytes"] = "0" });
                break;
        }
        Assert.Throws<InvalidDataException>(() => Parse(r));
    }
}
