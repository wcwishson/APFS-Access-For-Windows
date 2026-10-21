using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class LiveVolumeVerificationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MetadataControlKeepsExactScopeAndDoesNotChangeOrdinaryPayloadQuery(bool metadataOnly)
    {
        using var directory = DTempDirectory.Create("metadata-control");
        var path = Path.Combine(directory.Path, "control"); var scope = LiveVerificationFixture.Scope();
        var action = metadataOnly ? ContainerControlAction.VolumeVerifyMetadata : ContainerControlAction.VolumeVerify;
        var pending = ContainerControlChannel.SendAsync(path, new string('a', 64), action, 101,
            TimeSpan.FromSeconds(3), default, scope.RequestLines);
        var json = metadataOnly ? LiveVerificationFixture.Report(scope) : PayloadEvidence();
        await Respond(path, pending, json.ToJsonString(), actionName: metadataOnly ? "volume-verify-metadata" : "volume-verify");
        var response = await pending;
        Assert.True(response.Success, response.Code);
        var report = Assert.IsType<LiveVolumeVerificationReport>(response.VerificationReport);
        Assert.Equal(scope, report.Scope); Assert.True(report.Complete);
        Assert.Equal(metadataOnly ? 20 : 21, report.Json.GetProperty("coverage").GetArrayLength());
        Assert.Equal(metadataOnly ? 1 : 2, report.Json.GetProperty("version").GetInt32());
        if (metadataOnly) Assert.Null(report.PayloadInventory);
        else
        {
            Assert.True(report.Json.GetProperty("observePayloadContent").GetBoolean());
            Assert.Equal("268435456", report.Json.GetProperty("limits").GetProperty("maxPayloadLogicalBytes").GetString());
            Assert.Equal("1024", report.Json.GetProperty("limits").GetProperty("maxPayloadEntries").GetString());
            Assert.NotNull(report.PayloadInventory);
        }
        Assert.False(report.Json.GetProperty("wholeVolumeVerified").GetBoolean());
        Assert.False(report.Json.GetProperty("payloadContentHashesVerified").GetBoolean());
        Assert.False(File.Exists(path)); Assert.False(File.Exists(path + ".response"));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("zero-container")]
    [InlineData("zero-volume")]
    [InlineData("leading-xid")]
    [InlineData("overflow-window")]
    [InlineData("source-newline")]
    [InlineData("source-empty")]
    public async Task MetadataControlRejectsUnboundScopeAndActionExtrasBeforePublication(string variant)
    {
        using var directory = DTempDirectory.Create("metadata-control-invalid");
        var path = Path.Combine(directory.Path, "control");
        var lines = LiveVerificationFixture.Scope().RequestLines.ToList();
        switch (variant)
        {
            case "missing": lines.RemoveAt(5); break;
            case "extra": lines.Add("payload=false"); break;
            case "zero-container": lines[0] = new string('0', 32); break;
            case "zero-volume": lines[1] = new string('0', 32); break;
            case "leading-xid": lines[2] = "020"; break;
            case "overflow-window": lines[3] = ulong.MaxValue.ToString(); lines[4] = "1"; break;
            case "source-newline": lines[5] = "held\nreplacement"; break;
            case "source-empty": lines[5] = ""; break;
        }
        await Assert.ThrowsAsync<ArgumentException>(() => ContainerControlChannel.SendAsync(path,
            new string('a', 64), ContainerControlAction.VolumeVerifyMetadata, 101, TimeSpan.FromSeconds(3), default, lines));
        Assert.Empty(Directory.GetFiles(directory.Path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MetadataControlUsesExistingOneMiBResponseBound(bool oversized)
    {
        using var directory = DTempDirectory.Create("metadata-control-bound");
        var path = Path.Combine(directory.Path, "control");
        var pending = ContainerControlChannel.SendAsync(path, new string('a', 64), ContainerControlAction.VolumeVerifyMetadata,
            101, TimeSpan.FromSeconds(3), default, LiveVerificationFixture.Scope().RequestLines);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!File.Exists(path) && !pending.IsCompleted) await Task.Delay(5, deadline.Token);
        var lines = await File.ReadAllLinesAsync(path, deadline.Token);
        Assert.Equal("volume-verify-metadata", lines[3]);
        var response = $"APFS-CONTROL/1\n{lines[1]}\nok\nVolumeVerificationReport\nvolume-verification-json/1\n" +
            LiveVerificationFixture.Report().ToJsonString();
        Assert.Equal(1024 * 1024, LiveVolumeVerificationReport.MaximumResponseBytes);
        var size = LiveVolumeVerificationReport.MaximumResponseBytes + (oversized ? 1 : 0);
        response += new string(' ', size - Encoding.UTF8.GetByteCount(response) - 1) + "\n";
        Assert.Equal(size, Encoding.UTF8.GetByteCount(response));
        await File.WriteAllTextAsync(path + ".tmp", response, new UTF8Encoding(false), deadline.Token);
        File.Move(path + ".tmp", path + ".response");
        var result = await pending;
        Assert.Equal(!oversized, result.Success);
        Assert.Equal(oversized ? "ControlResponseInvalid" : "VolumeVerificationReport", result.Code);
        if (oversized) Assert.Null(result.VerificationReport);
        else Assert.True(result.VerificationReport!.Complete);
        Assert.False(File.Exists(path)); Assert.False(File.Exists(path + ".response"));
    }

    [Theory]
    [InlineData("bare-success")]
    [InlineData("wrong-marker")]
    [InlineData("wrong-oid")]
    [InlineData("payload-bound-refusal")]
    public async Task MetadataControlNeverTurnsUnprovenOrRefusedResponseIntoVerification(string variant)
    {
        using var directory = DTempDirectory.Create("metadata-control-proof");
        var path = Path.Combine(directory.Path, "control");
        var pending = ContainerControlChannel.SendAsync(path, new string('a', 64), ContainerControlAction.VolumeVerifyMetadata,
            101, TimeSpan.FromSeconds(3), default, LiveVerificationFixture.Scope().RequestLines);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!File.Exists(path) && !pending.IsCompleted) await Task.Delay(5, deadline.Token);
        var request = await File.ReadAllLinesAsync(path, deadline.Token);
        var json = LiveVerificationFixture.Report(variant == "wrong-oid" ? LiveVerificationFixture.Scope(oid: "102") : null).ToJsonString();
        var body = variant switch
        {
            "bare-success" => "ok\nVolumeVerificationReport\n",
            "payload-bound-refusal" => "error\nVolumeVerificationReportBound\n",
            _ => $"ok\nVolumeVerificationReport\n{(variant == "wrong-marker" ? "snapshot-inventory-json/1" : "volume-verification-json/1")}\n{json}\n",
        };
        await File.WriteAllTextAsync(path + ".tmp", $"APFS-CONTROL/1\n{request[1]}\n" + body, new UTF8Encoding(false), deadline.Token);
        File.Move(path + ".tmp", path + ".response");
        var result = await pending;
        Assert.False(result.Success); Assert.Null(result.VerificationReport);
        Assert.Equal(variant == "payload-bound-refusal" ? "VolumeVerificationReportBound" : "ControlResponseInvalid", result.Code);
    }

    private static JsonObject PayloadEvidence() => PayloadObservationFixture.Upgrade(LiveVerificationFixture.Report(), live: true);
    private static LiveVolumeVerificationReport ParsePayload(JsonObject node)
        => LiveVolumeVerificationReport.Parse(JsonSerializer.SerializeToElement(node));

    [Fact]
    public void PayloadObservationParsesExactCurrentRowsWithoutExpectedAuthority()
    {
        var report = ParsePayload(PayloadEvidence());
        Assert.True(report.Complete); Assert.Equal(21, report.Json.GetProperty("coverage").GetArrayLength());
        AssertCoverageAndObservation(report);
        Assert.Equal("NotSupplied", report.Json.GetProperty("payloadInventory").GetProperty("expectedComparison").GetString());
        Assert.False(report.Json.GetProperty("payloadContentHashesVerified").GetBoolean());
        Assert.NotNull(report.PayloadInventory);
        Assert.Equal("9007199254740993", report.PayloadInventory.Entries[0].InodeOid);
        Assert.All(report.PayloadInventory.Entries, entry => Assert.Null(entry.ExpectedSha256));
    }

    [Theory]
    [InlineData("ReadFailure")] [InlineData("BudgetExceeded")] [InlineData("Unsupported")]
    public void PayloadObservationPreservesPartialAndRefusalWithoutCompleteHash(string status)
    {
        var node = PayloadEvidence(); PayloadObservationFixture.Fail(node, status);
        var report = ParsePayload(node);
        Assert.False(report.Complete); Assert.Equal(status == "Unsupported" ? "Refused" : "Incomplete", report.Outcome);
    }

    [Theory]
    [MemberData(nameof(PayloadObservationFixture.PartialInvalidCases), MemberType = typeof(PayloadObservationFixture))]
    public void PayloadObservationRejectsContradictoryPartialReports(string mutation)
    {
        var node = PayloadEvidence(); PayloadObservationFixture.Fail(node, "ReadFailure");
        PayloadObservationFixture.MutatePartial(node, mutation);
        Assert.Throws<InvalidDataException>(() => ParsePayload(node));
    }

    [Fact]
    public void PayloadObservationEarlyRefusalCanPublishEmptyTypedInventory()
    {
        var node = PayloadObservationFixture.Upgrade(LiveVerificationFixture.Report(damaged: true), live: true);
        node["selected"] = null; node["outcome"] = 3; node["outcomeName"] = "Refused";
        node["coverage"]![4]!["state"] = 1; node["coverage"]![0]!["state"] = 4;
        node["findings"]![0]!["check"] = 1; node["findings"]![0]!["code"] = 2; node["findings"]![0]!["severity"] = 2;
        PayloadObservationFixture.Bind(node);
        var report = ParsePayload(node);
        Assert.Equal("Refused", report.Outcome); Assert.NotNull(report.PayloadInventory);
        Assert.Empty(report.PayloadInventory.Entries); Assert.False(report.PayloadInventory.HashesObserved);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void PayloadObservationAcceptsExactBoundsAndEmptyAdmittedCensus(bool empty)
    {
        var node = PayloadEvidence(); PayloadObservationFixture.AtBounds(node, empty);
        Assert.True(ParsePayload(node).Complete);
    }

    [Fact]
    public void PayloadObservationUsesNativeUtf8NameOrder()
    {
        var node = PayloadEvidence(); PayloadObservationFixture.UnicodeNames(node);
        Assert.Equal("\U00010000", ParsePayload(node).PayloadInventory!.Entries[2].NameUtf8);
    }

    [Fact]
    public async Task PayloadObservationAuthenticatedTransportRetainsVersionOneMarker()
    {
        using var directory = DTempDirectory.Create("payload-transport"); var path = Path.Combine(directory.Path, "control");
        var scope = LiveVerificationFixture.Scope();
        var pending = ContainerControlChannel.SendAsync(path, new string('a', 64), ContainerControlAction.VolumeVerify,
            101, TimeSpan.FromSeconds(3), default, scope.RequestLines);
        await Respond(path, pending, PayloadEvidence().ToJsonString());
        var result = await pending;
        Assert.True(result.Success, result.Code); Assert.Equal("VolumeVerificationReport", result.Code);
        Assert.NotNull(result.VerificationReport!.PayloadInventory);
        Assert.Equal(3, result.VerificationReport.PayloadInventory.Entries.Count);
    }

    [Theory]
    [MemberData(nameof(PayloadObservationFixture.InvalidCases), MemberType = typeof(PayloadObservationFixture))]
    public void PayloadObservationRejectsForgedInventory(string mutation)
    {
        var node = PayloadEvidence(); PayloadObservationFixture.Mutate(node, mutation);
        Assert.Throws<InvalidDataException>(() => ParsePayload(node));
    }

    [Fact]
    public void PayloadObservationRejectsDuplicatePropertiesAndOversizedUtf8()
    {
        foreach (var bad in PayloadObservationFixture.DuplicateProperties(PayloadEvidence().ToJsonString()))
        {
            using var document = JsonDocument.Parse(bad);
            Assert.Throws<InvalidDataException>(() => LiveVolumeVerificationReport.Parse(document.RootElement));
        }
        var node = PayloadEvidence(); node["coverage"]![0]!["scopeDetail"] = new string('x', LiveVolumeVerificationReport.MaximumResponseBytes);
        Assert.Throws<InvalidDataException>(() => ParsePayload(node));
    }

    [Fact]
    public void PayloadObservationLegacyParsesKeepOriginalCoverageAndPlanBytes()
    {
        var node = LiveVerificationFixture.Report(); var report = ParsePayload(node);
        Assert.Equal(20, report.Json.GetProperty("coverage").GetArrayLength());
        AssertCoverageAndObservation(report);
        Assert.StartsWith("apfs-verifier-refusal-v1|", report.Json.GetProperty("repair").GetProperty("planId").GetString());
        Assert.Null(report.PayloadInventory);
        node["payloadInventory"] = PayloadObservationFixture.Inventory();
        Assert.Throws<InvalidDataException>(() => ParsePayload(node));
    }

    [NativeVerificationDocumentTheory]
    [InlineData("healthy-0.json", true, "0")]
    [InlineData("healthy-8192.json", true, "8192")]
    [InlineData("checksum.response", false, "0")]
    [InlineData("namespace.response", false, "0")]
    public void NativeGeneratedRetainedOwnerDocumentsKeepExactScopeAndVerdict(string file, bool complete, string offset)
    {
        var text = File.ReadAllText(Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_NATIVE_VERIFICATION_DOCUMENTS")!, file));
        if (file.EndsWith(".response", StringComparison.Ordinal))
        {
            var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.TrimEnd('\r')).ToArray();
            Assert.Equal(6, lines.Length); Assert.Equal("volume-verification-json/1", lines[4]); text = lines[5];
        }
        using var document = JsonDocument.Parse(text);
        var report = LiveVolumeVerificationReport.Parse(document.RootElement);
        Assert.Equal(complete, report.Complete); Assert.Equal(offset, report.Scope.StoreOffsetBytes);
        Assert.Equal(document.RootElement.GetProperty("requestedScope").GetProperty("sourceIdentity").GetString(), report.Scope.SourceIdentity);
        Assert.Equal("101", report.Scope.VolumeOid); Assert.Equal("20", report.Scope.CheckpointXid);
        Assert.False(report.Json.GetProperty("wholeVolumeVerified").GetBoolean());
        Assert.False(report.Json.GetProperty("payloadContentHashesVerified").GetBoolean());
        AssertCoverageAndObservation(report);
        if (!complete) Assert.NotEmpty(report.Json.GetProperty("findings").EnumerateArray());
    }

    private static void AssertCoverageAndObservation(LiveVolumeVerificationReport report)
    {
        var current = report.Json.GetProperty("version").GetInt32() == 2;
        var coverage = report.Json.GetProperty("coverage").EnumerateArray().ToArray();
        Assert.Equal(Enumerable.Range(1, current ? 21 : 20),
            coverage.Select(row => row.GetProperty("check").GetInt32()).Order());
        foreach (var row in coverage)
        {
            var check = row.GetProperty("check").GetInt32();
            var implemented = check <= 11 || check >= 17;
            Assert.Equal(implemented, row.GetProperty("implemented").GetBoolean());
            Assert.Equal(implemented, row.GetProperty("required").GetBoolean());
            // Allocation/history/expected hashes remain unproven; Crypto/Fusion remain unsupported.
            if (!implemented || report.Complete)
                Assert.Equal(check is 15 or 16 ? 4 : implemented ? 2 : 1, row.GetProperty("state").GetInt32());
        }
        Assert.False(report.Json.GetProperty("wholeVolumeVerified").GetBoolean());
        Assert.False(report.Json.GetProperty("payloadContentHashesVerified").GetBoolean());
        if (!current)
        {
            Assert.Null(report.PayloadInventory);
            return;
        }
        Assert.True(report.Json.GetProperty("observePayloadContent").GetBoolean());
        var inventory = Assert.IsType<CurrentPayloadInventory>(report.PayloadInventory);
        var observation = Assert.Single(coverage, row => row.GetProperty("check").GetInt32() == 21);
        Assert.Equal(report.Complete ? 2 : 1, observation.GetProperty("state").GetInt32());
        Assert.Equal("selected-current-volume", inventory.ScopeKind);
        Assert.Equal("SHA256", inventory.Algorithm);
        Assert.Equal("NotSupplied", inventory.ExpectedComparison);
        Assert.Equal(report.Complete, inventory.EnumerationComplete);
        Assert.Equal(report.Complete, inventory.ReadComplete);
        Assert.Equal(report.Complete, inventory.HashesObserved);
        Assert.All(inventory.Entries, entry => Assert.Null(entry.ExpectedSha256));
        if (report.Complete) Assert.NotEmpty(inventory.Entries);
        else Assert.Empty(inventory.Entries);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthenticatedQueryCarriesExactOwnerScopeAndTypedVerdict(bool damaged)
    {
        using var directory = DTempDirectory.Create("live-verify");
        var path = Path.Combine(directory.Path, "control"); var scope = LiveVerificationFixture.Scope();
        var pending = ContainerControlChannel.SendAsync(path, new string('a', 64), ContainerControlAction.VolumeVerify,
            101, TimeSpan.FromSeconds(3), default, scope.RequestLines);
        await Respond(path, pending, LiveVerificationFixture.Report(scope, damaged).ToJsonString());
        var result = await pending;
        Assert.True(result.Success, result.Code); Assert.Equal("VolumeVerificationReport", result.Code);
        Assert.Equal(scope, result.VerificationReport!.Scope); Assert.Equal(!damaged, result.VerificationReport.Complete);
        Assert.Null(result.Inventory); Assert.False(File.Exists(path));
    }

    [Theory]
    [InlineData("decimal")]
    [InlineData("leading-zero")]
    [InlineData("overflow")]
    [InlineData("source")]
    [InlineData("selected")]
    [InlineData("plan")]
    [InlineData("whole")]
    [InlineData("coverage")]
    [InlineData("limit")]
    [InlineData("late")]
    [InlineData("ranges")]
    [InlineData("unknown")]
    [InlineData("duplicate")]
    public void ReportRejectsContradictoryLossyUnboundOrLateEvidence(string mutation)
    {
        var report = LiveVerificationFixture.Report();
        switch (mutation)
        {
            case "decimal": report["sourceReads"] = 94; break;
            case "leading-zero": report["requestedScope"]!["checkpointXid"] = "020"; break;
            case "overflow": report["sourceReadBytes"] = "18446744073709551616"; break;
            case "source": report["requestedScope"]!["sourceIdentity"] = "unsafe source"; break;
            case "selected": report["selected"]!["scope"]!["volumeOid"] = "102"; break;
            case "plan": report["repair"]!["planId"] = "tampered"; break;
            case "whole": report["wholeVolumeVerified"] = true; break;
            case "coverage": report["coverage"]![0]!["state"] = 1; break;
            case "limit": report["limits"]!["maxReads"] = "65537"; break;
            case "late": report["elapsedMs"] = "5001"; break;
            case "ranges": report["allocationCensus"]!["unattributedMainRanges"] = new JsonArray(
                new JsonObject { ["physicalBlock"] = "511", ["blockCount"] = "2" }); break;
            case "unknown": report["extra"] = true; break;
        }
        var json = report.ToJsonString();
        if (mutation == "duplicate") json = json.Replace("\"version\":1", "\"version\":1,\"version\":1", StringComparison.Ordinal);
        using var document = JsonDocument.Parse(json);
        Assert.Throws<InvalidDataException>(() => LiveVolumeVerificationReport.Parse(document.RootElement));
    }

    [Fact]
    public async Task LegacyRefusalHasNoReportAndWrongTypedMarkerCannotBecomeProof()
    {
        using var directory = DTempDirectory.Create("live-verify-refusal"); var path = Path.Combine(directory.Path, "control");
        var scope = LiveVerificationFixture.Scope();
        foreach (var json in new[] { null, LiveVerificationFixture.Report().ToJsonString() })
        {
            var pending = ContainerControlChannel.SendAsync(path, new string('a', 64), ContainerControlAction.VolumeVerify,
                101, TimeSpan.FromSeconds(3), default, scope.RequestLines);
            await Respond(path, pending, json, "snapshot-inventory-json/1");
            var result = await pending; Assert.False(result.Success); Assert.Null(result.VerificationReport);
            Assert.Equal(json is null ? "VolumeVerificationBusy" : "ControlResponseInvalid", result.Code);
        }
        await Assert.ThrowsAsync<ArgumentException>(() => ContainerControlChannel.SendAsync(path, new string('a', 64),
            ContainerControlAction.VolumeVerify, 101, TimeSpan.FromSeconds(3), default, [..scope.RequestLines, "repair"]));
    }

    [Fact]
    public void CapabilityRequiresActualBoundScopeAndIsIndependentOfMountReady()
    {
        var scope = LiveVerificationFixture.Scope();
        var row = new JsonObject { ["objectId"] = "101", ["canonicalId"] = "apfs-vol:" + scope.ContainerUuid + ":101",
            ["mounted"] = false, ["ready"] = false, ["writable"] = false, ["recoveryActive"] = false, ["writeDegraded"] = false,
            ["recoveryReason"] = "", ["volumeVerificationSupported"] = true,
            ["volumeVerificationScope"] = JsonSerializer.SerializeToNode(scope, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }) };
        var status = new JsonObject { ["containerUuid"] = scope.ContainerUuid, ["ownerPid"] = 123, ["ownerStartFileTimeUtc"] = 42,
            ["leaseHeld"] = true, ["checkpointXid"] = "20", ["recoveryRequired"] = false, ["recoveryVolumeObjectId"] = null,
            ["recoveryReason"] = "", ["volumes"] = new JsonArray(row) };
        Assert.True(Assert.Single(ContainerStatusReader.Parse(status.ToJsonString()).Volumes).VolumeVerificationSupported);
        row["volumeVerificationScope"]!["volumeOid"] = "102";
        Assert.Throws<ContainerManifestException>(() => ContainerStatusReader.Parse(status.ToJsonString()));
        row["volumeVerificationScope"] = null; row["volumeVerificationSupported"] = false;
        Assert.False(Assert.Single(ContainerStatusReader.Parse(status.ToJsonString()).Volumes).VolumeVerificationSupported);
    }

    private static async Task Respond(string path, Task<ContainerControlResult> pending, string? json,
        string marker = "volume-verification-json/1", string actionName = "volume-verify")
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!File.Exists(path) && !pending.IsCompleted) await Task.Delay(5, deadline.Token);
        var lines = await File.ReadAllLinesAsync(path, deadline.Token);
        Assert.Equal(11, lines.Length); Assert.Equal(actionName, lines[3]); Assert.Equal("101", lines[4]);
        Assert.Equal(LiveVerificationFixture.Scope().RequestLines, lines.Skip(5).ToArray());
        var response = $"APFS-CONTROL/1\n{lines[1]}\n" +
            (json is null ? "error\nVolumeVerificationBusy\n" : $"ok\nVolumeVerificationReport\n{marker}\n{json}\n");
        await File.WriteAllTextAsync(path + ".tmp", response, new UTF8Encoding(false), deadline.Token);
        File.Move(path + ".tmp", path + ".response");
    }
}

public static class PayloadObservationFixture
{
    private const string EmptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public static JsonObject Inventory() => new()
    {
        ["scopeKind"] = "selected-current-volume", ["algorithm"] = "SHA256",
        ["enumerationComplete"] = true, ["readComplete"] = true, ["hashesObserved"] = true,
        ["expectedComparison"] = "NotSupplied", ["maxLogicalBytes"] = "268435456", ["maxEntries"] = "1024",
        ["entryCount"] = "3", ["logicalBytesRead"] = "8",
        ["entries"] = new JsonArray(
            Row("file-data", "9007199254740993", "18446744073709551615", null, "8",
                Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(new byte[] { 66, 66, 66, 66, 66, 66, 66, 66 })).ToLowerInvariant()),
            Row("xattr", "9007199254740993", "0", "com.apple.empty", "0", EmptyDigest),
            Row("xattr", "9007199254740993", "18446744073709551615", "com.apple.external", "0", EmptyDigest))
    };
    private static JsonObject Row(string kind, string inode, string stream, string? name, string size, string digest)
        => new() { ["kind"] = kind, ["inodeOid"] = inode, ["streamOid"] = stream, ["nameUtf8"] = name,
            ["logicalSizeBytes"] = size, ["logicalBytesRead"] = size, ["readOutcome"] = "Complete",
            ["observedSha256"] = digest, ["expectedSha256"] = null };
    public static JsonObject Upgrade(JsonObject node, bool live)
    {
        node["version"] = live ? 2 : 3; node["observePayloadContent"] = true;
        var limits = node[live ? "limits" : "requestedScope"]!;
        limits["maxPayloadLogicalBytes"] = "268435456"; limits["maxPayloadEntries"] = "1024";
        var complete = node["outcome"]!.GetValue<int>() == 1;
        node["payloadInventory"] = Inventory();
        node["coverage"]!.AsArray().Add(new JsonObject { ["check"] = 21, ["implemented"] = true,
            ["required"] = true, ["state"] = complete ? 2 : 1, ["scopeDetail"] = "Current payload observation" });
        if (!complete)
        {
            var p = node["payloadInventory"]!; p["enumerationComplete"] = false; p["readComplete"] = false; p["hashesObserved"] = false;
            p["entryCount"] = "0"; p["logicalBytesRead"] = "0"; p["entries"] = new JsonArray();
        }
        Bind(node); return node;
    }
    public static void Fail(JsonObject node, string status)
    {
        var refused = status == "Unsupported";
        node["outcome"] = refused ? 3 : 2; node["outcomeName"] = refused ? "Refused" : "Incomplete";
        node["coveredFilesystemRecords"] = "0"; node["coveredPhysicalExtents"] = "0"; node["allocationCensus"] = null;
        node["repair"]!["refusal"] = 2; node["coverage"]![20]!["state"] = refused ? 4 : 1;
        var p = node["payloadInventory"]!; p["readComplete"] = false; p["hashesObserved"] = false;
        var row = p["entries"]![0]!; row["readOutcome"] = status; row["observedSha256"] = null;
        row["logicalBytesRead"] = status == "ReadFailure" ? "4" : "0"; p["logicalBytesRead"] = row["logicalBytesRead"]!.DeepClone();
        node["findings"] = new JsonArray(new JsonObject { ["code"] = refused ? 8 : status == "ReadFailure" ? 3 : 4,
            ["severity"] = refused ? 2 : 3, ["check"] = 21, ["volumeOid"] = "101", ["objectId"] = "9007199254740993",
            ["physicalBlock"] = null, ["checkpointXid"] = "20", ["failedSourceOffsetBytes"] = status == "ReadFailure" ? "8196" : null,
            ["detail"] = "payload observation stopped" });
        Bind(node);
    }

    public static void AtBounds(JsonObject node, bool empty)
    {
        var p = node["payloadInventory"]!; var rows = p["entries"]!.AsArray(); rows.Clear();
        if (!empty)
        {
            rows.Add(Row("file-data", "1", "18446744073709551615", null, "268435456", new string('a', 64)));
            for (var i = 1; i < 1024; ++i) rows.Add(Row("xattr", i.ToString(System.Globalization.CultureInfo.InvariantCulture), "0", "empty", "0", EmptyDigest));
        }
        p["entryCount"] = empty ? "0" : "1024"; p["logicalBytesRead"] = empty ? "0" : "268435456";
        Bind(node);
    }

    public static void UnicodeNames(JsonObject node)
    {
        var rows = node["payloadInventory"]!["entries"]!;
        rows[1]!["nameUtf8"] = "\uE000"; rows[2]!["nameUtf8"] = "\U00010000"; rows[2]!["streamOid"] = "0";
        Bind(node);
    }

    public static IEnumerable<object[]> PartialInvalidCases => new[] {
        "digest", "bytesPastEof", "sum", "readComplete", "hashesObserved", "enumerationComplete",
        "verifiedCheck", "missingFailureFinding", "count", "sizeBound", "census", "proofCounters", "emptyForged",
        "unsupportedBytes", "notReadBytes", "admissionRefusal"
    }.Select(x => new object[] { x });
    public static void MutatePartial(JsonObject node, string mutation)
    {
        var p = node["payloadInventory"]!; var row = p["entries"]![0]!;
        switch (mutation)
        {
            case "digest": row["observedSha256"] = new string('a', 64); break;
            case "bytesPastEof": row["logicalBytesRead"] = "9"; p["logicalBytesRead"] = "9"; break;
            case "sum": p["logicalBytesRead"] = "5"; break;
            case "readComplete": p["readComplete"] = true; break;
            case "hashesObserved": p["hashesObserved"] = true; break;
            case "enumerationComplete": p["enumerationComplete"] = false; break;
            case "verifiedCheck": node["coverage"]![20]!["state"] = 2; break;
            case "missingFailureFinding": node["findings"]![0]!["code"] = 4; break;
            case "count": p["entryCount"] = "2"; break;
            case "sizeBound": row["logicalSizeBytes"] = "18446744073709551615"; break;
            case "census": node["allocationCensus"] = new JsonObject(); break;
            case "proofCounters": node["coveredFilesystemRecords"] = "1"; break;
            case "emptyForged": p["entries"] = new JsonArray(); p["entryCount"] = "0"; p["logicalBytesRead"] = "0"; break;
            case "unsupportedBytes": row["readOutcome"] = "Unsupported"; break;
            case "notReadBytes": row["readOutcome"] = "NotRead"; break;
            case "admissionRefusal": node["findings"]![0]!["code"] = 6; node["findings"]![0]!["check"] = 5;
                node["coverage"]![4]!["state"] = 3; row["readOutcome"] = "NotRead";
                row["logicalBytesRead"] = "0"; p["logicalBytesRead"] = "0"; break;
            default: throw new ArgumentException(mutation);
        }
        Bind(node);
    }

    public static IEnumerable<object[]> InvalidCases => new[] {
        "missing", "null", "extra", "scope", "algorithm", "expected", "expectedDigest", "digestMissing", "digestUpper",
        "digestShort", "digestInvalid", "emptyDigest", "numeric", "leadingZero", "overflow", "zeroInode", "zeroFileStream",
        "unknownKind", "fileName", "xattrNameMissing", "xattrNameEmpty", "xattrNul", "xattrNameLarge", "duplicateKey",
        "duplicateFile", "duplicateXattr", "unsorted", "unknownStatus", "shortComplete", "readPastEof", "partialDigest",
        "notReadBytes", "unknownProperty", "missingRowProperty", "wrongCount", "wrongBytes", "maxEntries", "maxLogical",
        "sizeBound", "sumBound", "entryBound", "readFalse", "enumerationFalse", "hashesFalse", "whole", "verified",
        "scopeMismatch", "checkMissing", "checkDuplicate", "checkUnknown", "checkUnproven", "checkOptional",
        "checkUnimplemented", "observeFalse", "observeMissing", "limitEntries", "limitBytes", "oldPlan", "extraFindingCode"
    }.Select(x => new object[] { x });

    public static void Mutate(JsonObject node, string mutation)
    {
        var p = node["payloadInventory"]!; var rows = p["entries"]!.AsArray(); var row = rows[0]!;
        switch (mutation)
        {
            case "missing": node.Remove("payloadInventory"); break;
            case "null": node["payloadInventory"] = null; break;
            case "extra": p["reclaimable"] = true; break;
            case "scope": p["scopeKind"] = "all-volumes"; break;
            case "algorithm": p["algorithm"] = "SHA1"; break;
            case "expected": p["expectedComparison"] = "Match"; break;
            case "expectedDigest": row["expectedSha256"] = row["observedSha256"]!.DeepClone(); break;
            case "digestMissing": row["observedSha256"] = null; break;
            case "digestUpper": row["observedSha256"] = row["observedSha256"]!.GetValue<string>().ToUpperInvariant(); break;
            case "digestShort": row["observedSha256"] = "aa"; break;
            case "digestInvalid": row["observedSha256"] = new string('z', 64); break;
            case "emptyDigest": rows[1]!["observedSha256"] = row["observedSha256"]!.DeepClone(); break;
            case "numeric": row["inodeOid"] = 9007199254740993L; break;
            case "leadingZero": row["inodeOid"] = "09007199254740993"; break;
            case "overflow": row["streamOid"] = "18446744073709551616"; break;
            case "zeroInode": row["inodeOid"] = "0"; break;
            case "zeroFileStream": row["streamOid"] = "0"; break;
            case "unknownKind": row["kind"] = "directory"; break;
            case "fileName": row["nameUtf8"] = "file.txt"; break;
            case "xattrNameMissing": rows[1]!["nameUtf8"] = null; break;
            case "xattrNameEmpty": rows[1]!["nameUtf8"] = ""; break;
            case "xattrNul": rows[1]!["nameUtf8"] = "a\0b"; break;
            case "xattrNameLarge": rows[1]!["nameUtf8"] = new string('x', 4097); break;
            case "duplicateKey": rows.Add(rows[1]!.DeepClone()); p["entryCount"] = "4"; break;
            case "duplicateFile": var alias = row.DeepClone(); alias["streamOid"] = "18446744073709551614";
                rows.Insert(0, alias); p["entryCount"] = "4"; p["logicalBytesRead"] = "16"; break;
            case "duplicateXattr": rows[2]!["nameUtf8"] = rows[1]!["nameUtf8"]!.DeepClone(); break;
            case "unsorted": var first = rows[0]!.DeepClone(); rows.RemoveAt(0); rows.Add(first); break;
            case "unknownStatus": row["readOutcome"] = "Success"; break;
            case "shortComplete": row["logicalBytesRead"] = "7"; p["logicalBytesRead"] = "7"; break;
            case "readPastEof": row["logicalBytesRead"] = "9"; p["logicalBytesRead"] = "9"; break;
            case "partialDigest": row["readOutcome"] = "ReadFailure"; break;
            case "notReadBytes": row["readOutcome"] = "NotRead"; row["observedSha256"] = null; break;
            case "unknownProperty": row["bytes"] = "hidden"; break;
            case "missingRowProperty": row.AsObject().Remove("expectedSha256"); break;
            case "wrongCount": p["entryCount"] = "2"; break;
            case "wrongBytes": p["logicalBytesRead"] = "9"; break;
            case "maxEntries": p["maxEntries"] = "1025"; break;
            case "maxLogical": p["maxLogicalBytes"] = "268435457"; break;
            case "sizeBound": row["logicalSizeBytes"] = "268435457"; break;
            case "sumBound": row["logicalSizeBytes"] = "268435456"; rows[1]!["logicalSizeBytes"] = "1"; break;
            case "entryBound": for (var i = 0; i < 1022; ++i) rows.Add(Row("xattr", "18446744073709551615", "0", "name" + i, "0", EmptyDigest));
                p["entryCount"] = "1025"; break;
            case "readFalse": p["readComplete"] = false; break;
            case "enumerationFalse": p["enumerationComplete"] = false; break;
            case "hashesFalse": p["hashesObserved"] = false; break;
            case "whole": node["wholeVolumeVerified"] = true; break;
            case "verified": node["payloadContentHashesVerified"] = true; break;
            case "scopeMismatch": var selected = node["selected"]!; (selected["scope"] ?? selected)["volumeOid"] = "102"; break;
            case "checkMissing": node["coverage"]!.AsArray().RemoveAt(20); break;
            case "checkDuplicate": node["coverage"]![20]!["check"] = 20; break;
            case "checkUnknown": node["coverage"]![20]!["check"] = 22; break;
            case "checkUnproven": node["coverage"]![20]!["state"] = 1; break;
            case "checkOptional": node["coverage"]![20]!["required"] = false; break;
            case "checkUnimplemented": node["coverage"]![20]!["implemented"] = false; break;
            case "observeFalse": node["observePayloadContent"] = false; break;
            case "observeMissing": node.Remove("observePayloadContent"); break;
            case "limitEntries": node[node.ContainsKey("limits") ? "limits" : "requestedScope"]!["maxPayloadEntries"] = "1025"; break;
            case "limitBytes": node[node.ContainsKey("limits") ? "limits" : "requestedScope"]!["maxPayloadLogicalBytes"] = "268435457"; break;
            case "oldPlan": node["repair"]!["planId"] = node["repair"]!["planId"]!.GetValue<string>().Replace("refusal-v2|", "refusal-v1|"); return;
            case "extraFindingCode": Fail(node, "ReadFailure"); node["findings"]![0]!["code"] = 26; break;
            default: throw new ArgumentException(mutation);
        }
        if (mutation is not ("observeMissing" or "limitEntries" or "limitBytes")) Bind(node);
    }
    public static IEnumerable<string> DuplicateProperties(string json)
    {
        yield return json.Replace("\"observePayloadContent\":true", "\"observePayloadContent\":true,\"observePayloadContent\":true", StringComparison.Ordinal);
        yield return json.Replace("\"entryCount\":\"3\"", "\"entryCount\":\"3\",\"entryCount\":\"3\"", StringComparison.Ordinal);
        yield return json.Replace("\"expectedSha256\":null", "\"expectedSha256\":null,\"expectedSha256\":null", StringComparison.Ordinal);
    }

    // Independent wire fixture encoder, without calling either production BuildPlanId.
    public static void Bind(JsonObject node)
    {
        using var document = JsonDocument.Parse(node.ToJsonString()); var root = document.RootElement;
        var live = node.ContainsKey("limits"); var b = new StringBuilder("apfs-verifier-refusal-v2|");
        void Add(string value) => b.Append(Encoding.UTF8.GetByteCount(value).ToString(System.Globalization.CultureInfo.InvariantCulture)).Append(':').Append(value);
        void Fields(JsonElement obj, string keys)
        {
            foreach (var key in keys.Split(' '))
            {
                var v = obj.GetProperty(key);
                Add(v.ValueKind switch { JsonValueKind.String => v.GetString()!, JsonValueKind.True => "1",
                    JsonValueKind.False => "0", JsonValueKind.Null => "unknown", _ => v.GetRawText() });
            }
        }
        var scope = root.GetProperty("requestedScope"); var limits = live ? root.GetProperty("limits") : scope;
        Fields(live ? scope : root.GetProperty("source"), live ? "sourceIdentity" : "identity");
        const string exact = "storeOffsetBytes storeSizeBytes containerUuid volumeUuid volumeOid checkpointXid";
        Fields(scope, exact); var selected = root.GetProperty("selected"); Add(selected.ValueKind == JsonValueKind.Null ? "0" : "1");
        if (selected.ValueKind != JsonValueKind.Null)
        {
            Fields(live ? selected.GetProperty("scope") : selected, exact);
            Fields(selected, "checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock");
        }
        Fields(limits, "maxReads maxReadBytes maxRecords maxRecordBytes");
        Fields(live ? root : scope, "requireWholeVolume requirePayloadContentHashes");
        Fields(root, "observePayloadContent"); Fields(limits, "maxPayloadLogicalBytes maxPayloadEntries");
        Fields(root, "outcome"); Fields(root.GetProperty("repair"), "refusal");
        var findings = root.GetProperty("findings"); Add(findings.GetArrayLength().ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach (var f in findings.EnumerateArray()) Fields(f, "check code severity volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes detail");
        var coverage = root.GetProperty("coverage"); Add(coverage.GetArrayLength().ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach (var c in coverage.EnumerateArray()) Fields(c, "check implemented required state");
        node["repair"]!["planId"] = b.ToString();
    }
}

public sealed class NativeVerificationDocumentTheoryAttribute : TheoryAttribute
{
    public NativeVerificationDocumentTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("APFSACCESS_NATIVE_VERIFICATION_DOCUMENTS") is null)
            Skip = "Requires explicit saved native retained-owner protocol evidence; never launches a host.";
    }
}
