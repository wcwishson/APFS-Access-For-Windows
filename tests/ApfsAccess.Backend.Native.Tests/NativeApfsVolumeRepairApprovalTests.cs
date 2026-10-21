using System.Globalization;
using System.Text.Json.Nodes;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeApfsVolumeRepairApprovalTests
{
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Volume = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    [Theory]
    [InlineData("RepairNeedsConfirmation", 3)]
    [InlineData("RepairHealthyNoFinding", 0)]
    public void LegacyParserAcceptsActualNativeNumericScope(string code, int exit)
    {
        using var directory = DTempDirectory.Create("repair-legacy-native-wire");
        var request = Request(directory.Path) with { ApprovalMode = "" };
        var report = Report(request, code, exit);
        report["version"] = 1; report.Remove("source");
        var runner = new Runner(new(exit, report.ToJsonString(), ""));
        var result = new NativeApfsVolumeRepair(runner, Tool(directory.Path)).Repair(request);
        Assert.Equal(exit, result.NativeExitCode);
        Assert.DoesNotContain("--approval-mode", runner.Arguments!);
    }

    [Fact]
    public void StrictDryRunForwardsModeAndReturnsExactPublicSourceEvidence()
    {
        using var directory = DTempDirectory.Create("repair-approval-dry");
        var request = Request(directory.Path);
        var json = Report(request, "RepairNeedsConfirmation", 3);
        var runner = new Runner(new(3, json.ToJsonString(), ""));
        var result = new NativeApfsVolumeRepair(runner, Tool(directory.Path)).Repair(request);
        Assert.Equal(ApfsRepairOutcome.NeedsConfirmation, result.Outcome);
        Assert.Equal(NativeApfsVolumeRepair.ReadApprovalIdentity(request.Image), result.Report.GetProperty("source").GetProperty("identity").GetString());
        Assert.Equal(NativeApfsVolumeRepair.HashFile(request.Image, default), result.Report.GetProperty("source").GetProperty("sha256").GetString());
        Assert.Equal(["--approval-mode", "exact-source-v1"], runner.Arguments!.TakeLast(2));
        Assert.DoesNotContain("--confirm", runner.Arguments!);
        Assert.DoesNotContain("--approved-source-sha256", runner.Arguments!);
    }

    [Fact]
    public void ConfirmedStrictApplyForwardsReviewedEvidenceAndAllowsVerifiedPublication()
    {
        using var directory = DTempDirectory.Create("repair-approval-apply");
        var request = Approved(Request(directory.Path));
        var report = Report(request, "RepairedAndVerified", 0);
        var runner = new Runner(new(0, report.ToJsonString(), ""), () =>
        {
            using var stream = new FileStream(request.Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            stream.WriteByte(0xAF);
        });
        var result = new NativeApfsVolumeRepair(runner, Tool(directory.Path)).Repair(request);
        Assert.Equal(ApfsRepairOutcome.RepairedAndVerified, result.Outcome);
        Assert.Equal(["--approval-mode", "exact-source-v1", "--approved-source-identity", request.ApprovedSourceIdentity,
            "--approved-source-sha256", request.ApprovedSourceSha256], runner.Arguments!.TakeLast(6));
        Assert.NotEqual(request.ApprovedSourceSha256, NativeApfsVolumeRepair.HashFile(request.Image, default));
    }

    [Theory]
    [InlineData("unknown", "identity", "hash")]
    [InlineData("", "identity", "hash")]
    [InlineData("exact-source-v1", "", "hash")]
    [InlineData("exact-source-v1", "identity", "")]
    [InlineData("exact-source-v1", "identity", "ABCDEF")]
    [InlineData("exact-source-v1", "identity", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
    [InlineData("exact-source-v1", "identity", "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
    [InlineData("exact-source-v1", "malformed", "hash")]
    public void InvalidApprovalNeverDispatches(string mode, string identity, string hash)
    {
        using var directory = DTempDirectory.Create("repair-approval-invalid");
        var valid = Approved(Request(directory.Path));
        var request = valid with
        {
            ApprovalMode = mode,
            ApprovedSourceIdentity = identity == "identity" ? valid.ApprovedSourceIdentity : identity,
            ApprovedSourceSha256 = hash == "hash" ? valid.ApprovedSourceSha256 : hash,
        };
        var runner = new Runner(new(0, "", ""));
        Assert.Throws<ArgumentException>(() => new NativeApfsVolumeRepair(runner, Tool(directory.Path)).Repair(request));
        Assert.Null(runner.Arguments);
    }

    [Fact]
    public void DryApprovalAndCountOnlyApplyAreRejectedButZeroCountIntentIsValid()
    {
        using var directory = DTempDirectory.Create("repair-approval-shapes");
        var request = Request(directory.Path);
        NativeApfsVolumeRepair.ValidateRequest(request);
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRepair.ValidateRequest(request with { Confirm = true, ExpectedCount = "1" }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRepair.ValidateRequest(Approved(request) with { Confirm = false, ExpectedCount = "" }));
        NativeApfsVolumeRepair.ValidateRequest(Approved(request) with { ExpectedCount = "0" });
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRepair.ValidateRequest(request with { StoreOffsetBytes = "4096" }));
    }

    [Theory]
    [InlineData("version")]
    [InlineData("null-source")]
    [InlineData("uppercase-hash")]
    [InlineData("extra-source")]
    [InlineData("scope")]
    [InlineData("string-counter")]
    [InlineData("missing-plan")]
    [InlineData("missing-finding")]
    [InlineData("unchanged")]
    [InlineData("token")]
    public void StrictReportRejectsDowngradeScopeOrAuthorityForgery(string corruption)
    {
        using var directory = DTempDirectory.Create("repair-approval-report");
        var request = Request(directory.Path);
        var report = Report(request, "RepairNeedsConfirmation", 3);
        switch (corruption)
        {
            case "version": report["version"] = 1; break;
            case "null-source": report["source"] = null; break;
            case "uppercase-hash": report["source"]!["sha256"] = new string('A', 64); break;
            case "extra-source": report["source"]!["extra"] = true; break;
            case "scope": report["scope"]!["checkpointXid"] = 21UL; break;
            case "string-counter": report["scope"]!["volumeOid"] = "101"; break;
            case "missing-plan": report["plan"] = null; break;
            case "missing-finding": report["finding"] = null; break;
            case "unchanged": report["bytesUnchanged"] = null; break;
            case "token": report["confirmationToken"] = "not-public-authority"; break;
        }
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeRepair.ParseReport(report.ToJsonString(), 3, request));
    }

    [Fact]
    public void FreshApplyMustEchoExactReviewedSourceAndCount()
    {
        using var directory = DTempDirectory.Create("repair-approval-echo");
        var request = Approved(Request(directory.Path));
        foreach (var field in new[] { "identity", "sha256", "expectedCount" })
        {
            var report = Report(request, "RepairedAndVerified", 0);
            if (field == "expectedCount") report["plan"]![field] = 2UL;
            else if (field == "sha256") report["source"]![field] = new string('f', 64);
            else report["source"]![field] = request.ApprovedSourceIdentity.Replace("windows-image-v1:", "windows-image-v1:0");
            Assert.Throws<InvalidDataException>(() => NativeApfsVolumeRepair.ParseReport(report.ToJsonString(), 0, request));
        }
        var unapproved = request with { ApprovedSourceSha256 = "", ApprovedSourceIdentity = "" };
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeRepair.ParseReport(Report(request, "RepairedAndVerified", 0).ToJsonString(), 0, unapproved));
    }

    [Fact]
    public void OriginalJournalReplayAndHealthyNoOpCarryNoNewApproval()
    {
        using var directory = DTempDirectory.Create("repair-approval-replay");
        var request = Request(directory.Path);
        var replay = Report(request, "RepairedAndVerified", 0, replayed: true);
        Assert.Equal(ApfsRepairOutcome.RepairedAndVerified, NativeApfsVolumeRepair.ParseReport(replay.ToJsonString(), 0, request).Outcome);
        var healthy = Report(request, "RepairHealthyNoFinding", 0);
        Assert.Equal(ApfsRepairOutcome.HealthyNoFinding, NativeApfsVolumeRepair.ParseReport(healthy.ToJsonString(), 0, request).Outcome);
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeRepair.ParseReport(replay.ToJsonString(), 0, request with { ApprovalMode = "" }));
    }

    [Fact]
    public void RefusalCanReportDifferentSourceFromApprovalWithoutAuthorizingApply()
    {
        using var directory = DTempDirectory.Create("repair-approval-refusal");
        var request = Approved(Request(directory.Path)) with { ApprovedSourceSha256 = new string('f', 64) };
        var report = Report(request, "RepairRefused", 4);
        var runner = new Runner(new(4, report.ToJsonString(), ""));
        var result = new NativeApfsVolumeRepair(runner, Tool(directory.Path)).Repair(request);
        Assert.Equal(ApfsRepairOutcome.Refused, result.Outcome);
        Assert.False(result.Report.GetProperty("applied").GetBoolean());
    }

    [Fact]
    public void NativeDryDigestMustMatchActualCompleteInvocationImage()
    {
        using var directory = DTempDirectory.Create("repair-approval-digest-lie");
        var request = Request(directory.Path);
        var report = Report(request, "RepairNeedsConfirmation", 3);
        report["source"]!["sha256"] = new string('f', 64);
        var runner = new Runner(new(3, report.ToJsonString(), ""));
        Assert.Throws<InvalidDataException>(() => new NativeApfsVolumeRepair(runner, Tool(directory.Path)).Repair(request));
    }

    private static ApfsVolumeRepairRequest Request(string directory)
    {
        var image = Path.Combine(directory, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        return new(image, "apfs-container:" + Container, Volume, "101", "20", "0", "4096",
            Path.Combine(directory, "repair.wal"), Path.Combine(directory, "evidence"), "", false)
        { ApprovalMode = NativeApfsVolumeRepair.ExactSourceApprovalMode };
    }

    private static ApfsVolumeRepairRequest Approved(ApfsVolumeRepairRequest request) => request with
    {
        Confirm = true, ExpectedCount = "1", ApprovedSourceIdentity = NativeApfsVolumeRepair.ReadApprovalIdentity(request.Image),
        ApprovedSourceSha256 = NativeApfsVolumeRepair.HashFile(request.Image, default),
    };

    private static string Tool(string directory)
    {
        var tool = Path.Combine(directory, "ApfsVolumeRepairTool.exe"); File.WriteAllBytes(tool, [0x4D, 0x5A]); return tool;
    }

    private static JsonObject Report(ApfsVolumeRepairRequest request, string code, int exit, bool replayed = false)
    {
        var repaired = code == "RepairedAndVerified";
        var needsPlan = code == "RepairNeedsConfirmation" || (repaired && !replayed);
        return new()
        {
            ["format"] = "apfs-access-repair", ["version"] = 2, ["command"] = "repair", ["success"] = exit == 0,
            ["exitCode"] = exit, ["code"] = code, ["error"] = null,
            ["image"] = new JsonObject { ["path"] = request.Image, ["sizeBytes"] = 4096UL },
            ["scope"] = new JsonObject
            {
                ["containerUuid"] = Container, ["volumeUuid"] = Volume, ["volumeOid"] = 101UL,
                ["checkpointXid"] = 20UL, ["storeOffsetBytes"] = 0UL, ["storeSizeBytes"] = 4096UL,
            },
            ["source"] = new JsonObject { ["identity"] = NativeApfsVolumeRepair.ReadApprovalIdentity(request.Image),
                ["sha256"] = NativeApfsVolumeRepair.HashFile(request.Image, default) },
            ["finding"] = needsPlan ? new JsonObject { ["code"] = 25, ["severity"] = 3, ["check"] = 7, ["detail"] = "count differs" } : null,
            ["plan"] = needsPlan ? new JsonObject { ["expectedCount"] = 1UL } : null,
            ["applied"] = repaired, ["replayed"] = replayed,
            ["postVerify"] = exit == 0 ? new JsonObject { ["outcome"] = 1, ["findings"] = 0UL } : null,
            ["journal"] = request.Journal, ["backup"] = repaired && !replayed ? "backup.apfs" : null,
            ["bytesUnchanged"] = repaired ? null : JsonValue.Create(true),
        };
    }

    private sealed class Runner(ObserverRunResult result, Action? action = null) : IObserverRunner
    {
        public IReadOnlyList<string>? Arguments { get; private set; }
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        { Arguments = arguments.ToArray(); action?.Invoke(); return result; }
    }
}
