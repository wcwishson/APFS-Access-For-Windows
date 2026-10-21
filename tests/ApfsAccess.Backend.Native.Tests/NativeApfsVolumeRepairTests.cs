using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// Managed transport over the offline repair tool: strict report parsing,
// exact scope/identity binding, and mid-run tamper detection. The native
// tool binary itself is proven by ApfsVolumeRepairToolTests; these gates pin
// the contract between the bytes on disk and the JSON the CLI trusts.
public sealed class NativeApfsVolumeRepairTests
{
    private const string ContainerHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string VolumeHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    [Fact]
    public void ParseReport_AcceptsCanonicalDryRunAndApplyShapes()
    {
        using var temp = DTempDirectory.Create("repair-parse");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        var request = DryRunRequest(image);
        var dry = ParseReport(CanonicalJson(request, 3, "RepairNeedsConfirmation", finding: true, plan: true), 3, request);
        Assert.Equal(ApfsRepairOutcome.NeedsConfirmation, dry.Outcome);
        var done = ParseReport(CanonicalJson(request, 0, "RepairedAndVerified", finding: true, plan: true,
            applied: true, postVerify: true, backup: "b", unchanged: null), 0, request with { Confirm = true, ExpectedCount = "1" });
        Assert.Equal(ApfsRepairOutcome.RepairedAndVerified, done.Outcome);
        var healthy = ParseReport(CanonicalJson(request, 0, "RepairHealthyNoFinding", postVerify: true, unchanged: true), 0, request);
        Assert.Equal(ApfsRepairOutcome.HealthyNoFinding, healthy.Outcome);
    }

    [Theory]
    [InlineData(0, "RepairNeedsConfirmation")]
    [InlineData(3, "RepairedAndVerified")]
    [InlineData(4, "RepairHealthyNoFinding")]
    [InlineData(0, "NoSuchCode")]
    public void ParseReport_RejectsExitCodeMismatch(int exit, string code)
    {
        using var temp = DTempDirectory.Create("repair-parse-refuse");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        var request = DryRunRequest(image);
        Assert.Throws<InvalidDataException>(() =>
            ParseReport(CanonicalJson(request, exit, code, finding: true, plan: true), exit, request));
    }

    [Fact]
    public void ParseReport_RejectsScopeFindingAndPlanViolations()
    {
        using var temp = DTempDirectory.Create("repair-parse-scope");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        var request = DryRunRequest(image);
        // Scope echo must be exact.
        Assert.Throws<InvalidDataException>(() => ParseReport(
            CanonicalJson(request, 3, "RepairNeedsConfirmation", finding: true, plan: true)
                .Replace("\"volumeOid\":\"101\"", "\"volumeOid\":\"102\""), 3, request));
        // Healthy must carry no finding and no plan.
        Assert.Throws<InvalidDataException>(() => ParseReport(
            CanonicalJson(request, 0, "RepairHealthyNoFinding", finding: true, postVerify: true), 0, request));
        Assert.Throws<InvalidDataException>(() => ParseReport(
            CanonicalJson(request, 4, "RepairRefused"), 4, request with { ContainerId = "apfs-container:" + new string('c', 32) }));
        // Replay has no new finding or plan; fresh apply requires explicit intent.
        Assert.Throws<InvalidDataException>(() => ParseReport(
            CanonicalJson(request, 0, "RepairedAndVerified", finding: true, plan: true,
                applied: true, replayed: true, postVerify: true), 0, request));
        // Unchanged bytes are only claimable on non-failure outcomes.
        Assert.Throws<InvalidDataException>(() => ParseReport(
            CanonicalJson(request, 4, "RepairRefused", unchanged: true).Replace("\"exitCode\":4", "\"exitCode\":5"), 5, request));
        // Unknown top-level keys fail closed.
        Assert.Throws<InvalidDataException>(() => ParseReport(
            CanonicalJson(request, 3, "RepairNeedsConfirmation", finding: true, plan: true)
                .TrimEnd('}') + ",\"extra\":1}", 3, request));
    }

    [Fact]
    public void ValidateRequest_PinsScopeAndIntentShape()
    {
        using var temp = DTempDirectory.Create("repair-validate");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        var journal = Path.Combine(temp.Path, "repair.wal");
        var evidence = Path.Combine(temp.Path, "evidence");
        ApfsVolumeRepairRequest Base() => new(image, "apfs-container:" + ContainerHex, VolumeHex,
            "101", "20", "0", "4096", journal, evidence, string.Empty, false);
        NativeApfsVolumeRepair.ValidateRequest(Base());
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRepair.ValidateRequest(Base() with { Journal = image }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRepair.ValidateRequest(Base() with { Confirm = true }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRepair.ValidateRequest(Base() with { ExpectedCount = "1" }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRepair.ValidateRequest(
            Base() with { Journal = Path.Combine(temp.Path, "missing-dir", "repair.wal") }));
        var ok = Base() with { ExpectedCount = "1", Confirm = true };
        NativeApfsVolumeRepair.ValidateRequest(ok);
    }

    [Fact]
    public void Repair_InvokesToolVectorAndBindsOutcome()
    {
        using var temp = DTempDirectory.Create("repair-invoke");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        var request = DryRunRequest(image);
        var tool = Path.Combine(temp.Path, "ApfsVolumeRepairTool.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var runner = new CannedRunner(
            CanonicalJson(request, 3, "RepairNeedsConfirmation", finding: true, plan: true));
        var transport = new NativeApfsVolumeRepair(runner, tool);

        var result = transport.Repair(request);

        Assert.Equal(
            ["--image", image, "--container-uuid", ContainerHex, "--volume-uuid", VolumeHex,
             "--volume-oid", "101", "--checkpoint-xid", "20", "--store-offset-bytes", "0",
             "--store-size-bytes", "4096", "--journal", request.Journal, "--evidence-dir", request.EvidenceDir],
            runner.LastArguments);
        Assert.Equal(ApfsRepairOutcome.NeedsConfirmation, result.Outcome);
        Assert.Equal(3, result.NativeExitCode);
    }

    [Fact]
    public void ParseReport_AcceptsNativeReplayWithoutNewConfirmationAndRejectsUnconfirmedFreshApply()
    {
        using var temp = DTempDirectory.Create("repair-replay");
        var image = Path.Combine(temp.Path, "image.apfs"); File.WriteAllBytes(image, new byte[4096]);
        var request = DryRunRequest(image);
        var replay = ParseReport(CanonicalJson(request, 0, "RepairedAndVerified", applied: true, replayed: true,
            postVerify: true, unchanged: false), 0, request);
        Assert.Equal(ApfsRepairOutcome.RepairedAndVerified, replay.Outcome);
        Assert.Throws<InvalidDataException>(() => ParseReport(CanonicalJson(request, 0, "RepairedAndVerified",
            finding: true, plan: true, applied: true, postVerify: true, unchanged: false), 0, request));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Repair_InPlaceWriteKeepsIdentityButUnchangedBytesClaimIsStillChecked(bool claimsUnchanged)
    {
        using var temp = DTempDirectory.Create("repair-in-place");
        var image = Path.Combine(temp.Path, "image.apfs"); File.WriteAllBytes(image, new byte[4096]);
        var request = DryRunRequest(image) with { Confirm = true, ExpectedCount = "1" };
        var tool = Path.Combine(temp.Path, "ApfsVolumeRepairTool.exe"); File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var json = CanonicalJson(request, 0, "RepairedAndVerified", finding: true, plan: true, applied: true,
            postVerify: true, unchanged: claimsUnchanged);
        var repair = new NativeApfsVolumeRepair(new InPlaceRunner(image, json), tool);
        if (claimsUnchanged) Assert.Throws<InvalidDataException>(() => repair.Repair(request));
        else Assert.Equal(ApfsRepairOutcome.RepairedAndVerified, repair.Repair(request).Outcome);
    }

    [Fact]
    public void Repair_DetectsMidRunReplacement()
    {
        using var temp = DTempDirectory.Create("repair-tamper");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        var request = DryRunRequest(image);
        // The runner swaps the file mid-call: identity must mismatch post-run.
        var tool = Path.Combine(temp.Path, "ApfsVolumeRepairTool.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var transport = new NativeApfsVolumeRepair(new ReplacingRunner(image,
            CanonicalJson(request, 3, "RepairNeedsConfirmation", finding: true, plan: true)),
            tool);

        Assert.Throws<InvalidDataException>(() => transport.Repair(request));
    }

    [Fact]
    public void Repair_DetectsUnchangedBytesLie()
    {
        using var temp = DTempDirectory.Create("repair-lie");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        var request = DryRunRequest(image);
        // The runner appends mid-call while reporting bytesUnchanged:true.
        var tool = Path.Combine(temp.Path, "ApfsVolumeRepairTool.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var transport = new NativeApfsVolumeRepair(new AppendingRunner(image,
            CanonicalJson(request, 0, "RepairHealthyNoFinding", postVerify: true, unchanged: true)),
            tool);

        Assert.Throws<InvalidDataException>(() => transport.Repair(request));
    }

    private static ApfsVolumeRepairRequest DryRunRequest(string image)
    {
        var dir = Path.GetDirectoryName(image)!;
        return new ApfsVolumeRepairRequest(image, "apfs-container:" + ContainerHex, VolumeHex,
            "101", "20", "0", new FileInfo(image).Length.ToString(), Path.Combine(dir, "repair.wal"),
            Path.Combine(dir, "evidence"), string.Empty, false);
    }

    private static ApfsVolumeRepairResult ParseReport(string json, int exit, ApfsVolumeRepairRequest request)
        => NativeApfsVolumeRepair.ParseReport(json, exit, request);

    private static string CanonicalJson(ApfsVolumeRepairRequest request, int exit, string code,
        bool finding = false, bool plan = false, bool applied = false, bool replayed = false,
        bool postVerify = false, string? backup = null, bool? unchanged = true)
    {
        string Str(string? value) => value is null ? "null" : $"\"{value}\"";
        var findingJson = finding
            ? "{\"code\":25,\"severity\":3,\"check\":7,\"detail\":\"count differs\"}" : "null";
        var planJson = plan ? "{\"expectedCount\":1}" : "null";
        var postJson = postVerify ? "{\"outcome\":1,\"findings\":0}" : "null";
        return "{\"format\":\"apfs-access-repair\",\"version\":1,\"command\":\"repair\"," +
            $"\"success\":{(exit == 0 ? "true" : "false")},\"exitCode\":{exit},\"code\":\"{code}\",\"error\":null," +
            "\"image\":{\"path\":\"" + request.Image.Replace("\\", "\\\\") + "\",\"sizeBytes\":4096}," +
            "\"scope\":{\"containerUuid\":\"" + request.ContainerId[15..] + "\",\"volumeUuid\":\"" + request.VolumeUuid +
            "\",\"volumeOid\":\"" + request.VolumeOid + "\",\"checkpointXid\":\"" + request.CheckpointXid +
            "\",\"storeOffsetBytes\":\"" + request.StoreOffsetBytes + "\",\"storeSizeBytes\":\"" + request.StoreSizeBytes + "\"}," +
            $"\"finding\":{findingJson},\"plan\":{planJson},\"applied\":{(applied ? "true" : "false")}," +
            $"\"replayed\":{(replayed ? "true" : "false")},\"postVerify\":{postJson}," +
            $"\"journal\":\"{request.Journal.Replace("\\", "\\\\")}\",\"backup\":{Str(backup)}," +
            $"\"bytesUnchanged\":{(unchanged is null ? "null" : unchanged.Value ? "true" : "false")}}}";
    }

    private sealed class CapturingRunner(ObserverRunResult result) : IObserverRunner
    {
        public IReadOnlyList<string>? LastArguments { get; private set; }
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        {
            LastArguments = arguments.ToArray();
            return result;
        }
    }

    private sealed class CannedRunner(string json) : IObserverRunner
    {
        public IReadOnlyList<string>? LastArguments { get; private set; }
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        {
            LastArguments = arguments.ToArray();
            return new(3, json, string.Empty);
        }
    }

    private sealed class ReplacingRunner(string image, string json) : IObserverRunner
    {
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        {
            File.Delete(image);
            File.WriteAllBytes(image, new byte[8192]);
            return new(3, json, string.Empty);
        }
    }

    private sealed class AppendingRunner(string image, string json) : IObserverRunner
    {
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        {
            using var append = new FileStream(image, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            append.Write(new byte[512]);
            return new(0, json, string.Empty);
        }
    }

    private sealed class InPlaceRunner(string image, string json) : IObserverRunner
    {
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        {
            using (var writer = new FileStream(image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) writer.WriteByte(0xAF);
            File.SetLastWriteTimeUtc(image, DateTime.UtcNow.AddMinutes(1));
            return new(0, json, "");
        }
    }
}
