using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class RepairSourceApprovalCommandTests : IDisposable
{
    private const string ApprovalMode = "exact-source-v1";
    private static readonly string Identity = "windows-image-v1:" + new string('a', 48) +
        "00000000000000000000000000001000:100";
    private static readonly string Digest = new('b', 64);
    private readonly string directory = Path.Combine(Path.GetTempPath(), "repair-approval-cli-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "image.raw");
    private string[] Args => ["--image", Image, "--container-id", "apfs-container:" + new string('a', 32),
        "--volume-uuid", new string('b', 32), "--volume-oid", "101", "--checkpoint-xid", "20",
        "--store-offset-bytes", "0", "--store-size-bytes", "4096", "--journal", Path.Combine(directory, "repair.wal"),
        "--evidence-dir", Path.Combine(directory, "evidence")];
    private string[] DryArgs => [..Args, "--approval-mode", ApprovalMode];
    private string[] ApplyArgs => [..DryArgs, "--confirm", "--expected-count", "1",
        "--approved-source-identity", Identity, "--approved-source-sha256", Digest];

    public RepairSourceApprovalCommandTests()
    {
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Image, new byte[4096]);
    }

    public void Dispose() => Directory.Delete(directory, true);

    private static (int Exit, JsonElement Output, JsonElement? Request, int Calls) Run(
        string[] args, ApfsRepairOutcome outcome = ApfsRepairOutcome.NeedsConfirmation)
    {
        var previous = Console.Out;
        using var output = new StringWriter();
        JsonElement? request = null;
        var calls = 0;
        try
        {
            Console.SetOut(output);
            var exit = RepairCommand.Run(args, (value, _) =>
            {
                ++calls;
                request = JsonSerializer.SerializeToElement(value);
                var nativeExit = outcome == ApfsRepairOutcome.NeedsConfirmation ? 3 : 0;
                return new ApfsVolumeRepairResult(nativeExit, outcome,
                    JsonSerializer.SerializeToElement(new { version = 2, approvalMode = ApprovalMode }));
            });
            return (exit, JsonDocument.Parse(output.ToString()).RootElement.Clone(), request, calls);
        }
        finally { Console.SetOut(previous); }
    }

    [Fact]
    public void DryPlanForwardsTheExplicitSourceApprovalMode()
    {
        var actual = Run(DryArgs);
        Assert.Equal(3, actual.Exit);
        Assert.Equal(1, actual.Calls);
        Assert.Equal(ApprovalMode, actual.Request!.Value.GetProperty("ApprovalMode").GetString());
        Assert.False(actual.Request.Value.GetProperty("Confirm").GetBoolean());
        Assert.Equal(2, actual.Output.GetProperty("repair").GetProperty("version").GetInt32());
        Assert.Contains("--approved-source-identity", actual.Output.GetProperty("message").GetString());
        Assert.Contains("--approved-source-sha256", actual.Output.GetProperty("message").GetString());
    }

    [Fact]
    public void ConfirmedApplyForwardsEveryExactApprovalValue()
    {
        var actual = Run(ApplyArgs, ApfsRepairOutcome.RepairedAndVerified);
        Assert.Equal(0, actual.Exit);
        Assert.Equal(1, actual.Calls);
        var request = actual.Request!.Value;
        Assert.Equal(ApprovalMode, request.GetProperty("ApprovalMode").GetString());
        Assert.Equal(Identity, request.GetProperty("ApprovedSourceIdentity").GetString());
        Assert.Equal(Digest, request.GetProperty("ApprovedSourceSha256").GetString());
        Assert.Equal("1", request.GetProperty("ExpectedCount").GetString());
        Assert.True(request.GetProperty("Confirm").GetBoolean());
    }

    [Theory]
    [InlineData("--approval-mode", "unknown")]
    [InlineData("--approval-mode", "EXACT-SOURCE-V1")]
    [InlineData("--approval-mode", "")]
    [InlineData("--approved-source-identity", "windows-image-v1:invalid")]
    [InlineData("--approved-source-identity", "")]
    [InlineData("--approved-source-sha256", "short")]
    [InlineData("--approved-source-sha256", "")]
    public void InvalidOrUnscopedApprovalNeverDispatches(string flag, string value)
    {
        var actual = Run([..Args, flag, value]);
        Assert.Equal(2, actual.Exit);
        Assert.Equal(0, actual.Calls);
        Assert.Equal(JsonValueKind.Null, actual.Output.GetProperty("repair").ValueKind);
    }

    [Theory]
    [InlineData("--approved-source-identity")]
    [InlineData("--approved-source-sha256")]
    [InlineData("--expected-count")]
    public void ConfirmationRequiresAllApprovalValues(string removed)
    {
        var input = ApplyArgs.ToList();
        var index = input.IndexOf(removed);
        input.RemoveRange(index, 2);
        var actual = Run(input.ToArray());
        Assert.Equal(2, actual.Exit);
        Assert.Equal(0, actual.Calls);
    }

    [Theory]
    [InlineData("identity")]
    [InlineData("hash")]
    [InlineData("both")]
    public void ApprovalValuesWithoutConfirmationNeverDispatch(string material)
    {
        var input = DryArgs.ToList();
        if (material is "identity" or "both") input.AddRange(["--approved-source-identity", Identity]);
        if (material is "hash" or "both") input.AddRange(["--approved-source-sha256", Digest]);
        var actual = Run(input.ToArray());
        Assert.Equal(2, actual.Exit);
        Assert.Equal(0, actual.Calls);
    }

    [Theory]
    [InlineData("--approved-source-identity")]
    [InlineData("--approved-source-sha256")]
    public void EmptyExplicitApprovalDoesNotBecomeADryPlan(string flag)
    {
        var actual = Run([..DryArgs, flag, ""]);
        Assert.Equal(2, actual.Exit);
        Assert.Equal(0, actual.Calls);
    }

    [Theory]
    [InlineData("--approval-mode", "exact-source-v1")]
    [InlineData("--approved-source-identity", "duplicate")]
    [InlineData("--approved-source-sha256", "duplicate")]
    public void DuplicateApprovalArgumentsNeverDispatch(string flag, string value)
    {
        var actual = Run([..ApplyArgs, flag, value]);
        Assert.Equal(2, actual.Exit);
        Assert.Equal(0, actual.Calls);
    }

    [Theory]
    [InlineData("identity", "windows-image-v1:short:100")]
    [InlineData("creation", "0100")]
    [InlineData("hash", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    [InlineData("hash", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")]
    [InlineData("hash", "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
    public void MalformedExactMaterialNeverDispatches(string kind, string value)
    {
        var input = ApplyArgs;
        var identity = kind is "identity" or "creation";
        input[Array.IndexOf(input, identity ? "--approved-source-identity" : "--approved-source-sha256") + 1] =
            kind == "creation" ? Identity[..(Identity.LastIndexOf(':') + 1)] + value : value;
        var actual = Run(input);
        Assert.Equal(2, actual.Exit);
        Assert.Equal(0, actual.Calls);
    }

    [Fact]
    public void HelpExplainsTheSourceBoundConfirmation()
    {
        var actual = Run(["--help"]);
        Assert.Equal(0, actual.Exit);
        Assert.Equal(0, actual.Calls);
        Assert.Contains("--approval-mode exact-source-v1", actual.Output.GetProperty("usage").GetString());
        Assert.Contains("--approved-source-sha256", actual.Output.GetProperty("description").GetString());
        Assert.Contains("same image", actual.Output.GetProperty("description").GetString());
    }
}
