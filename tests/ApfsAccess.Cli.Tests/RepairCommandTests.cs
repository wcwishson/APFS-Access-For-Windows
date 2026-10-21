using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class RepairCommandTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "repair-cli-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "image.raw");
    private string Journal => Path.Combine(directory, "repair.wal");
    private string Evidence => Path.Combine(directory, "evidence");
    public RepairCommandTests() { Directory.CreateDirectory(directory); File.WriteAllBytes(Image, new byte[4096]); }
    public void Dispose() => Directory.Delete(directory, true);
    private string[] Args => ["--image", Image, "--container-id", "apfs-container:" + new string('a', 32), "--volume-uuid", new string('b', 32),
        "--volume-oid", "101", "--checkpoint-xid", "20", "--store-offset-bytes", "0", "--store-size-bytes", "4096",
        "--journal", Journal, "--evidence-dir", Evidence];
    private static (int Exit, JsonElement Json) Run(string[] args, ApfsVolumeRepairResult? result = null, Exception? failure = null, CancellationToken token = default)
    {
        var previous = Console.Out; using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            Func<ApfsVolumeRepairRequest, CancellationToken, ApfsVolumeRepairResult> repair = (_, _) =>
                failure is not null ? throw failure : result!;
            var exit = RepairCommand.Run(args, repair, token);
            return (exit, JsonDocument.Parse(output.ToString()).RootElement.Clone());
        }
        finally { Console.SetOut(previous); }
    }
    private static ApfsVolumeRepairResult NativeResult(int exit, ApfsRepairOutcome outcome)
    {
        using var document = JsonDocument.Parse("{}");
        return new ApfsVolumeRepairResult(exit, outcome, document.RootElement.Clone());
    }
    [Theory]
    [InlineData("--image")] [InlineData("--container-id")] [InlineData("--journal")] [InlineData("--evidence-dir")]
    [InlineData("--confirm")] [InlineData("--bogus")]
    public void DuplicateAndUnrelatedFlagsAreRejectedBeforeExecution(string flag)
    {
        Assert.Equal(2, Run([..Args, flag, "value"]).Exit);
    }
    [Fact]
    public void DuplicateSwitchesAreRejected()
    { Assert.Equal(2, Run([..Args, "--confirm", "--confirm"]).Exit); }
    [Fact]
    public void EveryExactSelectorIsRequired()
    {
        for (var index = 0; index < Args.Length; index += 2)
        { var args = Args; Assert.Equal(2, Run([..args[..index], ..args[(index + 2)..]]).Exit); }
    }
    [Theory]
    [InlineData("relative.raw")] [InlineData("\\\\.\\PhysicalDrive0")] [InlineData("\\\\server\\share\\image.raw")]
    [InlineData("D:\\image.raw:stream")] [InlineData("D:\\folder\\..\\image.raw")]
    public void ImageMustBeRegularAbsoluteLocalFile(string image)
    { var args = Args; args[1] = image; Assert.Equal(2, Run(args).Exit); }
    [Fact]
    public void ConfirmRequiresAnExplicitExpectedCount()
    {
        Assert.Equal(2, Run([..Args, "--confirm"]).Exit);
        var exit = Run([..Args, "--expected-count", "1", "--confirm"],
            NativeResult(0, ApfsRepairOutcome.RepairedAndVerified)).Exit;
        Assert.Equal(0, exit);
    }
    [Fact]
    public void ExpectedCountWithoutConfirmStatesNoIntent()
    {
        Assert.Equal(2, Run([..Args, "--expected-count", "1"]).Exit);
    }
    [Theory]
    [InlineData(ApfsRepairOutcome.RepairedAndVerified, 0, "RepairedAndVerified")]
    [InlineData(ApfsRepairOutcome.HealthyNoFinding, 0, "RepairHealthyNoFinding")]
    [InlineData(ApfsRepairOutcome.NeedsConfirmation, 3, "RepairNeedsConfirmation")]
    [InlineData(ApfsRepairOutcome.Refused, 4, "RepairRefused")]
    public void TypedNativeResultsKeepExitAndPayload(ApfsRepairOutcome outcome, int exit, string code)
    {
        var result = Run(Args, NativeResult(exit, outcome));
        Assert.Equal(exit, result.Exit);
        Assert.Equal(code, result.Json.GetProperty("code").GetString());
        Assert.Equal(exit == 0, result.Json.GetProperty("success").GetBoolean());
        Assert.Equal("repair", result.Json.GetProperty("command").GetString());
        Assert.Equal(exit, result.Json.GetProperty("nativeExitCode").GetInt32());
    }
    [Theory]
    [InlineData("launch", 5, "RepairToolLaunchFailed")] [InlineData("missing", 5, "RepairToolUnavailable")]
    [InlineData("timeout", 6, "RepairTimeout")] [InlineData("cancel", 12, "RepairCancelled")]
    [InlineData("malformed", 5, "InvalidRepairOutput")] [InlineData("native", 5, "NativeRepairFailed")]
    public void FailuresHaveExplicitCodesAndNoRepairPayload(string kind, int exit, string code)
    {
        Exception error = kind switch { "launch" => new System.ComponentModel.Win32Exception(), "missing" => new FileNotFoundException(),
            "timeout" => new TimeoutException(), "cancel" => new OperationCanceledException(), "malformed" => new InvalidDataException(),
            _ => new NativeRepairExitException(2, "Invalid native request") };
        var result = Run(Args, failure: error); Assert.Equal(exit, result.Exit);
        Assert.Equal(code, result.Json.GetProperty("code").GetString()); Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("repair").ValueKind);
        if (kind == "native") Assert.Equal(2, result.Json.GetProperty("nativeExitCode").GetInt32());
    }
    [Fact]
    public void CancellationBeforeExecutionAndHelp()
    {
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        Assert.Equal(12, Run(Args, token: cancellation.Token).Exit);
        var help = Run(["--help"]); Assert.Equal(0, help.Exit);
        Assert.Contains("Bounded offline", help.Json.GetProperty("description").GetString());
        Assert.Contains("--checkpoint-xid", help.Json.GetProperty("usage").GetString());
        Assert.Contains("bytes unchanged", help.Json.GetProperty("description").GetString());
    }
    [Fact]
    public async Task CapabilitiesAdvertiseRepairScope()
    {
        var previous = Console.Out; using var output = new StringWriter();
        try
        {
            Console.SetOut(output); Assert.Equal(0, await Program.RunForTestAsync(["capabilities"]));
            using var json = JsonDocument.Parse(output.ToString());
            Assert.Contains(json.RootElement.GetProperty("commands").EnumerateArray(), x => x.GetString() == "repair");
            Assert.Contains("Bounded offline", json.RootElement.GetProperty("repairScope").GetString());
        }
        finally { Console.SetOut(previous); }
    }
}
