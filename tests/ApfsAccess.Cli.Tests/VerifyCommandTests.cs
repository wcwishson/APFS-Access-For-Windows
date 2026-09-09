using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class VerifyCommandTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "verify-cli-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "image.raw");
    public VerifyCommandTests() { Directory.CreateDirectory(directory); File.WriteAllBytes(Image, new byte[4096]); }
    public void Dispose() => Directory.Delete(directory, true);
    private string[] Args => ["--image", Image, "--container-id", "apfs-container:" + new string('a',32), "--volume-uuid", new string('b',32),
        "--volume-oid", "101", "--checkpoint-xid", "20", "--store-offset-bytes", "0", "--store-size-bytes", "4096"];
    private static (int Exit, JsonElement Json) Run(string[] args, Exception? failure = null, CancellationToken token = default)
    {
        var previous = Console.Out; using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            var exit = VerifyCommand.Run(args, (_, _) => throw failure ?? new Exception("Should not execute"), token);
            return (exit, JsonDocument.Parse(output.ToString()).RootElement.Clone());
        }
        finally { Console.SetOut(previous); }
    }
    [Theory]
    [InlineData("--image")] [InlineData("--volume-uuid")] [InlineData("--checkpoint-xid")]
    [InlineData("--elevate")] [InlineData("--require-admin")] [InlineData("--device-id")]
    [InlineData("--profile")] [InlineData("--out")] [InlineData("--mode")]
    public void DuplicateAndUnrelatedFlagsAreRejectedBeforeExecution(string flag)
    { Assert.Equal(2, Run([..Args, flag, "value"]).Exit); }
    [Theory]
    [InlineData("--json")] [InlineData("--require-whole-volume")] [InlineData("--require-payload-content-hashes")]
    public void DuplicateSwitchesAreRejected(string flag)
    { Assert.Equal(2, Run([..Args, flag, flag]).Exit); }
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
    public void ExactArgumentsAndBroaderFlagsArePreserved()
    {
        var parsed = VerifyCommand.ParseArguments([..Args, "--json", "--require-whole-volume", "--require-payload-content-hashes"]);
        Assert.Equal(Image, parsed.Image); Assert.Equal("101", parsed.VolumeOid); Assert.Equal("20", parsed.CheckpointXid);
        Assert.Equal("0", parsed.StoreOffsetBytes); Assert.Equal("4096", parsed.StoreSizeBytes);
        Assert.True(parsed.RequireWholeVolume); Assert.True(parsed.RequirePayloadContentHashes);
    }
    [Theory]
    [InlineData("launch", 5, "ObserverLaunchFailed")] [InlineData("missing", 5, "ObserverUnavailable")]
    [InlineData("timeout", 6, "VerificationTimeout")] [InlineData("cancel", 12, "VerificationCancelled")]
    [InlineData("malformed", 5, "InvalidVerificationOutput")] [InlineData("native", 5, "NativeVerificationFailed")]
    public void FailuresHaveExplicitCodesAndNoVerificationPayload(string kind, int exit, string code)
    {
        Exception error = kind switch { "launch" => new System.ComponentModel.Win32Exception(), "missing" => new FileNotFoundException(),
            "timeout" => new TimeoutException(), "cancel" => new OperationCanceledException(), "malformed" => new InvalidDataException(),
            _ => new NativeVerificationExitException(2, "Invalid native request") };
        var result = Run(Args, error); Assert.Equal(exit, result.Exit);
        Assert.Equal(code, result.Json.GetProperty("code").GetString()); Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("verification").ValueKind);
        if (kind == "native") Assert.Equal(2, result.Json.GetProperty("nativeExitCode").GetInt32());
    }
    [Fact]
    public void CancellationBeforeExecutionAndHelp()
    {
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        Assert.Equal(12, Run(Args, token: cancellation.Token).Exit);
        var help = Run(["--help"]); Assert.Equal(0, help.Exit);
        Assert.Contains("covered current metadata subset", help.Json.GetProperty("description").GetString());
        Assert.Contains("--checkpoint-xid", help.Json.GetProperty("usage").GetString());
    }
    [Theory]
    [InlineData(1, 0, "CurrentMetadataSubsetVerified")]
    [InlineData(2, 3, "VerificationIncomplete")]
    [InlineData(3, 4, "VerificationRefused")]
    public void TypedNativeResultsKeepExitAndPayload(int outcome, int exit, string code)
    {
        var previous = Console.Out; using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            var report = JsonSerializer.SerializeToElement(new { wholeVolumeVerified = false, sourceReads = "18446744073709551615" });
            Assert.Equal(exit, VerifyCommand.Run([..Args, "--json"], (_, _) => new ApfsImageVerificationResult(exit, (ApfsVerificationOutcome)outcome, report)));
            using var json = JsonDocument.Parse(output.ToString());
            Assert.Equal(exit, json.RootElement.GetProperty("nativeExitCode").GetInt32());
            Assert.Equal(code, json.RootElement.GetProperty("code").GetString());
            Assert.Equal(exit == 0, json.RootElement.GetProperty("success").GetBoolean());
            Assert.Equal("18446744073709551615", json.RootElement.GetProperty("verification").GetProperty("sourceReads").GetString());
            Assert.False(json.RootElement.GetProperty("verification").GetProperty("wholeVolumeVerified").GetBoolean());
        }
        finally { Console.SetOut(previous); }
    }
    [Fact]
    public async Task RegistrationAndRoutingRequireNoService()
    {
        var previous = Console.Out; using var output = new StringWriter();
        try
        {
            Console.SetOut(output); Assert.Equal(0, await Program.RunForTestAsync(["capabilities"]));
            using var json = JsonDocument.Parse(output.ToString());
            Assert.Contains(json.RootElement.GetProperty("commands").EnumerateArray(), x => x.GetString() == "verify");
            Assert.Contains("covered current metadata subset", json.RootElement.GetProperty("verificationScope").GetString());
            output.GetStringBuilder().Clear();
            Assert.Equal(2, await Program.RunForTestAsync(["verify", "--elevate"]));
            using var invalid = JsonDocument.Parse(output.ToString());
            Assert.Equal("verify", invalid.RootElement.GetProperty("command").GetString());
            Assert.Equal("InvalidArguments", invalid.RootElement.GetProperty("code").GetString());
        }
        finally { Console.SetOut(previous); }
    }
}
