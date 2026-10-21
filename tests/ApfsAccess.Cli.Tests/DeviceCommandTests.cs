using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class DeviceCommandTests
{
    [Fact]
    public void ParseAcceptsDeviceIdWithOptionalFlags()
    {
        var options = DeviceCommand.Parse(["device-eject", "--device-id", "device-1"]);
        Assert.Equal("device-1", options.DeviceId);
        Assert.False(options.DryRun);
        Assert.True(Guid.TryParseExact(options.OperationId, "D", out _));

        var dry = DeviceCommand.Parse(["device-eject", "--device-id", "device-1", "--dry-run"]);
        Assert.True(dry.DryRun);
    }

    [Theory]
    [InlineData("frobnicate")]
    [InlineData("mount")]
    public void ParseRejectsUnknownActions(string action)
    {
        Assert.Throws<ArgumentException>(() =>
            DeviceCommand.Parse([action, "--device-id", "device-1"]));
    }

    [Fact]
    public void ParseRejectsMissingDeviceDuplicatesAndOperationShape()
    {
        Assert.Throws<ArgumentException>(() => DeviceCommand.Parse(["device-eject"]));
        Assert.Throws<ArgumentException>(() => DeviceCommand.Parse(
            ["device-eject", "--device-id", "a", "--device-id", "b"]));
        Assert.Throws<ArgumentException>(() => DeviceCommand.Parse(
            ["device-eject", "--device-id", "a", "--container-id", "b"]));
        Assert.Throws<ArgumentException>(() => DeviceCommand.Parse(
            ["device-eject", "--device-id", "a", "--dry-run", "--dry-run"]));
        Assert.Throws<ArgumentException>(() => DeviceCommand.Parse(
            ["device-eject", "--device-id", "a", "--operation-id", "not-a-guid"]));
    }

    [Fact]
    public async Task RunAsyncRefusesInvalidArgumentsBeforeConnecting()
    {
        Assert.Equal(2, await DeviceCommand.RunAsync(["device-eject"]));
        Assert.Equal(2, await DeviceCommand.RunAsync(["bogus"]));
    }

    private static async Task<(int Exit, System.Text.Json.JsonElement Json)> RunEnvelopeAsync(string[] args)
    {
        var previous = Console.Out; using var output = new StringWriter();
        try { Console.SetOut(output); var exit = await DeviceCommand.RunAsync(args); return (exit, System.Text.Json.JsonDocument.Parse(output.ToString()).RootElement.Clone()); }
        finally { Console.SetOut(previous); }
    }

    [Fact]
    public async Task ArgumentErrorEmitsSchema2EnvelopeWithUsage()
    {
        var (exit, json) = await RunEnvelopeAsync(["device-eject"]);
        Assert.Equal(2, exit);
        Assert.Equal(2, json.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("device-eject", json.GetProperty("command").GetString());
        Assert.True(Guid.TryParseExact(json.GetProperty("operationId").GetString(), "D", out _));
        Assert.False(json.GetProperty("success").GetBoolean());
        Assert.Equal(2, json.GetProperty("exitCode").GetInt32());
        Assert.Contains("device-eject", json.GetProperty("usage").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ArgumentErrorEchoesSuppliedCanonicalOperationId()
    {
        const string supplied = "01234567-89ab-cdef-0123-456789abcdef";
        var (exit, json) = await RunEnvelopeAsync(["device-eject", "--device-id", "d", "--operation-id", supplied, "--bogus", "x"]);
        Assert.Equal(2, exit);
        Assert.Equal(supplied, json.GetProperty("operationId").GetString());
        Assert.Equal("invalid-arguments", json.GetProperty("code").GetString());
    }

    [Fact]
    public async Task CapabilitiesAndHelpAdvertiseDeviceControlUsage()
    {
        Assert.Equal(0, await Program.RunForTestAsync(["capabilities"]));
        Assert.Equal(0, await Program.RunForTestAsync(["help"]));
    }

    [Fact]
    public void RescanParseAcceptsOptionalDeviceIdAndFlags()
    {
        var all = DeviceCommand.ParseControl(["rescan"]);
        Assert.Equal("rescan", all.Command);
        Assert.Null(all.DeviceId);
        Assert.False(all.DryRun);
        Assert.True(Guid.TryParseExact(all.OperationId, "D", out _));

        var specific = DeviceCommand.ParseControl(["rescan", "--device-id", "device-1"]);
        Assert.Equal("rescan", specific.Command);
        Assert.Equal("device-1", specific.DeviceId);
        Assert.False(specific.DryRun);

        var dry = DeviceCommand.ParseControl(["rescan", "--device-id", "device-1", "--dry-run"]);
        Assert.True(dry.DryRun);

        var alias = DeviceCommand.ParseControl(["device-rescan", "--dry-run"]);
        Assert.Equal("device-rescan", alias.Command);
        Assert.True(alias.DryRun);
    }

    [Fact]
    public async Task RescanDryRunEmitsSchema2InspectionEnvelope()
    {
        var (exitAll, jsonAll) = await RunEnvelopeAsync(["rescan", "--dry-run"]);
        Assert.Equal(0, exitAll);
        Assert.Equal(2, jsonAll.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("rescan", jsonAll.GetProperty("command").GetString());
        Assert.True(jsonAll.GetProperty("dryRun").GetBoolean());
        Assert.Equal("all", jsonAll.GetProperty("scope").GetString());

        var (exitDev, jsonDev) = await RunEnvelopeAsync(["rescan", "--device-id", "dev-1", "--dry-run"]);
        Assert.Equal(0, exitDev);
        Assert.Equal("dev-1", jsonDev.GetProperty("deviceId").GetString());
        Assert.Equal("device", jsonDev.GetProperty("scope").GetString());
    }

    [Fact]
    public async Task RescanArgumentErrorEmitsSchema2Envelope()
    {
        var (exit, json) = await RunEnvelopeAsync(["rescan", "--bogus", "val"]);
        Assert.Equal(2, exit);
        Assert.Equal(2, json.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("invalid-arguments", json.GetProperty("code").GetString());
        Assert.Contains("rescan", json.GetProperty("usage").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public void TerminalProofRecognizesProvenDeviceResult()
    {
        var target = new ApfsControlTarget("device-1", string.Empty);
        var request = new ControlOperationRequestPayload(
            Guid.NewGuid().ToString("D"), ApfsControlCommands.DeviceEject, target,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2));
        var now = DateTime.UtcNow;
        var result = new OperationResultPayload(
            request.OperationId, request.Command, target, ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
            now.AddSeconds(-1), now, now, FinalStatus: "device-ejected",
            MountProof: "absent", OwnershipProof: "proven", DurabilityProof: "proven",
            ExpiresAtUtc: request.ExpiresAtUtc);
        var validate = typeof(Program).GetMethod(
            "HasVerifiedTerminalSuccess",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.True((bool)validate!.Invoke(null, [result])!);
        Assert.False((bool)validate.Invoke(null, [result with { OwnershipProof = "not-proven" }])!);
        Assert.False((bool)validate.Invoke(null, [result with { FinalStatus = "container-unmounted" }])!);
    }
}
