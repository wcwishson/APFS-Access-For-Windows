using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class SnapshotControlCommandTests
{
    private static readonly string[] Identity =
        ["21", "victim", "249", "17", "230", "8293", "8", "250", "20"];

    [Fact]
    public void ParseCreateRequiresDeviceVolumeAndName()
    {
        var options = SnapshotControlCommand.Parse(
            ["create", "--device-id", "device-1", "--volume-id", "device-1|Main", "--name", "backup"]);
        Assert.Equal("create", options.Action);
        Assert.Equal("device-1", options.DeviceId);
        Assert.Equal("device-1|Main", options.VolumeId);
        Assert.Equal("backup", options.SnapshotName);
        Assert.Null(options.SnapshotIdentity);
        Assert.True(Guid.TryParseExact(options.OperationId, "D", out _));
    }

    [Fact]
    public void ParseDeleteCapturesNineIdentityFieldsInOrder()
    {
        var args = new List<string> { "delete", "--device-id", "device-1", "--volume-id", "device-1|Main" };
        string[] flags =
        [
            "--snapshot-xid", "--snapshot-name", "--superblock-block", "--omap-block",
            "--omap-tree-block", "--root-oid", "--root-block", "--extentref-block", "--source-xid",
        ];
        for (var i = 0; i < flags.Length; i++)
        {
            args.Add(flags[i]);
            args.Add(Identity[i]);
        }

        var options = SnapshotControlCommand.Parse([.. args]);
        Assert.Equal("delete", options.Action);
        Assert.Null(options.SnapshotName);
        Assert.Equal(Identity, options.SnapshotIdentity);
    }

    [Fact]
    public void ParseRecoverRequiresOnlyDeviceAndVolume()
    {
        var options = SnapshotControlCommand.Parse(
            ["recover", "--device-id", "device-1", "--volume-id", "device-1|Main"]);
        Assert.Equal("recover", options.Action);
        Assert.Null(options.SnapshotName);
        Assert.Null(options.SnapshotIdentity);
    }

    [Theory]
    [InlineData("frobnicate")]
    [InlineData("list")]
    public void ParseRejectsUnknownActions(string action)
    {
        Assert.Throws<ArgumentException>(() =>
            SnapshotControlCommand.Parse([action, "--device-id", "d", "--volume-id", "v"]));
    }

    [Theory]
    [InlineData("create")]
    [InlineData("delete")]
    [InlineData("recover")]
    public void ParseRejectsMissingDeviceOrVolume(string action)
    {
        Assert.Throws<ArgumentException>(() => SnapshotControlCommand.Parse([action, "--volume-id", "v"]));
        Assert.Throws<ArgumentException>(() => SnapshotControlCommand.Parse([action, "--device-id", "d"]));
    }

    [Fact]
    public void ParseRejectsDuplicateOptions()
    {
        Assert.Throws<ArgumentException>(() => SnapshotControlCommand.Parse(
            ["create", "--device-id", "a", "--device-id", "b", "--volume-id", "v", "--name", "n"]));
    }

    [Fact]
    public void ParseRejectsMismatchedParameters()
    {
        Assert.Throws<ArgumentException>(() => SnapshotControlCommand.Parse(
            ["create", "--device-id", "d", "--volume-id", "v"]));
        Assert.Throws<ArgumentException>(() => SnapshotControlCommand.Parse(
            ["create", "--device-id", "d", "--volume-id", "v", "--name", "n", "--snapshot-xid", "21"]));
        Assert.Throws<ArgumentException>(() => SnapshotControlCommand.Parse(
            ["delete", "--device-id", "d", "--volume-id", "v", "--snapshot-xid", "21"]));
        Assert.Throws<ArgumentException>(() => SnapshotControlCommand.Parse(
            ["recover", "--device-id", "d", "--volume-id", "v", "--name", "n"]));
    }

    [Fact]
    public void ParseRejectsNonCanonicalOperationId()
    {
        Assert.Throws<ArgumentException>(() => SnapshotControlCommand.Parse(
            ["recover", "--device-id", "d", "--volume-id", "v", "--operation-id", "not-a-guid"]));
        var options = SnapshotControlCommand.Parse(
            ["recover", "--device-id", "d", "--volume-id", "v", "--operation-id", "00000000-0000-0000-0000-000000000001"]);
        Assert.Equal("00000000-0000-0000-0000-000000000001", options.OperationId);
    }

    [Fact]
    public async Task RunAsyncRefusesInvalidArgumentsBeforeConnecting()
    {
        Assert.Equal(2, await SnapshotControlCommand.RunAsync(["create", "--device-id", "d"]));
        Assert.Equal(2, await SnapshotControlCommand.RunAsync(["bogus"]));
    }

    private static async Task<(int Exit, System.Text.Json.JsonElement Json)> RunEnvelopeAsync(string[] args)
    {
        var previous = Console.Out; using var output = new StringWriter();
        try { Console.SetOut(output); var exit = await SnapshotControlCommand.RunAsync(args); return (exit, System.Text.Json.JsonDocument.Parse(output.ToString()).RootElement.Clone()); }
        finally { Console.SetOut(previous); }
    }

    [Fact]
    public async Task ArgumentErrorEmitsSchema2EnvelopeWithFreshOperationId()
    {
        var (exit, json) = await RunEnvelopeAsync(["create", "--device-id", "d"]);
        Assert.Equal(2, exit);
        Assert.Equal(2, json.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("snapshots", json.GetProperty("command").GetString());
        Assert.True(Guid.TryParseExact(json.GetProperty("operationId").GetString(), "D", out _));
        Assert.False(json.GetProperty("success").GetBoolean());
        Assert.Equal(2, json.GetProperty("exitCode").GetInt32());
        Assert.Contains("snapshots create", json.GetProperty("usage").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ArgumentErrorEchoesSuppliedCanonicalOperationId()
    {
        const string supplied = "01234567-89ab-cdef-0123-456789abcdef";
        var (exit, json) = await RunEnvelopeAsync(["recover", "--device-id", "d", "--operation-id", supplied]);
        Assert.Equal(2, exit);
        Assert.Equal(supplied, json.GetProperty("operationId").GetString());
        Assert.Equal("invalid-arguments", json.GetProperty("code").GetString());
    }

    [Fact]
    public async Task CapabilitiesAndHelpAdvertiseSnapshotControlUsage()
    {
        Assert.Equal(0, await Program.RunForTestAsync(["capabilities"]));
        Assert.Equal(0, await Program.RunForTestAsync(["help"]));
    }

    [Theory]
    [InlineData("snapshot-create", "snapshot-created")]
    [InlineData("snapshot-delete", "snapshot-deleted")]
    [InlineData("snapshot-recover", "snapshot-recovered")]
    [InlineData("snapshot-recover", "snapshot-recover-noop")]
    public void TerminalProofRecognizesProvenSnapshotResults(string command, string finalStatus)
    {
        var target = new ApfsControlTarget("device-1", "device-1|Main");
        var request = command == "snapshot-delete"
            ? new ControlOperationRequestPayload(
                Guid.NewGuid().ToString("D"), command, target, ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2), SnapshotIdentity: Identity)
            : command == "snapshot-create"
            ? new ControlOperationRequestPayload(
                Guid.NewGuid().ToString("D"), command, target, ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2), SnapshotName: "backup")
            : new ControlOperationRequestPayload(
                Guid.NewGuid().ToString("D"), command, target, ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2));
        var now = DateTime.UtcNow;
        var result = new OperationResultPayload(
            request.OperationId, command, target, ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
            now.AddSeconds(-1), now, now, FinalStatus: finalStatus,
            MountProof: "present", OwnershipProof: "proven", DurabilityProof: "not-applicable",
            ExpiresAtUtc: request.ExpiresAtUtc,
            SnapshotName: request.SnapshotName, SnapshotIdentity: request.SnapshotIdentity);
        var validate = typeof(Program).GetMethod(
            "HasVerifiedTerminalSuccess",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.True((bool)validate!.Invoke(null, [result])!);
        Assert.False((bool)validate.Invoke(null, [result with { OwnershipProof = "not-proven" }])!);
        Assert.False((bool)validate.Invoke(null, [result with { FinalStatus = "healthy-rw" }])!);
    }
}
