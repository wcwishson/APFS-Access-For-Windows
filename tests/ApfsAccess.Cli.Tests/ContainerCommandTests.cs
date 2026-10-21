using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class ContainerCommandTests
{
    private const string DeviceId = "device-1";
    private const string ContainerId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Theory]
    [InlineData(@"\\.\PhysicalDrive2")]
    [InlineData(@"\\.\physicaldrive2")]
    public void ParseNativeDevicePathRoundTripsControlRequest(string device)
    {
        var options = ContainerCommand.Parse(["container-unmount", "--device-id", device, "--container-id", ContainerId]);
        Assert.Equal(device, options.DeviceId);
        var request = new ControlOperationRequestPayload(options.OperationId, ApfsControlCommands.ContainerUnmount,
            new(options.DeviceId, "", ContainerUuid: options.ContainerId), ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2));
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2);
        Assert.True(PipeMessageCodec.Validate(envelope).IsValid);
        Assert.True(PipeMessageCodec.TryDeserialize(PipeMessageCodec.Serialize(envelope), out var decoded));
        Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(decoded!, out var actual));
        Assert.Equal(device, actual!.Target!.DeviceId);
        Assert.Equal(18, actual.Target.DeviceId.Length);
        Assert.Equal(ApfsOperationFingerprint.Compute(request), ApfsOperationFingerprint.Compute(actual));
    }

    [Fact]
    public void ParseMountRequiresDeviceContainerAndMode()
    {
        var options = ContainerCommand.Parse(
            ["container-mount", "--device-id", DeviceId, "--container-id", ContainerId, "--mode", "read-write"]);
        Assert.Equal("container-mount", options.Action);
        Assert.Equal(DeviceId, options.DeviceId);
        Assert.Equal(ContainerId, options.ContainerId);
        Assert.Equal(ApfsControlModes.ReadWrite, options.RequestedMode);
        Assert.False(options.DryRun);
        Assert.True(Guid.TryParseExact(options.OperationId, "D", out _));
    }

    [Fact]
    public void ParseMountCanonicalizesModeAndContainerId()
    {
        var options = ContainerCommand.Parse(
            ["container-mount", "--device-id", DeviceId, "--container-id", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "--mode", "RO"]);
        Assert.Equal(ApfsControlModes.ReadOnly, options.RequestedMode);
        Assert.Equal(ContainerId, options.ContainerId);
    }

    [Theory]
    [InlineData("container-mount")]
    [InlineData("container-unmount")]
    [InlineData("container-verify")]
    [InlineData("container-manage")]
    public void CommonNoStartServiceOptionPreservesSelectorsAndRequestIdentity(string action)
    {
        const string operationId = "01234567-89ab-cdef-0123-456789abcdef";
        string[] args = [action, "--device-id", DeviceId, "--container-id", ContainerId,
            "--operation-id", operationId];
        if (action == "container-mount") args = [.. args, "--mode", "read-write"];
        var expected = ContainerCommand.Parse(args);
        Assert.Equal(expected, ContainerCommand.Parse([.. args, "--no-start-service"]));
        Assert.Equal(expected, ContainerCommand.Parse([action, "--NO-START-SERVICE", .. args[1..]]));
        Assert.Throws<ArgumentException>(() => ContainerCommand.Parse(
            [.. args, "--no-start-service", "--NO-START-SERVICE"]));
    }

    [Theory]
    [InlineData("container-manage")]
    public async Task CommonNoStartServiceOptionReachesActionInsteadOfArgumentRefusal(string action)
    {
        var (exit, json) = await RunEnvelopeAsync(
            [action, "--device-id", DeviceId, "--container-id", ContainerId, "--no-start-service"]);
        Assert.Equal(3, exit);
        Assert.Equal("service-unavailable", json.GetProperty("code").GetString());
    }

    [Fact]
    public void ParseUnmountForbidsMode()
    {
        var options = ContainerCommand.Parse(
            ["container-unmount", "--device-id", DeviceId, "--container-id", ContainerId]);
        Assert.Equal("container-unmount", options.Action);
        Assert.Null(options.RequestedMode);
        Assert.Throws<ArgumentException>(() => ContainerCommand.Parse(
            ["container-unmount", "--device-id", DeviceId, "--container-id", ContainerId, "--mode", "read-only"]));
    }

    [Fact]
    public void ParseVerifyAndManageTakeDeviceAndContainerWithNoMode()
    {
        foreach (var action in new[] { "container-verify", "container-manage" })
        {
            var options = ContainerCommand.Parse(
                [action, "--device-id", DeviceId, "--container-id", ContainerId]);
            Assert.Equal(action, options.Action);
            Assert.Equal(DeviceId, options.DeviceId);
            Assert.Equal(ContainerId, options.ContainerId);
            Assert.Null(options.RequestedMode);
        }
        Assert.Throws<ArgumentException>(() => ContainerCommand.Parse(
            ["container-verify", "--device-id", DeviceId, "--container-id", ContainerId, "--mode", "read-only"]));
        Assert.Throws<ArgumentException>(() => ContainerCommand.Parse(
            ["container-manage", "--device-id", DeviceId]));
    }

    [Theory]
    [InlineData("container-manage", "unbound atomic container change")]
    public async Task UnavailableLiveActionsRefuseClosedWithStableEnvelope(string action, string marker)
    {
        var (exit, json) = await RunEnvelopeAsync([action, "--device-id", DeviceId, "--container-id", ContainerId]);
        Assert.Equal(3, exit);
        Assert.Equal(2, json.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(action, json.GetProperty("command").GetString());
        Assert.True(Guid.TryParseExact(json.GetProperty("operationId").GetString(), "D", out _));
        Assert.False(json.GetProperty("success").GetBoolean());
        Assert.Equal(3, json.GetProperty("exitCode").GetInt32());
        Assert.Equal("service-unavailable", json.GetProperty("code").GetString());
        Assert.Contains(marker, json.GetProperty("message").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("frobnicate")]
    [InlineData("mount")]
    public void ParseRejectsUnknownActions(string action)
    {
        Assert.Throws<ArgumentException>(() =>
            ContainerCommand.Parse([action, "--device-id", DeviceId, "--container-id", ContainerId]));
    }

    [Fact]
    public void ParseRejectsMissingSelectorsAndDuplicates()
    {
        Assert.Throws<ArgumentException>(() => ContainerCommand.Parse(
            ["container-mount", "--container-id", ContainerId, "--mode", "read-write"]));
        Assert.Throws<ArgumentException>(() => ContainerCommand.Parse(
            ["container-mount", "--device-id", DeviceId, "--mode", "read-write"]));
        Assert.Throws<ArgumentException>(() => ContainerCommand.Parse(
            ["container-mount", "--device-id", DeviceId, "--container-id", ContainerId, "--mode", "read-write", "--mode", "read-only"]));
        Assert.Throws<ArgumentException>(() => ContainerCommand.Parse(
            ["container-mount", "--device-id", DeviceId, "--container-id", ContainerId, "--mode", "sometimes"]));
    }

    [Fact]
    public void ParseRejectsNonCanonicalOperationId()
    {
        Assert.Throws<ArgumentException>(() => ContainerCommand.Parse(
            ["container-unmount", "--device-id", DeviceId, "--container-id", ContainerId, "--operation-id", "not-a-guid"]));
        var options = ContainerCommand.Parse(
            ["container-unmount", "--device-id", DeviceId, "--container-id", ContainerId, "--operation-id", "00000000-0000-0000-0000-000000000001"]);
        Assert.Equal("00000000-0000-0000-0000-000000000001", options.OperationId);
    }

    [Fact]
    public async Task RunAsyncRefusesInvalidArgumentsBeforeConnecting()
    {
        Assert.Equal(2, await ContainerCommand.RunAsync(["container-mount", "--device-id", DeviceId]));
        Assert.Equal(2, await ContainerCommand.RunAsync(["bogus"]));
    }

    private static async Task<(int Exit, System.Text.Json.JsonElement Json)> RunEnvelopeAsync(string[] args)
    {
        var previous = Console.Out; using var output = new StringWriter();
        try { Console.SetOut(output); var exit = await ContainerCommand.RunAsync(args); return (exit, System.Text.Json.JsonDocument.Parse(output.ToString()).RootElement.Clone()); }
        finally { Console.SetOut(previous); }
    }

    [Fact]
    public async Task ArgumentErrorEmitsSchema2EnvelopeWithFreshOperationId()
    {
        var (exit, json) = await RunEnvelopeAsync(["container-mount", "--device-id", DeviceId]);
        Assert.Equal(2, exit);
        Assert.Equal(2, json.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("container-mount", json.GetProperty("command").GetString());
        Assert.True(Guid.TryParseExact(json.GetProperty("operationId").GetString(), "D", out _));
        Assert.False(json.GetProperty("success").GetBoolean());
        Assert.Equal(2, json.GetProperty("exitCode").GetInt32());
        Assert.Contains("container-mount", json.GetProperty("usage").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ArgumentErrorEchoesSuppliedCanonicalOperationId()
    {
        const string supplied = "01234567-89ab-cdef-0123-456789abcdef";
        var (exit, json) = await RunEnvelopeAsync(["container-unmount", "--device-id", DeviceId, "--operation-id", supplied]);
        Assert.Equal(2, exit);
        Assert.Equal(supplied, json.GetProperty("operationId").GetString());
        Assert.Equal("invalid-arguments", json.GetProperty("code").GetString());
    }

    [Theory]
    [InlineData("apfs-container:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void ContainerMatchesAcceptsPrefixedAndCaseVariants(string requested, string member)
    {
        Assert.True(ContainerCommand.ContainerMatches(requested, member));
        Assert.False(ContainerCommand.ContainerMatches(requested, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        Assert.False(ContainerCommand.ContainerMatches(null, member));
        Assert.False(ContainerCommand.ContainerMatches(requested, null));
    }

    [Fact]
    public async Task CapabilitiesAndHelpAdvertiseContainerControlUsage()
    {
        Assert.Equal(0, await Program.RunForTestAsync(["capabilities"]));
        Assert.Equal(0, await Program.RunForTestAsync(["help"]));
    }

    [Theory]
    [InlineData("container-mount", "container-mounted")]
    [InlineData("container-unmount", "container-unmounted")]
    public void TerminalProofRecognizesProvenContainerResults(string command, string finalStatus)
    {
        var target = new ApfsControlTarget(DeviceId, string.Empty, null, null, ContainerId);
        var request = command == "container-mount"
            ? new ControlOperationRequestPayload(
                Guid.NewGuid().ToString("D"), command, target, ApfsControlModes.ReadWrite,
                ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2))
            : new ControlOperationRequestPayload(
                Guid.NewGuid().ToString("D"), command, target,
                ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2));
        var now = DateTime.UtcNow;
        var result = command == "container-mount"
            ? new OperationResultPayload(
                request.OperationId, command, target, ApfsOperationFingerprint.Compute(request),
                ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
                now.AddSeconds(-1), now, now, FinalStatus: finalStatus,
                RequestedMode: request.RequestedMode, EffectiveMode: request.RequestedMode,
                MountProof: "present", OwnershipProof: "not-applicable", DurabilityProof: "not-applicable",
                ExpiresAtUtc: request.ExpiresAtUtc)
            : new OperationResultPayload(
                request.OperationId, command, target, ApfsOperationFingerprint.Compute(request),
                ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
                now.AddSeconds(-1), now, now, FinalStatus: finalStatus,
                MountProof: "absent", OwnershipProof: "proven", DurabilityProof: "proven",
                ExpiresAtUtc: request.ExpiresAtUtc);
        var validate = typeof(Program).GetMethod(
            "HasVerifiedTerminalSuccess",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.True((bool)validate!.Invoke(null, [result])!);
        Assert.False((bool)validate.Invoke(null, [result with { OwnershipProof = "not-proven" }])!);
        Assert.False((bool)validate.Invoke(null, [result with { FinalStatus = "healthy-rw" }])!);
    }
}
