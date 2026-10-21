using System.IO.Pipes;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Cli;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class ImageRepairFixCommandTests
{
    private const string Image = @"D:\ApfsAccessScratch\Tests\cli-repair.apfsimg";
    private static readonly string Container = new('1', 32);
    private static readonly string PlanId = new('d', 64);
    private static string VolumeId => "apfs-vol:" + Container + ":101";

    private static async Task<(int Exit, JsonElement Json)> Invoke(params string[] args)
    {
        var previous = Console.Out;
        using var writer = new StringWriter();
        try
        {
            Console.SetOut(writer);
            var exit = await Program.RunForTestAsync(args);
            return (exit, JsonDocument.Parse(writer.ToString()).RootElement.Clone());
        }
        finally { Console.SetOut(previous); }
    }

    private static string[] Args(string command, string pipe) => [command, "--device-id", Image, "--volume-id", VolumeId,
        "--pipe-name", pipe, "--no-start-service", "--timeout-ms", "3000"];

    [Theory]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")]
    [InlineData("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
    public async Task InvalidApprovalFailsBeforeAnyServiceConnection(string id)
    {
        var result = await Invoke([..Args("fix", "ApfsAccess.Cli.RepairMissing." + Guid.NewGuid().ToString("N")), "--approve-image-repair", id]);
        Assert.Equal(2, result.Exit);
        Assert.Contains("--approve-image-repair", result.Json.GetProperty("message").GetString());
    }

    [Theory]
    [InlineData("status")]
    [InlineData("list")]
    [InlineData("mount")]
    [InlineData("eject")]
    [InlineData("quit")]
    [InlineData("query")]
    public async Task ApprovalIsOnlyForFix(string command)
    {
        var result = await Invoke([..Args(command, "ApfsAccess.Cli.RepairMissing." + Guid.NewGuid().ToString("N")), "--approve-image-repair", PlanId]);
        Assert.Equal(2, result.Exit);
        Assert.Contains("--approve-image-repair", result.Json.GetProperty("message").GetString());
    }

    [Fact]
    public async Task DryRunCannotCarryApproval()
    {
        var result = await Invoke([..Args("fix", "ApfsAccess.Cli.RepairMissing." + Guid.NewGuid().ToString("N")),
            "--approve-image-repair", PlanId, "--dry-run"]);
        Assert.Equal(2, result.Exit);
        Assert.Contains("--dry-run", result.Json.GetProperty("message").GetString());
    }

    [Fact]
    public async Task DuplicateApprovalCannotBeReinterpreted()
    {
        var result = await Invoke([..Args("fix", "ApfsAccess.Cli.RepairMissing." + Guid.NewGuid().ToString("N")),
            "--approve-image-repair", PlanId, "--approve-image-repair", new string('e', 64)]);
        Assert.Equal(2, result.Exit);
        Assert.Contains("once", result.Json.GetProperty("message").GetString());
    }

    [Fact]
    public async Task ExplicitApprovalReachesTheCorrelatedServiceRequest()
    {
        var name = "ApfsAccess.Cli.RepairForward." + Guid.NewGuid().ToString("N");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        ControlOperationRequestPayload? received = null;
        var server = RunService(name, control =>
        {
            received = control;
            return Failed(control);
        }, deadline.Token);
        var result = await Invoke([..Args("fix", name), "--approve-image-repair", PlanId]);
        await server;
        Assert.NotNull(received);
        Assert.Equal(PlanId, received.ApprovedImageRepairPlanId);
        Assert.Equal(Image, received.Target!.DeviceId);
        Assert.Equal(VolumeId, received.Target.VolumeId);
        Assert.Equal(5, result.Exit);
        Assert.Equal("Scripted native refusal.", result.Json.GetProperty("message").GetString());
        Assert.Equal(PlanId, result.Json.GetProperty("approvedImageRepairPlanId").GetString());
    }

    [Fact]
    public async Task DifferentApprovalEchoCannotBeAcceptedAsTheIssuedResult()
    {
        var name = "ApfsAccess.Cli.RepairMismatch." + Guid.NewGuid().ToString("N");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var server = RunService(name, control => Failed(control with { ApprovedImageRepairPlanId = new string('e', 64) }), deadline.Token);
        var result = await Invoke([..Args("fix", name), "--approve-image-repair", PlanId]);
        await server;
        Assert.Equal(5, result.Exit);
        Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.Contains("repair approval", result.Json.GetProperty("message").GetString());
    }

    [Fact]
    public async Task InitialOfferIsExposedWithoutAutomaticallyApprovingIt()
    {
        var name = "ApfsAccess.Cli.RepairOffer." + Guid.NewGuid().ToString("N");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var received = 0;
        var server = RunService(name, control =>
        {
            ++received;
            Assert.Null(control.ApprovedImageRepairPlanId);
            var now = DateTime.UtcNow;
            var offer = new ImageRepairOffer(PlanId, now.AddMinutes(3),
                new(Image, "apfs-container:" + Container, new string('2', 32), "101", "7", "0", "16777216"),
                "recovery-fixture", "selected-v1:" + new string('e', 64), new string('c', 64), "0",
                "windows-image-v1:" + new string('a', 48) + "00000000000000000000000001000000:100", new string('b', 64));
            return Failed(control) with { Code = ApfsOperationCodes.BlockedRecovery, FinalStatus = "repair-confirmation-required", ImageRepairOffer = offer };
        }, deadline.Token);
        var result = await Invoke(Args("fix", name));
        await server;
        Assert.Equal(9, result.Exit);
        Assert.Equal(1, received);
        Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.Equal(PlanId, result.Json.GetProperty("imageRepairOffer").GetProperty("planId").GetString());
        Assert.Equal("0", result.Json.GetProperty("imageRepairOffer").GetProperty("expectedCount").GetString());
    }

    [Fact]
    public async Task PlainFixAcceptsCorrelatedOriginalRecoveryWithoutChangingItsRequestFingerprint()
    {
        var name = "ApfsAccess.Cli.RepairResume." + Guid.NewGuid().ToString("N");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var originalId = Guid.NewGuid().ToString("D");
        var server = RunService(name, control =>
        {
            Assert.Null(control.ApprovedImageRepairPlanId);
            var binding = new ImageRepairOffer(PlanId, DateTime.UtcNow.AddMinutes(-1),
                new(Image, "apfs-container:" + Container, new string('2', 32), "101", "7", "0", "16777216"),
                "recovery-fixture", "selected-v1:" + new string('e', 64), new string('c', 64), "0",
                "windows-image-v1:" + new string('a', 48) + "00000000000000000000000001000000:100", new string('b', 64));
            return Failed(control) with
            {
                State = ApfsOperationStates.Succeeded, Code = ApfsOperationCodes.OperationSucceeded, Success = true,
                FinalStatus = "healthy-rw", EffectiveMode = ApfsControlModes.ReadWrite, RecoveryState = "inactive",
                MountProof = "present", OwnershipProof = "not-applicable", DurabilityProof = "not-applicable",
                ImageRepairReceipt = new(PlanId, "repaired", binding, @"D:\journal\original.rct2", @"D:\journal\evidence",
                    "RepairedAndVerified", 0, Replayed: true, NativePostVerifyComplete: true, OriginalAcceptedOperationId: originalId),
            };
        }, deadline.Token);
        var result = await Invoke(Args("fix", name));
        await server;
        Assert.Equal(0, result.Exit);
        Assert.True(result.Json.GetProperty("success").GetBoolean());
        Assert.False(result.Json.TryGetProperty("approvedImageRepairPlanId", out _));
        Assert.Equal(originalId, result.Json.GetProperty("imageRepairReceipt").GetProperty("originalAcceptedOperationId").GetString());
    }

    private static OperationResultPayload Failed(ControlOperationRequestPayload request)
    {
        var now = DateTime.UtcNow;
        return new(request.OperationId, request.Command, request.Target, ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Failed, ApfsOperationCodes.OperationFailed, false, now, now, now,
            FinalStatus: "failed", MountProof: "not-proven", OwnershipProof: "not-proven", DurabilityProof: "not-proven",
            Diagnostic: "Scripted native refusal.", ExpiresAtUtc: request.ExpiresAtUtc,
            ApprovedImageRepairPlanId: request.ApprovedImageRepairPlanId);
    }

    private static async Task RunService(string name, Func<ControlOperationRequestPayload, OperationResultPayload> respond, CancellationToken token)
    {
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await server.WaitForConnectionAsync(token);
        await using var peer = new PipePeer(server);
        await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged,
            new StatusChangedPayload(RuntimeState.Idle, [], null, DateTime.UtcNow, [], false, [])), token);
        var envelope = await peer.ReadMessageAsync(token);
        Assert.NotNull(envelope);
        Assert.True(PipeMessageCodec.Validate(envelope).IsValid);
        Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(envelope, out var request));
        var response = respond(request!);
        await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, response, request!.OperationId, PipeSchemaVersions.Schema2), token);
    }
}
