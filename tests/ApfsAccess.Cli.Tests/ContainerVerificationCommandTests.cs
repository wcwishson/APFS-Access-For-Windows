using System.Text.Json;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class ContainerVerificationCommandTests
{
    [Theory]
    [InlineData("capabilities")]
    [InlineData("help")]
    public async Task AdvertisesClientBatchAndCurrentMetadataScope(string command)
    {
        var previous = Console.Out;
        using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            Assert.Equal(0, await Program.RunForTestAsync([command]));
        }
        finally { Console.SetOut(previous); }
        using var document = JsonDocument.Parse(output.ToString());
        var availability = document.RootElement.GetProperty("containerVerifyAvailability").GetString()!;
        Assert.StartsWith("available: client batch", availability);
        Assert.Contains("current metadata only", availability);
        Assert.Contains("--dry-run", document.RootElement.GetProperty("containerControlUsage").GetString());
        Assert.StartsWith("unavailable:", document.RootElement.GetProperty("containerManageAvailability").GetString());
    }

    [Theory]
    [InlineData(false, false, 0)]
    [InlineData(false, true, 5)]
    [InlineData(true, false, 0)]
    public async Task DispatchEmitsBatchIdentityPerVolumeOutcomesAndTruthfulAggregate(bool dryRun, bool failSecond, int expectedExit)
    {
        var client = new FakeContainerVerificationClient(CliContainerVerificationFixture.Status(3));
        client.Send = (r, _) => Task.FromResult(CliContainerVerificationFixture.Result(r, !failSecond || client.Requests.Count != 2));
        var options = CliContainerVerificationFixture.Options(dryRun);
        string[] args = ["container-verify", "--device-id", options.DeviceId, "--container-id", options.ContainerId,
            "--operation-id", options.OperationId, "--no-start-service"];
        if (dryRun) args = [..args, "--dry-run"];
        var previous = Console.Out;
        using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            Assert.Equal(expectedExit, await ContainerCommand.RunAsync(args, client));
        }
        finally { Console.SetOut(previous); }
        using var document = JsonDocument.Parse(output.ToString());
        var json = document.RootElement;
        Assert.Equal(2, json.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("container-verify", json.GetProperty("command").GetString());
        Assert.Equal(options.OperationId, json.GetProperty("operationId").GetString());
        Assert.Equal(options.OperationId, json.GetProperty("batchId").GetString());
        Assert.Equal(expectedExit == 0, json.GetProperty("success").GetBoolean());
        Assert.Equal(expectedExit, json.GetProperty("exitCode").GetInt32());
        Assert.Equal(!dryRun, json.GetProperty("operationIssued").GetBoolean());
        Assert.Equal("client-batch", json.GetProperty("execution").GetString());
        Assert.False(json.GetProperty("atomicContainerVerification").GetBoolean());
        Assert.Contains("current metadata only", json.GetProperty("scope").GetString());
        var states = json.GetProperty("volumes").EnumerateArray().Select(v => v.GetProperty("state").GetString()).ToArray();
        Assert.Equal(dryRun ? ["NotAttempted", "NotAttempted", "NotAttempted"] : failSecond ?
            ["Verified", "Failed", "NotAttempted"] : ["Verified", "Verified", "Verified"], states);
        Assert.Equal(dryRun ? 0 : failSecond ? 2 : 3, client.Requests.Count);
    }

    [Fact]
    public async Task ManageRemainsLocalUnavailableEvenWithBatchClientAvailable()
    {
        var client = new FakeContainerVerificationClient(CliContainerVerificationFixture.Status());
        Assert.Equal(3, await ContainerCommand.RunAsync(["container-manage", "--device-id", CliContainerVerificationFixture.Image,
            "--container-id", CliContainerVerificationFixture.Hex], client));
        Assert.Equal(0, client.StatusReads);
        Assert.Empty(client.Requests);
    }
}
