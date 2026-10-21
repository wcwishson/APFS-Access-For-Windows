using ApfsAccess.Ipc;
using Xunit;

namespace ApfsAccess.Cli.Tests;

public sealed class AuthenticatedPrivateEndpointTests
{
    [Theory]
    [InlineData("arbitrary", 2)]
    [InlineData("authenticated", 3)]
    public async Task ProductionEntryKeepsArbitraryMutationPipesRefusedAndAuthenticatedPrivateRoutesConnect(string kind, int expected)
    {
        var pipe = kind == "authenticated" ? FusionControlEndpoint.ForPrivateInstance(Guid.NewGuid()) : "backup-custom-" + Guid.NewGuid().ToString("N");
        var code = await Program.Main(["quit", "--operation-id", Guid.NewGuid().ToString("D"),
            "--pipe-name", pipe, "--no-start-service", "--timeout-ms", "250"]);
        Assert.Equal(expected, code);
    }
}
