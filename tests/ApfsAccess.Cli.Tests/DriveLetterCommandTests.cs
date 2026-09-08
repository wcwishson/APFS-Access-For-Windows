using ApfsAccess.Ipc;
namespace ApfsAccess.Cli.Tests;

public sealed class DriveLetterCommandTests
{
    private static string[] Args(string letter = "t") => ["--device-id", "exact-device", "--volume-id", "exact-volume", "--volume-uuid", "fbda2042-9e07-420e-aea1-eafefed58643", "--letter", letter];
    [Fact]
    public async Task SendsExactIdentityAndNormalizedLetter()
    {
        DriveLetterPreferenceRequestPayload? sent = null;
        Assert.Equal(0, await DriveLetterCommand.RunAsync(Args(), request => {
            sent = request; return Task.FromResult(new AckPayload(true, "Saved"));
        }));
        Assert.Equal(new("exact-device", "exact-volume", "fbda2042-9e07-420e-aea1-eafefed58643", "T"), sent);
    }
    [Theory]
    [InlineData("T:")]
    [InlineData("TT")]
    [InlineData("1")]
    [InlineData("")]
    public async Task RejectsInvalidLetterBeforeTransport(string letter)
        => Assert.Equal(2, await DriveLetterCommand.RunAsync(Args(letter), _ => throw new Exception("Transport must not run")));
    [Fact]
    public async Task RejectsMissingUuidAndDuplicateArguments()
    {
        Assert.Equal(2, await DriveLetterCommand.RunAsync(["--letter", "T"], _ => throw new Exception()));
        Assert.Equal(2, await DriveLetterCommand.RunAsync([..Args(), "--letter", "R"], _ => throw new Exception()));
    }
    [Fact]
    public async Task StorageFailureAndStaleIdentityAreNonzero()
    {
        foreach (var code in new[] { "preference-storage-failed", "ambiguous-target", "missing-volume" })
            Assert.Equal(1, await DriveLetterCommand.RunAsync(Args(), _ => Task.FromResult(new AckPayload(false, "Refused", code))));
    }
    [Fact]
    public async Task TimeoutIsNotSuccess()
        => Assert.Equal(3, await DriveLetterCommand.RunAsync(Args(), _ => throw new OperationCanceledException()));
}
