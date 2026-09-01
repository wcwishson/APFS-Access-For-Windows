using System.Diagnostics;
using System.Text.Json;

public static class StartupHook
{
    public static void Initialize()
    {
        var marker = Environment.GetEnvironmentVariable("APFSACCESS_TEST_STARTUP_HOOK_MARKER");
        if (!string.IsNullOrWhiteSpace(marker))
        {
            File.WriteAllText(marker, "loaded");
        }
    }
}

namespace ApfsAccess.Cli.Tests
{
public sealed class ProgramArgumentSecurityTests
{
    private static readonly string ArtifactRoot = Path.Combine(
        Path.GetTempPath(),
        "ApfsAccessTests",
        "ProgramArgumentSecurity");

    public static TheoryData<string[]> RejectedCustomPipeArguments => new()
    {
        new[] { "status", "--pipe-name", NewPipeName("Elevate"), "--no-start-service", "--elevate" },
        new[] { "status", "--pipe-name", NewPipeName("RequireAdmin"), "--no-start-service", "--require-admin" },
        new[] { "mount", "--device-id", "device-a", "--volume-id", "device-a|volume", "--pipe-name", NewPipeName("Mount"), "--no-start-service" },
        new[] { "fix", "--device-id", "device-a", "--volume-id", "device-a|volume", "--pipe-name", NewPipeName("Fix"), "--no-start-service" },
        new[] { "eject", "--device-id", "device-a", "--volume-id", "device-a|volume", "--pipe-name", NewPipeName("Eject"), "--no-start-service" },
        new[] { "quit", "--pipe-name", NewPipeName("Quit"), "--no-start-service" },
        new[] { "cancel", "--operation-id", Guid.NewGuid().ToString("D"), "--pipe-name", NewPipeName("Cancel"), "--no-start-service" },
    };

    [Fact]
    public async Task PublicExecutableRequiresNoStartServiceForCustomPipe()
    {
        var result = await InvokeExecutableAsync("version", "--pipe-name", NewPipeName("NoNoStart"));

        Assert.Equal(2, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal("invalid-arguments", json.RootElement.GetProperty("errorCode").GetString());
    }

    [Theory]
    [MemberData(nameof(RejectedCustomPipeArguments))]
    public async Task PublicExecutableRejectsUnsafeCustomPipeArguments(string[] arguments)
    {
        var result = await InvokeExecutableAsync(arguments);

        Assert.Equal(2, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("invalid-arguments", json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task PublicMainDoesNotTrustAnAlternateEntryAssemblyForCustomPipeMutations()
    {
        var exitCode = await Program.Main(
        [
            "mount",
            "--device-id", "device-a",
            "--volume-id", "device-a|volume",
            "--pipe-name", NewPipeName("AlternateEntry"),
            "--no-start-service",
            "--timeout-ms", "50",
        ]);

        Assert.Equal(2, exitCode);
    }

    [Theory]
    [InlineData("status")]
    [InlineData("mount")]
    public async Task PublicExecutableKeepsReadOnlyAndDryRunCustomPipeTests(string command)
    {
        var arguments = command == "mount"
            ? new[]
            {
                "mount", "--device-id", "device-a", "--volume-id", "device-a|volume", "--dry-run",
                "--pipe-name", NewPipeName("DryRun"), "--no-start-service", "--timeout-ms", "250",
            }
            : new[]
            {
                "status", "--pipe-name", NewPipeName("ReadOnly"), "--no-start-service", "--timeout-ms", "250",
            };

        var result = await InvokeExecutableAsync(arguments);

        Assert.Equal(3, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal("service-unavailable", json.RootElement.GetProperty("errorCode").GetString());
    }

    private static async Task<ProcessResult> InvokeExecutableAsync(params string[] arguments)
    {
        Directory.CreateDirectory(ArtifactRoot);
        var executable = Path.Combine(Path.GetDirectoryName(typeof(Program).Assembly.Location)!, "ApfsAccess.Cli.exe");
        var startInfo = new ProcessStartInfo(executable)
        {
            WorkingDirectory = Path.GetDirectoryName(executable)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not launch the CLI argument test process.");
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        var output = await outputTask;
        var error = await errorTask;
        Assert.True(string.IsNullOrEmpty(error), error);
        return new ProcessResult(process.ExitCode, output);
    }

    private static string NewPipeName(string purpose)
        => $"ApfsAccess.Cli.Security.{purpose}.{Guid.NewGuid():N}";

    private sealed record ProcessResult(int ExitCode, string Output);
}
}
