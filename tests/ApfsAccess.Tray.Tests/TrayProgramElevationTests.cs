using ApfsAccess.Tray;
using System.Reflection;
using System.Text.Json;

namespace ApfsAccess.Tray.Tests;

public sealed class TrayProgramElevationTests
{
    [Fact]
    public void Program_HasAllowUnelevatedEscapeHatchForDiagnostics()
    {
        var method = typeof(Program).GetMethod("ShouldRelaunchElevated", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var previous = Environment.GetEnvironmentVariable("APFSACCESS_ALLOW_UNELEVATED");
        try
        {
            Environment.SetEnvironmentVariable("APFSACCESS_ALLOW_UNELEVATED", "1");
            var result = method!.Invoke(null, null);

            Assert.False(Assert.IsType<bool>(result));
        }
        finally
        {
            Environment.SetEnvironmentVariable("APFSACCESS_ALLOW_UNELEVATED", previous);
        }
    }

    [Fact]
    public void Program_AppliesOnlyAllowlistedElevatedEnvironmentKeysAndDeletesHandoff()
    {
        var method = typeof(Program).GetMethod("ApplyElevatedEnvironment", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var allowedKey = "APFSACCESS_TRACE_READS";
        var rejectedKey = "APFSACCESS_ELEVATION_TEST_UNLISTED";
        var previousAllowed = Environment.GetEnvironmentVariable(allowedKey);
        var previousRejected = Environment.GetEnvironmentVariable(rejectedKey);
        var path = Path.Combine(
            Path.GetTempPath(),
            $"elevation-environment-{Guid.NewGuid():N}.json");
        try
        {
            Environment.SetEnvironmentVariable(allowedKey, null);
            Environment.SetEnvironmentVariable(rejectedKey, "original");
            File.WriteAllText(path, JsonSerializer.Serialize(new Dictionary<string, string>
            {
                [allowedKey] = "1",
                [rejectedKey] = "injected",
            }));

            method!.Invoke(null, [new[] { "--apfsaccess-elevated-environment", path }]);

            Assert.Equal("1", Environment.GetEnvironmentVariable(allowedKey));
            Assert.Equal("original", Environment.GetEnvironmentVariable(rejectedKey));
            Assert.False(File.Exists(path));
        }
        finally
        {
            Environment.SetEnvironmentVariable(allowedKey, previousAllowed);
            Environment.SetEnvironmentVariable(rejectedKey, previousRejected);
            File.Delete(path);
        }
    }

    [Fact]
    public void Program_IgnoresMalformedElevatedEnvironmentAndDeletesHandoff()
    {
        var method = typeof(Program).GetMethod("ApplyElevatedEnvironment", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var path = Path.Combine(
            Path.GetTempPath(),
            $"elevation-environment-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, "{not-json");
        try
        {
            method!.Invoke(null, [new[] { "--apfsaccess-elevated-environment", path }]);
            Assert.False(File.Exists(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Program_DoesNotDeleteUnrecognizedElevationFileName()
    {
        var method = typeof(Program).GetMethod("TryDeleteElevatedEnvironmentFile", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var path = Path.Combine(Path.GetTempPath(), $"unrecognized-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, "{}");
        try
        {
            method!.Invoke(null, [path]);
            Assert.True(File.Exists(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
