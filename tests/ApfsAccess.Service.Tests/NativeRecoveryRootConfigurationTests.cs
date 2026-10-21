using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using ApfsAccess.Service;
using Microsoft.Extensions.Configuration;

namespace ApfsAccess.Service.Tests;

public sealed class NativeRecoveryRootConfigurationTests
{
    [Theory]
    [InlineData("local")]
    [InlineData("service-environment")]
    [InlineData("command-line")]
    [InlineData("process-environment")]
    public void RealProvidersSelectRecoveryBeforeNativeChildEnvironment(string selection)
    {
        using var roots = new RecoveryRoots();
        var paths = new[] { "stock", "local", "service-environment", "command-line", "process-environment" }
            .ToDictionary(key => key, key => Path.Combine(roots.Root, key));
        foreach (var path in paths.Values) Directory.CreateDirectory(path);
        var marker = Path.Combine(paths["local"], "original.state");
        byte[] original = [31, 0, 255, 17];
        File.WriteAllBytes(marker, original);
        var stock = Path.Combine(roots.Root, "appsettings.json");
        var local = Path.Combine(roots.Root, "local-settings.json");
        File.WriteAllText(stock, JsonSerializer.Serialize(new { Service = new { NativeRecoveryRoot = paths["stock"] } }));
        File.WriteAllText(local, JsonSerializer.Serialize(new { Service = new { NativeRecoveryRoot = paths["local"] } }));
        Environment.SetEnvironmentVariable("Service__NativeRecoveryRoot",
            selection == "service-environment" ? paths[selection] : null);
        Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT",
            selection == "process-environment" ? paths[selection] : null);
        var builder = new ConfigurationBuilder().AddJsonFile(stock, optional: false, reloadOnChange: false)
            .AddJsonFile(local, optional: true, reloadOnChange: false).AddEnvironmentVariables();
        if (selection is "command-line" or "process-environment")
            builder.AddCommandLine(["--Service:NativeRecoveryRoot", paths["command-line"]]);
        using var configuration = (ConfigurationRoot)builder.Build();

        ApplyRecovery(configuration);

        Assert.Equal(paths[selection], Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT"));
        var child = new ProcessStartInfo("not-launched-native-owner.exe").Environment;
        Assert.Equal(paths[selection], child["APFSACCESS_RECOVERY_ROOT"]);
        Assert.Equal(original, File.ReadAllBytes(marker));
        Assert.False(Directory.Exists(Path.Combine(roots.Root, "recovery")));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void MissingRecoveryChoiceDoesNotCreateOrSelectReplacementRoot(string? value)
    {
        using var roots = new RecoveryRoots();
        Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", value);
        Environment.SetEnvironmentVariable("Service__NativeRecoveryRoot", null);
        using var configuration = (ConfigurationRoot)new ConfigurationBuilder()
            .AddJsonFile(Path.Combine(roots.Root, "absent-local-settings.json"), optional: true, reloadOnChange: false)
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Service:NativeRecoveryRoot"] = value }).Build();
        var before = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT");

        ApplyRecovery(configuration);

        Assert.Equal(before, Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT"));
        Assert.Empty(Directory.GetFileSystemEntries(roots.Root));
    }

    [Fact]
    public void ExplicitProcessRecoveryDoesNotEvaluateInvalidLowerPrioritySetting()
    {
        using var roots = new RecoveryRoots();
        var retained = Path.Combine(roots.Root, "retained");
        Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", retained);
        using var configuration = (ConfigurationRoot)new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["Service:NativeRecoveryRoot"] = "invalid\0root" }).Build();

        ApplyRecovery(configuration);

        Assert.Equal(retained, Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT"));
        Assert.Empty(Directory.GetFileSystemEntries(roots.Root));
    }

    [Fact]
    public void InvalidExplicitSettingRefusesWithoutReplacingRecoveryOrCreatingFallback()
    {
        using var roots = new RecoveryRoots();
        Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", null);
        using var configuration = (ConfigurationRoot)new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["Service:NativeRecoveryRoot"] = "invalid\0root" }).Build();

        var failure = Assert.Throws<TargetInvocationException>(() => ApplyRecovery(configuration));

        Assert.IsAssignableFrom<ArgumentException>(failure.InnerException);
        Assert.Null(Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT"));
        Assert.Empty(Directory.GetFileSystemEntries(roots.Root));
    }

    private static void ApplyRecovery(IConfiguration configuration)
    {
        var program = typeof(ServiceOptionsBinding).Assembly.GetType("Program", throwOnError: true)!;
        var method = Assert.Single(program.GetMethods(BindingFlags.NonPublic | BindingFlags.Static),
            candidate => candidate.Name.Contains("g__ConfigureNativeRecoveryRoot|", StringComparison.Ordinal));
        method.Invoke(null, [configuration]);
    }

    private sealed class RecoveryRoots : IDisposable
    {
        private readonly Dictionary<string, string?> _previous = new[] { "APFSACCESS_RECOVERY_ROOT", "Service__NativeRecoveryRoot" }
            .ToDictionary(key => key, Environment.GetEnvironmentVariable);
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "ApfsAccessRecoveryConfig", Guid.NewGuid().ToString("N"));
        internal RecoveryRoots() => Directory.CreateDirectory(Root);
        public void Dispose()
        {
            foreach (var key in _previous.Keys) Environment.SetEnvironmentVariable(key, _previous[key]);
            Directory.Delete(Root, recursive: true);
        }
    }
}
