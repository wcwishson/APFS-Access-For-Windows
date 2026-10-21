using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

namespace ApfsAccess.Tray.Tests;

[CollectionDefinition("PortableRuntimeEnvironment", DisableParallelization = true)]
public sealed class PortableRuntimeEnvironmentCollection
{
}

[Collection("PortableRuntimeEnvironment")]
public sealed class PortableRuntimeEnvironmentTests
{
    [Theory]
    [InlineData("Bootstrap", null)]
    [InlineData("Bootstrap", "")]
    [InlineData("Bootstrap", "   ")]
    [InlineData("Bootstrap", "original")]
    [InlineData("Tray", null)]
    [InlineData("Tray", "")]
    [InlineData("Tray", "   ")]
    [InlineData("Tray", "original")]
    public void RealRuntimeSetupPreservesExplicitSpoolAndRecovery(string program, string? spoolSetting)
    {
        using var roots = new RuntimeRoots();
        Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", roots.Runtime);
        Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", roots.Recovery);
        Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT",
            spoolSetting == "original" ? Path.Combine(roots.Spool, ".") : spoolSetting);

        InvokeRuntimeSetup(program);

        var expectedSpool = spoolSetting == "original" ? roots.Spool : Path.Combine(roots.Runtime, "payload-spool");
        Assert.Equal(expectedSpool, Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT"));
        Assert.Equal(roots.Recovery, Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT"));
        Assert.Equal(Path.Combine(roots.Runtime, "temp"), Environment.GetEnvironmentVariable("TEMP"));
        Assert.True(Directory.Exists(expectedSpool));
        Assert.Equal(spoolSetting != "original", Directory.Exists(Path.Combine(roots.Runtime, "payload-spool")));

        if (spoolSetting == "original")
        {
            var secondRuntime = Path.Combine(roots.Root, "second-runtime");
            Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", secondRuntime);
            InvokeRuntimeSetup(program);
            Assert.False(Directory.Exists(Path.Combine(secondRuntime, "payload-spool")));
            Assert.Equal(roots.Spool, Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT"));
        }

        var inherited = new ProcessStartInfo("not-launched.exe").Environment;
        Assert.Equal(expectedSpool, inherited["APFSACCESS_SPOOL_ROOT"]);
        Assert.Equal(roots.Recovery, inherited["APFSACCESS_RECOVERY_ROOT"]);
        roots.AssertOriginalBytes();
    }

    [Fact]
    public void RealElevationHandoffPreservesRootsThroughTrayAndServiceEnvironment()
    {
        using var roots = new RuntimeRoots();
        Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", roots.Runtime);
        Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", roots.Spool);
        Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", roots.Recovery);
        Environment.SetEnvironmentVariable("APFSACCESS_ROOT_TEST_UNLISTED", "original");
        InvokeRuntimeSetup("Bootstrap");

        var tray = typeof(ApfsAccess.Tray.Program);
        var write = RequiredMethod(tray, "WriteElevatedEnvironmentFile");
        var path = Assert.IsType<string>(write.Invoke(null, null));
        Assert.Equal(roots.Runtime, Path.GetDirectoryName(path));
        var handoff = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(path))!;
        Assert.Equal(roots.Recovery, handoff["APFSACCESS_RECOVERY_ROOT"]);
        Assert.Equal(roots.Spool, handoff["APFSACCESS_SPOOL_ROOT"]);
        handoff["APFSACCESS_ROOT_TEST_UNLISTED"] = "injected";
        File.WriteAllText(path, JsonSerializer.Serialize(handoff));

        // Reproduce the reduced environment of the elevated child without invoking UAC or Main.
        foreach (var key in RuntimeRoots.RootKeys) Environment.SetEnvironmentVariable(key, null);
        RequiredMethod(tray, "ApplyElevatedEnvironment").Invoke(null,
            [new[] { "--apfsaccess-elevated-environment", path }]);
        Assert.False(File.Exists(path));
        Assert.Equal("original", Environment.GetEnvironmentVariable("APFSACCESS_ROOT_TEST_UNLISTED"));
        InvokeRuntimeSetup("Tray");

        Assert.False(Directory.Exists(Path.Combine(roots.Runtime, "payload-spool")));
        var service = new ProcessStartInfo("ApfsAccess.Service.exe").Environment;
        Assert.Equal(roots.Runtime, service["APFSACCESS_RUNTIME_ROOT"]);
        Assert.Equal(roots.Spool, service["APFSACCESS_SPOOL_ROOT"]);
        Assert.Equal(roots.Recovery, service["APFSACCESS_RECOVERY_ROOT"]);
        roots.AssertOriginalBytes();
    }

    private static void InvokeRuntimeSetup(string program)
    {
        var type = program == "Tray" ? typeof(ApfsAccess.Tray.Program) :
            Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "APFS Access.dll"))
                .GetType("ApfsAccess.Bootstrap.Program", throwOnError: true)!;
        RequiredMethod(type, program == "Tray" ? "ConfigurePortableRuntimeEnvironment" : "ConfigureRuntimeScratchEnvironment")
            .Invoke(null, null);
    }

    private static MethodInfo RequiredMethod(Type type, string name)
        => type.GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException($"Production startup method missing: {name}");

    private sealed class RuntimeRoots : IDisposable
    {
        internal static readonly string[] RootKeys =
            ["TEMP", "TMP", "APFSACCESS_RUNTIME_ROOT", "APFSACCESS_SPOOL_ROOT", "APFSACCESS_RECOVERY_ROOT"];
        private readonly Dictionary<string, string?> _previous = RootKeys.Append("APFSACCESS_ROOT_TEST_UNLISTED")
            .ToDictionary(key => key, Environment.GetEnvironmentVariable);
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "ApfsAccessPortableRoots", Guid.NewGuid().ToString("N"));
        internal string Runtime => Path.Combine(Root, "runtime");
        internal string Spool => Path.Combine(Root, "original-spool");
        internal string Recovery => Path.Combine(Root, "original-recovery");
        private static readonly byte[] Wal = [0, 7, 255, 4, 1];
        private static readonly byte[] Marker = [19, 9, 0, 254];

        internal RuntimeRoots()
        {
            Directory.CreateDirectory(Spool);
            Directory.CreateDirectory(Recovery);
            File.WriteAllBytes(Path.Combine(Spool, "write-ahead.wal"), Wal);
            File.WriteAllBytes(Path.Combine(Recovery, "original.state"), Marker);
        }

        internal void AssertOriginalBytes()
        {
            Assert.Equal(Wal, File.ReadAllBytes(Path.Combine(Spool, "write-ahead.wal")));
            Assert.Equal(Marker, File.ReadAllBytes(Path.Combine(Recovery, "original.state")));
        }

        public void Dispose()
        {
            foreach (var key in _previous.Keys) Environment.SetEnvironmentVariable(key, _previous[key]);
            Directory.Delete(Root, recursive: true);
        }
    }
}
