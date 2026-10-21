using ApfsAccess.Backend.Native;
using System.Text;
using System.Text.Json;
using ApfsAccess.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class ServiceOptionsBindingTests
{
    private static readonly string[] DefaultPool = Enumerable.Range('D', 'Z' - 'D' + 1)
        .Select(letter => ((char)letter).ToString()).ToArray();

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("original")]
    public void BootstrapPreservesRecoveryAndHonorsExplicitSpoolRoot(string? spoolSetting)
    {
        var keys = new[] { "TEMP", "TMP", "APFSACCESS_RUNTIME_ROOT", "APFSACCESS_SPOOL_ROOT", "APFSACCESS_RECOVERY_ROOT" };
        var previous = keys.ToDictionary(key => key, Environment.GetEnvironmentVariable);
        var root = Path.Combine(Path.GetTempPath(), "ApfsAccessBootstrapTests", Guid.NewGuid().ToString("N"));
        var runtime = Path.Combine(root, "runtime");
        var recovery = Path.Combine(root, "original-recovery");
        var spool = Path.Combine(root, "original-spool");
        Directory.CreateDirectory(recovery);
        Directory.CreateDirectory(spool);
        var marker = Path.Combine(recovery, "original.state");
        var wal = Path.Combine(spool, "write-ahead.wal");
        var markerBytes = Encoding.ASCII.GetBytes("original recovery marker");
        var walBytes = Encoding.ASCII.GetBytes("original WAL bytes");
        File.WriteAllBytes(marker, markerBytes);
        File.WriteAllBytes(wal, walBytes);

        try
        {
            var explicitSpool = spoolSetting == "original";
            Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", runtime);
            Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", recovery);
            Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", explicitSpool ? Path.Combine(spool, ".") : spoolSetting);
            // Invoke the real compiled bootstrap without running Main, acquiring its lease or starting a host.
            var program = typeof(ServiceOptionsBinding).Assembly.GetType("Program", throwOnError: true)!;
            var bootstrap = Assert.Single(program.GetMethods(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static),
                method => method.Name.Contains("g__ConfigurePortableRuntimeEnvironment|", StringComparison.Ordinal));
            Assert.Equal(runtime, Assert.IsType<string>(bootstrap.Invoke(null, null)));

            var expectedSpool = explicitSpool ? spool : Path.Combine(runtime, "payload-spool");
            Assert.Equal(expectedSpool, Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT"));
            Assert.Equal(recovery, Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT"));
            Assert.Equal(runtime, Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT"));
            Assert.Equal(Path.Combine(runtime, "temp"), Environment.GetEnvironmentVariable("TEMP"));
            Assert.Equal(Path.Combine(runtime, "temp"), Environment.GetEnvironmentVariable("TMP"));
            Assert.True(Directory.Exists(expectedSpool));
            Assert.Equal(!explicitSpool, Directory.Exists(Path.Combine(runtime, "payload-spool")));
            using var configuration = (ConfigurationRoot)new ConfigurationBuilder().AddInMemoryCollection().Build();
            var services = new ServiceCollection();
            var configured = ServiceOptionsBinding.Configure(services, configuration, runtime);
            using var provider = services.BuildServiceProvider();
            var journalRoot = Path.Combine(runtime, "management-journals");
            Assert.Equal(journalRoot, configured.ManagementJournalRoot);
            Assert.Equal(journalRoot, provider.GetRequiredService<IOptionsMonitor<ServiceHostOptions>>().CurrentValue.ManagementJournalRoot);
            Assert.True(Directory.Exists(journalRoot));
            NativeApfsVolumeManagement.ValidateStoreRoot(journalRoot);

            if (explicitSpool)
            {
                Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", Path.Combine(root, "second-runtime"));
                bootstrap.Invoke(null, null);
                Assert.False(Directory.Exists(Path.Combine(root, "second-runtime", "payload-spool")));
            }
            var inherited = new System.Diagnostics.ProcessStartInfo("bootstrap-inheritance-not-launched.exe").Environment;
            Assert.Equal(expectedSpool, inherited["APFSACCESS_SPOOL_ROOT"]);
            Assert.Equal(recovery, inherited["APFSACCESS_RECOVERY_ROOT"]);
            Assert.Equal(markerBytes, File.ReadAllBytes(marker));
            Assert.Equal(walBytes, File.ReadAllBytes(wal));
        }
        finally
        {
            foreach (var key in keys) Environment.SetEnvironmentVariable(key, previous[key]);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void PhysicalInventoryOptInBindsIndependentlyOfImageSnapshotsAndDefaultsOff()
    {
        using var omitted = (ConfigurationRoot)Json(new { Service = new { EnableImageSnapshots = true } }).Build();
        Assert.False(BindAndCompare(omitted).EnableRetainedPhysicalSnapshotInventory);
        using var enabled = (ConfigurationRoot)Json(new { Service = new { EnableRetainedPhysicalSnapshotInventory = true } }).Build();
        var configured = BindAndCompare(enabled);
        Assert.True(configured.EnableRetainedPhysicalSnapshotInventory); Assert.False(configured.EnableImageSnapshots);
    }

    [Fact]
    public void OmittedPoolPreservesInitializerAndOtherOptions()
    {
        using var configuration = (ConfigurationRoot)Json(new { Service = new { BackendMode = "Native", AutoMountEnabled = false, PollSeconds = 17 } }).Build();
        var options = BindAndCompare(configuration);
        Assert.Equal(DefaultPool, options.MountLetterPool);
        Assert.Equal("Native", options.BackendMode);
        Assert.False(options.AutoMountEnabled);
        Assert.Equal(17, options.PollSeconds);
    }

    [Fact]
    public void LayeredJsonNarrowPoolReplacesPackagedPoolAndChoosesM()
    {
        using var configuration = (ConfigurationRoot)Packaged().AddJsonStream(Stream(new
        {
            Service = new { MountLetterPool = new[] { "M", "N", "O", "P" }, AutoMountEnabled = false },
        })).Build();
        var options = BindAndCompare(configuration);
        Assert.Equal(new[] { "M", "N", "O", "P" }, options.MountLetterPool);
        Assert.Equal("Native", options.BackendMode);
        Assert.False(options.AutoMountEnabled);
        Assert.Equal(11, options.PollSeconds);
        Assert.Equal(new[] { "fixture.apfs.img" }, options.NativeDeviceCandidates);
        var policy = new FirstFreeMountPolicy(options.MountLetterPool);
        Assert.Equal('M', policy.SelectDriveLetter(new("test", "device", "Test", true), new HashSet<char> { 'C', 'D' }));
    }

    [Theory]
    [InlineData("environment")]
    [InlineData("command-line")]
    public void ExplicitHigherPrecedenceProviderReplacesWholePool(string provider)
    {
        var builder = Packaged().AddJsonStream(Stream(new { Service = new { MountLetterPool = new[] { "M", "N", "O", "P" } } }));
        var prefix = "APFSACCESS_BINDING_TEST_" + Guid.NewGuid().ToString("N") + "_";
        var first = prefix + "Service__MountLetterPool__0";
        var second = prefix + "Service__MountLetterPool__1";
        try
        {
            if (provider == "environment")
            {
                Environment.SetEnvironmentVariable(first, "Q");
                Environment.SetEnvironmentVariable(second, "R");
                builder.AddEnvironmentVariables(prefix);
            }
            else
            {
                builder.AddCommandLine(["--Service:MountLetterPool:0=Q", "--Service:MountLetterPool:1=R"]);
            }
            using var configuration = (ConfigurationRoot)builder.Build();
            Assert.Equal(new[] { "Q", "R" }, BindAndCompare(configuration).MountLetterPool);
        }
        finally
        {
            Environment.SetEnvironmentVariable(first, null);
            Environment.SetEnvironmentVariable(second, null);
        }
    }

    [Fact]
    public void HigherProviderWithoutPoolKeepsLastExplicitPool()
    {
        using var configuration = (ConfigurationRoot)Packaged()
            .AddJsonStream(Stream(new { Service = new { MountLetterPool = new[] { "M", "N" } } }))
            .AddCommandLine(["--Service:PollSeconds=19"])
            .Build();
        var options = BindAndCompare(configuration);
        Assert.Equal(new[] { "M", "N" }, options.MountLetterPool);
        Assert.Equal(19, options.PollSeconds);
    }

    [Fact]
    public void ExplicitEmptyPoolDoesNotResurrectLowerProviderTail()
    {
        using var configuration = (ConfigurationRoot)Packaged()
            .AddJsonStream(Stream(new { Service = new { MountLetterPool = Array.Empty<string>() } }))
            .Build();
        Assert.Empty(BindAndCompare(configuration).MountLetterPool);
    }

    [Fact]
    public void DefaultManagementRootIsSharedByFactoryAndMonitorAndSurvivesReload()
    {
        using var runtime = new BindingRuntime();
        using var configuration = (ConfigurationRoot)new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Service:BackendMode"] = "Native", ["Service:NativeAutoDiscoverPhysicalDrives"] = "false",
            ["Service:NativeWriteEvidenceStorePath"] = Path.Combine(runtime.Path, "write-evidence.json"),
        }).Build();
        var services = new ServiceCollection();
        var configured = ServiceOptionsBinding.Configure(services, configuration, runtime.Path);
        var expected = Path.Combine(runtime.Path, "management-journals");
        Assert.Equal(expected, configured.ManagementJournalRoot);
        Assert.True(Directory.Exists(expected));
        NativeApfsVolumeManagement.ValidateStoreRoot(expected);
        using var provider = services.BuildServiceProvider();
        var monitored = provider.GetRequiredService<IOptionsMonitor<ServiceHostOptions>>();
        Assert.Equal(expected, provider.GetRequiredService<IOptions<ServiceHostOptions>>().Value.ManagementJournalRoot);
        Assert.Equal(expected, monitored.CurrentValue.ManagementJournalRoot);
        using var backend = new NativeApfsBackend(configured);
        var options = typeof(NativeApfsBackend).GetField("_options", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        Assert.Equal(expected, Assert.IsType<ServiceHostOptions>(options.GetValue(backend)).ManagementJournalRoot);

        var original = Path.Combine(expected, new string('a', 64) + ".vif1");
        var bytes = Encoding.ASCII.GetBytes("unresolved original evidence");
        File.WriteAllBytes(original, bytes);
        Assert.Throws<IOException>(() => NativeManagementJournalAdmission.RequireClearRoot(expected));
        var prior = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT");
        try
        {
            Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", Path.Combine(runtime.Path, "different-runtime"));
            configuration.Reload();
            Assert.Equal(expected, monitored.CurrentValue.ManagementJournalRoot);
            Assert.Equal(bytes, File.ReadAllBytes(original));
            Assert.False(Directory.Exists(Path.Combine(runtime.Path, "different-runtime")));
            Assert.Throws<IOException>(() => NativeManagementJournalAdmission.RequireClearRoot(expected));
        }
        finally { Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", prior); }
    }

    [Theory]
    [InlineData("json")]
    [InlineData("environment")]
    [InlineData("command-line")]
    public void ExplicitManagementRootWinsWithoutCreatingDefault(string source)
    {
        using var runtime = new BindingRuntime();
        var explicitRoot = Path.Combine(runtime.Path, "configured-root");
        Directory.CreateDirectory(explicitRoot);
        var original = Path.Combine(explicitRoot, "original.vif1");
        File.WriteAllText(original, "preserved original");
        var builder = Packaged().AddJsonStream(Stream(new { Service = new { ManagementJournalRoot = explicitRoot } }));
        var prefix = "APFSACCESS_BINDING_TEST_" + Guid.NewGuid().ToString("N") + "_";
        var key = prefix + "Service__ManagementJournalRoot";
        var selected = source == "json" ? explicitRoot : Path.Combine(runtime.Path, "higher-precedence-root");
        try
        {
            if (source == "environment")
            {
                Environment.SetEnvironmentVariable(key, selected);
                builder.AddEnvironmentVariables(prefix);
            }
            else if (source == "command-line") builder.AddCommandLine(["--Service:ManagementJournalRoot=" + selected]);
            using var configuration = (ConfigurationRoot)builder.Build();
            var services = new ServiceCollection();
            var configured = ServiceOptionsBinding.Configure(services, configuration, runtime.Path);
            using var provider = services.BuildServiceProvider();
            Assert.Equal(selected, configured.ManagementJournalRoot);
            Assert.Equal(selected, provider.GetRequiredService<IOptionsMonitor<ServiceHostOptions>>().CurrentValue.ManagementJournalRoot);
            Assert.Equal("preserved original", File.ReadAllText(original));
            Assert.False(Directory.Exists(Path.Combine(runtime.Path, "management-journals")));
            Assert.Equal(source == "json", Directory.Exists(selected));
        }
        finally { Environment.SetEnvironmentVariable(key, null); }
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("relative-journal-root")]
    public void InvalidExplicitManagementRootIsNotReplacedWithDefault(string root)
    {
        using var runtime = new BindingRuntime();
        using var configuration = (ConfigurationRoot)Json(new { Service = new { ManagementJournalRoot = root } }).Build();
        var services = new ServiceCollection();
        Assert.Equal(root, ServiceOptionsBinding.Configure(services, configuration, runtime.Path).ManagementJournalRoot);
        using var provider = services.BuildServiceProvider();
        Assert.Equal(root, provider.GetRequiredService<IOptionsMonitor<ServiceHostOptions>>().CurrentValue.ManagementJournalRoot);
        Assert.ThrowsAny<ArgumentException>(() => NativeApfsVolumeManagement.ValidateStoreRoot(root));
        Assert.False(Directory.Exists(Path.Combine(runtime.Path, "management-journals")));
    }

    [Fact]
    public void DefaultManagementRootRefusesFileOrReparseDirectory()
    {
        using var runtime = new BindingRuntime();
        using var configuration = (ConfigurationRoot)Packaged().Build();
        var root = Path.Combine(runtime.Path, "management-journals");
        File.WriteAllText(root, "preserved conflict");
        Assert.ThrowsAny<ArgumentException>(() => ServiceOptionsBinding.Configure(new ServiceCollection(), configuration, runtime.Path));
        Assert.Equal("preserved conflict", File.ReadAllText(root));
        File.Delete(root);
        var other = Path.Combine(runtime.Path, "other");
        Directory.CreateDirectory(other);
        Directory.CreateSymbolicLink(root, other);
        try
        {
            Assert.Throws<IOException>(() => ServiceOptionsBinding.Configure(new ServiceCollection(), configuration, runtime.Path));
            Assert.Empty(Directory.GetFileSystemEntries(other));
        }
        finally { Directory.Delete(root); }
        var alias = Path.Combine(runtime.Path, "runtime-alias");
        Directory.CreateSymbolicLink(alias, other);
        try
        {
            Assert.Throws<IOException>(() => ServiceOptionsBinding.Configure(new ServiceCollection(), configuration, alias));
            Assert.Empty(Directory.GetFileSystemEntries(other));
        }
        finally { Directory.Delete(alias); }
    }

    private static ServiceHostOptions BindAndCompare(IConfigurationRoot configuration)
    {
        using var runtime = new BindingRuntime();
        var services = new ServiceCollection();
        var configured = ServiceOptionsBinding.Configure(services, configuration, runtime.Path);
        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<ServiceHostOptions>>().Value;
        var monitored = provider.GetRequiredService<IOptionsMonitor<ServiceHostOptions>>().CurrentValue;
        Assert.Equal(configured.MountLetterPool, options.MountLetterPool);
        Assert.Equal(configured.MountLetterPool, monitored.MountLetterPool);
        Assert.Equal(configured.BackendMode, options.BackendMode);
        Assert.Equal(configured.AutoMountEnabled, options.AutoMountEnabled);
        Assert.Equal(configured.PollSeconds, options.PollSeconds);
        Assert.Equal(configured.NativeDeviceCandidates, options.NativeDeviceCandidates);
        Assert.Equal(configured.EnableRetainedPhysicalSnapshotInventory, options.EnableRetainedPhysicalSnapshotInventory);
        Assert.Equal(configured.EnableRetainedPhysicalSnapshotInventory, monitored.EnableRetainedPhysicalSnapshotInventory);
        Assert.Equal(configured.ManagementJournalRoot, options.ManagementJournalRoot);
        Assert.Equal(configured.ManagementJournalRoot, monitored.ManagementJournalRoot);
        return configured;
    }

    private sealed class BindingRuntime : IDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ApfsAccessBindingTests", Guid.NewGuid().ToString("N"));
        internal BindingRuntime() => Directory.CreateDirectory(Path);
        public void Dispose() => Directory.Delete(Path, recursive: true);
    }

    private static IConfigurationBuilder Packaged() => Json(new
    {
        Service = new { MountLetterPool = DefaultPool, BackendMode = "Native", PollSeconds = 11, NativeDeviceCandidates = new[] { "fixture.apfs.img" } },
    });
    private static IConfigurationBuilder Json(object value) => new ConfigurationBuilder().AddJsonStream(Stream(value));
    private static Stream Stream(object value) => new MemoryStream(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)));
}
