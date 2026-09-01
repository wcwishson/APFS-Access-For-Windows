using ApfsAccess.Backend.Mock;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Service;

var runtimeRoot = ConfigurePortableRuntimeEnvironment();
using var serviceInstanceLease = ServiceInstanceLease.TryAcquire(runtimeRoot);
if (serviceInstanceLease is null)
{
    Console.Error.WriteLine("APFS Access service is already running.");
    Environment.ExitCode = 17;
    return;
}

var builder = Host.CreateApplicationBuilder(args);

builder.Services.Configure<ServiceHostOptions>(
    builder.Configuration.GetSection(ServiceHostOptions.SectionName)
);

var configuredOptions = builder.Configuration
    .GetSection(ServiceHostOptions.SectionName)
    .Get<ServiceHostOptions>() ?? new ServiceHostOptions();

builder.Services.Configure<HostOptions>(options =>
{
    var nativeStopSeconds = Math.Clamp(configuredOptions.NativeHostStopTimeoutSeconds, 1, 60);
    options.ShutdownTimeout = TimeSpan.FromSeconds((nativeStopSeconds * 2) + 10);
});

builder.Services.AddSingleton<IMountPolicy>(_ => new FirstFreeMountPolicy(configuredOptions.MountLetterPool));

if (string.Equals(configuredOptions.BackendMode, "Native", StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddSingleton<IApfsBackend>(_ => new NativeApfsBackend(configuredOptions));
}
else
{
    builder.Services.AddSingleton<IApfsBackend, MockApfsBackend>();
}

builder.Services.AddSingleton<RuntimeStatusPublisher>();

builder.Services.AddSingleton<ApfsMountWorker>();
builder.Services.AddHostedService(static sp => sp.GetRequiredService<ApfsMountWorker>());
builder.Services.AddSingleton<AgentControlCommandExecutor>();
builder.Services.AddSingleton(static sp =>
{
    var runtimeRoot = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT")
        ?? throw new InvalidOperationException("APFSACCESS_RUNTIME_ROOT is not configured.");
    return new AgentControlOperationService(
        sp.GetRequiredService<AgentControlCommandExecutor>().ExecuteAsync,
        Path.Combine(runtimeRoot, "agent-operations"));
});
builder.Services.AddSingleton(static sp => new TrayPipeHostService(
    sp.GetRequiredService<ILogger<TrayPipeHostService>>(),
    sp.GetRequiredService<RuntimeStatusPublisher>(),
    sp.GetRequiredService<ApfsMountWorker>(),
    sp.GetRequiredService<IHostApplicationLifetime>(),
    sp.GetRequiredService<AgentControlOperationService>()));
builder.Services.AddHostedService(static sp => sp.GetRequiredService<TrayPipeHostService>());

await builder.Build().RunAsync();

static string ConfigurePortableRuntimeEnvironment()
{
    var runtimeRoot = ResolveRuntimeRoot();
    var tempRoot = Path.Combine(runtimeRoot, "temp");
    var spoolRoot = Path.Combine(runtimeRoot, "payload-spool");

    Directory.CreateDirectory(tempRoot);
    Directory.CreateDirectory(spoolRoot);

    Environment.SetEnvironmentVariable("TEMP", tempRoot);
    Environment.SetEnvironmentVariable("TMP", tempRoot);
    Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", spoolRoot);
    Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", runtimeRoot);
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_TRACE_MOVES");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_PERF_COUNTERS");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_TRACE_COMMITS");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_TRACE_READS");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_DEFER_CLOSE_COMMITS");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_CONTENT_WRITEBACK");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_ENABLE_GROUPED_DEFERRED_ACCEPTANCE");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_GROUPED_DEFERRED_ACCEPTANCE");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_EXPERIMENTAL_NAMESPACE_WRITEBACK");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_NAMESPACE_WRITEBACK");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_ASYNC_BLOCK_IO");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_ASYNC_BLOCK_IO_DEPTH");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_CHECKPOINT_DELTA_SHADOW");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_STRICT_COMMIT_VERIFY");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_WORKING_FREE_SANITIZE_CACHE");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_CHECKPOINT_SERIALIZATION_BUFFER_REUSE");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_CHECKPOINT_SLOT_INDEX");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_CHECKPOINT_BLOCK_INDEX_CACHE");
    PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_INDEX_DELTA");
    return runtimeRoot;
}

static void PreserveOptionalDiagnosticEnvironment(string key)
{
    var value = Environment.GetEnvironmentVariable(key);
    if (!string.IsNullOrWhiteSpace(value))
    {
        Environment.SetEnvironmentVariable(key, value);
    }
}

static string ResolvePortableRoot()
{
    var overrideRoot = Environment.GetEnvironmentVariable("APFSACCESS_PORTABLE_ROOT");
    if (!string.IsNullOrWhiteSpace(overrideRoot))
    {
        return Path.GetFullPath(overrideRoot);
    }

    var baseDirectory = new DirectoryInfo(AppContext.BaseDirectory);
    if (baseDirectory.Name.StartsWith("payload-", StringComparison.OrdinalIgnoreCase) &&
        baseDirectory.Parent is not null)
    {
        return baseDirectory.Parent.FullName;
    }

    return Path.Combine(AppContext.BaseDirectory, ".apfsaccess-portable");
}

static string ResolveRuntimeRoot()
{
    var overrideRoot = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT");
    if (!string.IsNullOrWhiteSpace(overrideRoot))
    {
        return Path.GetFullPath(overrideRoot);
    }

    var portableRoot = ResolvePortableRoot();
    if (LooksLikeCloudSyncedPath(portableRoot))
    {
        var driveRoot = Path.GetPathRoot(portableRoot);
        if (!string.IsNullOrWhiteSpace(driveRoot))
        {
            return Path.Combine(driveRoot, "ApfsAccessScratch", "AppRuntime");
        }
    }

    return Path.Combine(portableRoot, "runtime");
}

static bool LooksLikeCloudSyncedPath(string path)
{
    return path.Contains("SynologyDrive", StringComparison.OrdinalIgnoreCase) ||
           path.Contains("OneDrive", StringComparison.OrdinalIgnoreCase) ||
           path.Contains("Dropbox", StringComparison.OrdinalIgnoreCase) ||
           path.Contains("Google Drive", StringComparison.OrdinalIgnoreCase) ||
           path.Contains("iCloudDrive", StringComparison.OrdinalIgnoreCase);
}
