using ApfsAccess.Backend.Mock;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Service;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.Configure<ServiceHostOptions>(
    builder.Configuration.GetSection(ServiceHostOptions.SectionName)
);

var configuredOptions = builder.Configuration
    .GetSection(ServiceHostOptions.SectionName)
    .Get<ServiceHostOptions>() ?? new ServiceHostOptions();

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

builder.Services.AddHostedService<ApfsMountWorker>();
builder.Services.AddHostedService<TrayPipeHostService>();

await builder.Build().RunAsync();
