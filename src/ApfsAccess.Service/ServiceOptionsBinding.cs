using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ApfsAccess.Service;

public static class ServiceOptionsBinding
{
    public static ServiceHostOptions Configure(IServiceCollection services, IConfigurationRoot configuration, string runtimeRoot)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrEmpty(runtimeRoot);
        var resolvedRuntimeRoot = Path.GetFullPath(runtimeRoot);
        var section = configuration.GetSection(ServiceHostOptions.SectionName);
        services.Configure<ServiceHostOptions>(section);
        services.PostConfigure<ServiceHostOptions>(options =>
        {
            ReplaceMountLetterPool(configuration, options);
            SetDefaultManagementRoot(options, resolvedRuntimeRoot);
        });
        var configured = section.Get<ServiceHostOptions>() ?? new ServiceHostOptions();
        ReplaceMountLetterPool(configuration, configured);
        SetDefaultManagementRoot(configured, resolvedRuntimeRoot);
        return configured;
    }

    private static void SetDefaultManagementRoot(ServiceHostOptions options, string runtimeRoot)
    {
        if (options.ManagementJournalRoot is not null) return;
        NativeApfsVolumeManagement.ValidateStoreRoot(runtimeRoot);
        var root = Path.Combine(runtimeRoot, "management-journals");
        if (!Path.Exists(root)) Directory.CreateDirectory(root);
        NativeApfsVolumeManagement.ValidateStoreRoot(root);
        options.ManagementJournalRoot = root;
    }

    private static void ReplaceMountLetterPool(IConfigurationRoot configuration, ServiceHostOptions options)
    {
        const string path = ServiceHostOptions.SectionName + ":" + nameof(ServiceHostOptions.MountLetterPool);
        // Arrays otherwise merge by index across providers and append to the
        // initialized options property. The last explicit provider owns this pool.
        foreach (var provider in configuration.Providers.Reverse())
        {
            var keys = provider.GetChildKeys([], path)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(key => key, ConfigurationKeyComparer.Instance)
                .ToArray();
            if (keys.Length == 0 && !provider.TryGet(path, out _))
                continue;

            var letters = new string[keys.Length];
            for (var index = 0; index < keys.Length; ++index)
            {
                if (!provider.TryGet(path + ":" + keys[index], out var value))
                    throw new InvalidOperationException("Service:MountLetterPool requires direct string array values.");
                letters[index] = value!;
            }
            options.MountLetterPool = letters;
            return;
        }
    }
}
