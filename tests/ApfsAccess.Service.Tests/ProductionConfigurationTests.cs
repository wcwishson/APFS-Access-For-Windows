using System.Text.Json;

namespace ApfsAccess.Service.Tests;

public sealed class ProductionConfigurationTests
{
    [Fact]
    public void ProductionConfig_UsesCanonicalSafetyGateWithoutPrivatePilotHistory()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(FindProductionConfig()));
        var service = document.RootElement.GetProperty("Service");

        Assert.Equal("CanonicalImage", service.GetProperty("NativeWritePromotionPolicy").GetString());
        Assert.True(service.GetProperty("NativeWriteAllowRawPhysicalDevices").GetBoolean());
        Assert.True(service.GetProperty("NativeWriteStrictMode").GetBoolean());
        Assert.True(service.GetProperty("NativeWriteIntegrityCheckOnMount").GetBoolean());
        Assert.True(service.GetProperty("NativeWriteRequireCanonicalCommit").GetBoolean());
        Assert.True(service.GetProperty("NativeWriteDisallowScaffoldCommitOnNonFixture").GetBoolean());
        Assert.True(service.GetProperty("NativeWriteRejectScaffoldReplayBlobOnNonFixture").GetBoolean());
        Assert.True(service.GetProperty("NativeWriteRequireCanonicalReplayCandidateOnNonFixture").GetBoolean());
    }

    private static string FindProductionConfig()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            var candidate = Path.Combine(
                directory.FullName,
                "src",
                "ApfsAccess.Service",
                "appsettings.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException("Could not locate the production APFS Access configuration.");
    }
}
