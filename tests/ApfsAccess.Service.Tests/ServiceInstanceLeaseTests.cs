using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed class ServiceInstanceLeaseTests
{
    [Fact]
    public void DefaultLeaseUsesMachineWideNamespace()
    {
        var field = typeof(ServiceInstanceLease).GetField(
            "DefaultLeaseName",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        Assert.NotNull(field);
        Assert.StartsWith("Global\\", Assert.IsType<string>(field!.GetValue(null)));
    }

    [Fact]
    public void TryAcquire_AllowsOnlyOneLiveServiceOwnerAcrossRuntimeRoots()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "ApfsAccessTests",
            "ServiceInstanceLease",
            Guid.NewGuid().ToString("N"),
            "first");
        var secondRoot = Path.Combine(Path.GetDirectoryName(root)!, "second");
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(secondRoot);
        var mutexName = $"Global\\ApfsAccess.Service.Tests.{Guid.NewGuid():N}";

        try
        {
            using var first = ServiceInstanceLease.TryAcquire(root, mutexName);
            Assert.NotNull(first);

            using var duplicate = ServiceInstanceLease.TryAcquire(secondRoot, mutexName);
            Assert.Null(duplicate);

            first!.Dispose();
            using var replacement = ServiceInstanceLease.TryAcquire(secondRoot, mutexName);
            Assert.NotNull(replacement);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
            Directory.Delete(secondRoot, recursive: true);
        }
    }

    [Fact]
    public void LeaseCanBeReleasedAfterAsyncContinuationChangesThreads()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "ApfsAccessTests",
            "ServiceInstanceLease",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var leaseName = $"Global\\ApfsAccess.Service.Tests.{Guid.NewGuid():N}";
        ServiceInstanceLease? lease = null;
        using var acquired = new ManualResetEventSlim();
        using var allowOwnerThreadExit = new ManualResetEventSlim();
        Thread? acquiringThread = null;

        try
        {
            acquiringThread = new Thread(() =>
            {
                lease = ServiceInstanceLease.TryAcquire(root, leaseName);
                acquired.Set();
                allowOwnerThreadExit.Wait(TimeSpan.FromSeconds(5));
            });
            acquiringThread.Start();
            Assert.True(acquired.Wait(TimeSpan.FromSeconds(5)));
            Assert.NotNull(lease);

            var exception = Record.Exception(() => lease!.Dispose());
            allowOwnerThreadExit.Set();
            Assert.True(acquiringThread.Join(TimeSpan.FromSeconds(5)));

            Assert.Null(exception);
            using var replacement = ServiceInstanceLease.TryAcquire(root, leaseName);
            Assert.NotNull(replacement);
        }
        finally
        {
            allowOwnerThreadExit.Set();
            acquiringThread?.Join(TimeSpan.FromSeconds(5));
            try
            {
                lease?.Dispose();
            }
            catch
            {
            }
            Directory.Delete(root, recursive: true);
        }
    }
}
