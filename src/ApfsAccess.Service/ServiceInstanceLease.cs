using System.Threading;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ApfsAccess.Service;

internal sealed class ServiceInstanceLease : IDisposable
{
    private const string DefaultLeaseName = @"Global\APFSAccess.Service.Instance";
    private Semaphore? _semaphore;

    private ServiceInstanceLease(Semaphore semaphore)
    {
        _semaphore = semaphore;
    }

    internal static ServiceInstanceLease? TryAcquire(string runtimeRoot, string? leaseName = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        Directory.CreateDirectory(runtimeRoot);
        var name = string.IsNullOrWhiteSpace(leaseName) ? DefaultLeaseName : leaseName;

        try
        {
            var semaphore = CreateSemaphore(name);
            try
            {
                if (!semaphore.WaitOne(0))
                {
                    semaphore.Dispose();
                    return null;
                }

                return new ServiceInstanceLease(semaphore);
            }
            catch
            {
                semaphore.Dispose();
                throw;
            }
        }
        catch (UnauthorizedAccessException)
        {
            // An inaccessible existing lease is still a safe refusal to start;
            // never fall back to a runtime-root-local lock.
            return null;
        }
        catch (WaitHandleCannotBeOpenedException)
        {
            return null;
        }
    }

    private static Semaphore CreateSemaphore(string name)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new Semaphore(initialCount: 1, maximumCount: 1, name);
        }

        var security = new SemaphoreSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var rights = SemaphoreRights.Modify | SemaphoreRights.Synchronize;
        security.AddAccessRule(new SemaphoreAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            SemaphoreRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new SemaphoreAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            SemaphoreRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new SemaphoreAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            rights,
            AccessControlType.Allow));

        return SemaphoreAcl.Create(
            initialCount: 1,
            maximumCount: 1,
            name,
            createdNew: out _,
            security);
    }

    public void Dispose()
    {
        var semaphore = Interlocked.Exchange(ref _semaphore, null);
        if (semaphore is null)
        {
            return;
        }

        try
        {
            semaphore.Release();
        }
        finally
        {
            semaphore.Dispose();
        }
    }
}
