using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class AgentControlCommandExecutor
{
    private async Task<(bool Success, string? Diagnostic)> CompletePhysicalWritePermissionAsync(
        PhysicalWritePermissions.RequestPermission? permission, ApfsControlTarget target,
        bool success, CancellationToken token)
    {
        if (permission is null) return (success, null);
        string? diagnostic = null;
        if (success && !token.IsCancellationRequested)
        {
            try
            {
                var current = await ResolveTargetAsync(target, token).ConfigureAwait(false);
                var mounts = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
                if (!current.IsValid || !TryGetPhysicalFixOwner(mounts, target, out var owner) || owner is null ||
                    owner.HostProcessId <= 0 || owner.HostProcessCreationTimeFileTimeUtc is not > 0 || !SnapshotFixHealthy(owner) ||
                    permission.IsNew && !permission.RetainsOwner(owner.HostProcessId, owner.HostProcessCreationTimeFileTimeUtc, owner.MountPoint))
                    throw new IOException("PhysicalWritePermissionFinalHealthyOwnerNotProven");
                _worker.ConfirmPhysicalWritePermission(permission, current.Volume!, token);
                return (true, "Exact physical-volume write permission persisted.");
            }
            catch (Exception ex)
            {
                diagnostic = $"PhysicalWritePermissionNotCommitted: {ex.Message}";
            }
        }

        if (permission.IsNew)
        {
            // Keep the request lease until ordinary detach finishes. It never grants a
            // later request, and a failed detach retains normal ownership/recovery evidence.
            try
            {
                var probe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
                if (!TryGetPhysicalFixOwner(probe, target, out var owner))
                    diagnostic = AppendDiagnostic(diagnostic, "PhysicalWritePermissionCleanupOwnerNotProven");
                else if (owner is not null && permission.RetainsOwner(owner.HostProcessId, owner.HostProcessCreationTimeFileTimeUtc, owner.MountPoint))
                {
                    var detached = await _worker.EjectAdmittedPhysicalWriteOwnerAsync(target, owner).ConfigureAwait(false);
                    diagnostic = AppendDiagnostic(diagnostic, $"PhysicalWritePermissionGracefulDetach: {detached.Success}: {detached.Message}");
                }
                else if (owner is not null)
                    diagnostic = AppendDiagnostic(diagnostic, "PhysicalWritePermissionCleanupOwnerChanged: The observed owner was not admitted by this request; ownership retained.");
            }
            catch (Exception ex)
            {
                diagnostic = AppendDiagnostic(diagnostic, $"PhysicalWritePermissionGracefulDetachNotProven: {ex.Message}");
            }
        }
        return (false, diagnostic);
    }
}
