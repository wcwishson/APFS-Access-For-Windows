using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

namespace ApfsAccess.Backend.Native.Tests;

internal static class HostTerminalFixture
{
    internal static void BindOrdinary(object state, Process process, string statusPath)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(statusPath))!;
        Assert.StartsWith("D:\\", directory, StringComparison.OrdinalIgnoreCase);
        // Process-lifetime positives also need an independent original namespace
        // and terminal record. Invalid or dirty status cases use separate fixtures.
        state.GetType().GetProperty("OriginalMountPoints", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(state, new[] { Path.Combine(directory, "ordinary-test-namespace") });
        File.WriteAllText(statusPath, JsonSerializer.Serialize(new
        {
            hostPid = process.Id, mountReady = false, dirtyTransactionCount = 0ul,
            inFlightMutationCallbacks = 0ul, closeCommitDeferred = false,
            deferredCommitRequested = false, deferredCommitInFlight = false, shutdownDrainActive = false,
            walRecoveryStateValid = true, walAcceptedSequence = 0ul,
            walApfsDurableSequence = 0ul, walCleanupSequence = 0ul,
            payloadSpoolDirtyRangeCount = 0ul, payloadSpoolIndexDirty = false, payloadSpoolRecoveryRequired = false,
        }));
    }
}
