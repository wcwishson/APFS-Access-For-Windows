using System.Reflection;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed partial class HostProcessGuardianTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EncryptedWriterRetirementRetriesWithoutDroppingExactOwnerProof(bool deferGuardianRelease)
    {
        var root = CreateTestDirectory();
        var image = Path.Combine(root, "image.apfs");
        File.WriteAllBytes(image, new byte[8192]);
        var profile = EncryptedImageWriteLaunchTests.Profile(image);
        using var source = NativeEncryptedImageWriteLaunch.Prepare(profile);
        using var lifetime = HostLifetimeSentinel.Create(Path.Combine(root, "lifetime"));
        using var startup = HostStartupGate.Create(root);
        var armed = 0; var release = 0; var observations = 0;
        using var hooks = new GuardianCleanupHookScope(new HostGuardianCleanupTestHooks {
            ActiveProcessCount = job => Volatile.Read(ref armed) == 0 || Volatile.Read(ref release) != 0 ||
                Interlocked.Increment(ref observations) <= 2 ? TestJobActiveProcesses(job) : 1u,
        });
        var start = DedicatedGuardianChild(root);
        start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = lifetime.FilePath;
        var child = HostProcessGuardian.Start(start, startup);
        var guardian = child.Guardian!;
        var jobHandle = GuardianHandle(guardian, "_job");
        var session = Assert.IsType<NativeEncryptedImageServiceSession>(Activator.CreateInstance(
            typeof(NativeEncryptedImageServiceSession), BindingFlags.NonPublic | BindingFlags.Instance,
            null, [source, root, lifetime, child], null));
        var receipt = Path.Combine(root, "retirement.json");
        try
        {
            Assert.True(SpinWait.SpinUntil(() => File.Exists(Path.Combine(root, "ready.txt")), TimeSpan.FromSeconds(5)));
            lifetime.Dispose();
            Assert.True(child.Process.WaitForExit(5000));
            Assert.Equal(0, child.Process.ExitCode);
            File.WriteAllText(Path.Combine(root, "status.json"), JsonSerializer.Serialize(new {
                hostPid = guardian.ProcessId, mountReady = false, explicitReadOnly = false,
                immutableEncryptedImage = false, encryptedSourceId = profile.SourceId,
                encryptedContainerUuid = Guid.Parse(profile.ContainerUuid).ToString("N"),
                encryptedVolumeUuid = Guid.Parse(profile.VolumeUuid).ToString("N"),
                encryptedVolumeOid = profile.VolumeObjectId, encryptedSelectionCheckpointXid = profile.CheckpointXid,
                encryptedCheckpointXid = profile.CheckpointXid + 2,
                encryptedFailureReason = "None", encryptedFailureTickMs = 0ul,
                walRecoveryStateValid = true, encryptedHealth = "StoppingReadWrite",
                walAcceptedSequence = 34ul, walApfsDurableSequence = 34ul, walCleanupSequence = 34ul,
                dirtyTransactionCount = 0, volumeLabel = "Retirement control",
            }));
            if (deferGuardianRelease)
            {
                Volatile.Write(ref armed, 1);
                var pending = await session.StopAsync(TimeSpan.FromSeconds(1));
                Assert.False(pending.Success); Assert.True(pending.MountRemoved);
                Assert.False(pending.HostOwnershipReleased); Assert.False(pending.PendingDurabilityCleared);
                Assert.False(guardian.OwnershipReleased.IsCompleted); Assert.False(jobHandle.IsClosed);
                Assert.True(File.Exists(receipt));
                Volatile.Write(ref release, 1);
                await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
                Assert.True(jobHandle.IsClosed);
                // Retry must use the captured proof after both status and job handles
                // are unavailable, rather than recapturing a different observation.
                File.WriteAllText(Path.Combine(root, "status.json"), "{}");
            }
            else
            {
                using (var blocked = new FileStream(receipt, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                {
                    var pending = await session.StopAsync(TimeSpan.FromSeconds(1));
                    Assert.False(pending.Success); Assert.False(pending.HostOwnershipReleased);
                    Assert.False(pending.PendingDurabilityCleared);
                    Assert.False(guardian.OwnershipReleased.IsCompleted); Assert.False(jobHandle.IsClosed);
                }
            }
            var stopped = await session.StopAsync(TimeSpan.FromSeconds(1));
            Assert.True(stopped.Success); Assert.True(stopped.MountRemoved);
            Assert.True(stopped.HostOwnershipReleased); Assert.True(stopped.PendingDurabilityCleared);
            Assert.Equal(profile.CheckpointXid + 2, session.CheckpointXid);
            Assert.Equal(stopped, await session.StopAsync(TimeSpan.Zero));
            using var saved = JsonDocument.Parse(File.ReadAllText(receipt));
            Assert.True(saved.RootElement.GetProperty("durable").GetBoolean());
            Assert.Equal(profile.SourceId, saved.RootElement.GetProperty("profile").GetProperty("SourceId").GetString());
            Assert.Equal(new byte[8192], File.ReadAllBytes(image));
        }
        finally
        {
            Volatile.Write(ref release, 1);
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            child.StartupStderr?.Dispose(); child.Process.Dispose();
        }
    }
}
