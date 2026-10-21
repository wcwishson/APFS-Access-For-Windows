using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeHistoryKeeperIntegrationTests
{
    [HistoryKeeperTheory]
    [InlineData("delete", "cancel")]
    [InlineData("delete", "prepared-recover")]
    [InlineData("delete", "cancelled-recover")]
    [InlineData("format", "cancel")]
    [InlineData("format", "prepared-recover")]
    [InlineData("format", "cancelled-recover")]
    [InlineData("delete", "cancel-debt")]
    [InlineData("format", "cancel-debt")]
    public void AheadMarkerRefusesInsideActualKeeperBeforeEarlyReturn(string operation, string action)
    {
        var tools = Environment.GetEnvironmentVariable("APFS_HISTORY_TEST_TOOLS")!;
        var root = Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!, "history-" + operation + "-" + action + "-" + Guid.NewGuid().ToString("N"));
        Assert.StartsWith("D:", root, StringComparison.OrdinalIgnoreCase);
        Directory.CreateDirectory(root);
        var generator = Environment.GetEnvironmentVariable("APFS_HISTORY_TEST_FIXTURE")!;
        var runner = new HistoryWireRunner(root);
        Assert.Equal(0, runner.Run(generator, [root, "--managed-seed"]).ExitCode);
        var image = Path.Combine(root, "image.apfs"); var spool = Path.Combine(root, "spool"); var recovery = Path.Combine(root, "recovery");
        Directory.CreateDirectory(spool); Directory.CreateDirectory(recovery);
        NativeOrdinaryImageOwnership.RegisterFreshCopy(new(Path.Combine(root, "source.apfs"), image), root, spool, recovery);
        var setup = runner.Run(generator, [root, "--managed-prepare-" + operation]);
        Assert.True(setup.ExitCode == 0, setup.StandardOutput + setup.StandardError);
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "request.json")));
        var j = doc.RootElement;
        string Text(string key) => j.GetProperty(key).GetString()!;
        var container = Text("containerUuid");
        var observed = runner.Run(Path.Combine(tools, "VolumeManagementImage.exe"), ["--mode", "observe", "--image", image, "--offset", "0"]);
        Assert.Equal(0, observed.ExitCode);
        using var observation = JsonDocument.Parse(observed.StandardOutput);
        var uuids = observation.RootElement.GetProperty("volumes").EnumerateArray().ToDictionary(v => v.GetProperty("oid").GetString()!, v => v.GetProperty("volumeUuid").GetString()!);
        var census = j.GetProperty("siblingWals").EnumerateArray().Select(w => new VolumeTopologyWal(w.GetProperty("oid").GetString()!,
            uuids[w.GetProperty("oid").GetString()!], w.GetProperty("path").GetString()!)).ToArray();
        var template = NativeRecoveryStorageTests.Inventory(image).Volumes[0];
        var rows = census.Select(w => template with { CatalogContainerUuid = container, CatalogVolumeUuid = w.VolumeUuid,
            CatalogVolumeObjectId = ulong.Parse(w.Oid), RegisteredImage = null,
            RecoveryIdentity = NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, container, ulong.Parse(w.Oid), true) }).ToArray();
        var launch = new ProcessStartInfo("no-host-launched.exe");
        launch.Environment["APFSACCESS_SPOOL_ROOT"] = spool; launch.Environment["APFSACCESS_RECOVERY_ROOT"] = recovery;
        NativeOrdinaryImageOwnership.CaptureLaunch(launch, root, image, "0", rows);
        var request = new VolumeTopologyRequest(operation, image, root, "0", container, Text("volumeUuid"), Text("volumeOid"), Text("preXid"),
            Text("sourceIdentity"), spool, census, Name: operation == "format" ? Text("name") : null,
            CaseSensitive: operation == "format" ? j.GetProperty("caseSensitive").GetBoolean() : null,
            ImageOptions: operation == "format" ? new(Text("expectedBytes"), Text("targetBytes"), Text("newContainerUuid"), Text("newVolumeUuid"), Text("newVolumeWal")) : null);
        var token = Text("confirmationToken");
        VolumeTopologyResult Run(VolumeTopologyMode mode)
        {
            NativeOrdinaryImageOwnership.RequireCensus(root, image, "0", spool, recovery, container, census);
            using var preflight = NativeRecoveryStorage.AcquireForNativeKeeper(request, recovery, root);
            return operation == "delete"
                ? new NativeApfsVolumeManagement(runner, Path.Combine(tools, "VolumeManagementImage.exe"), root, spool).Execute(request, mode,
                    mode == VolumeTopologyMode.Cancel ? token : null, default, recovery)
                : new NativeApfsVolumeImageManagement(runner, Path.Combine(tools, "VolumeFormatImage.exe"), root, spool).Execute(request, mode,
                    mode == VolumeTopologyMode.Cancel ? token : null, default, recovery);
        }
        if (action == "cancelled-recover") Assert.Equal("cancelled", Run(VolumeTopologyMode.Cancel).Outcome);
        if (action == "cancel-debt") Assert.Equal(0, runner.Run(generator, [root, "--managed-debt"]).ExitCode);
        var cancel = action is "cancel" or "cancel-debt";
        var marker = NativeRecoveryStorage.CanonicalNativeMarker(recovery, rows[0].RecoveryIdentity!);
        File.WriteAllText(marker, "dirty=0\nlastCommitXid=" + (ulong.Parse(request.PreXid) + 1) + "\n");
        var before = Evidence(root);
        var result = Run(cancel ? VolumeTopologyMode.Cancel : VolumeTopologyMode.Recover);
        var after = Evidence(root);
        File.WriteAllText(Path.Combine(root, "ahead-refusal.json"), result.Report.GetRawText());
        File.WriteAllText(Path.Combine(root, "before-after-hashes.json"), JsonSerializer.Serialize(new { before, after }));
        Assert.Equal("KeeperHistoryMarkerCheckpointUnproved", result.Error);
        Assert.Contains(result.Outcome, new[] { "refused", "recovery-required" });
        Assert.Equal(before, after);
        File.WriteAllText(marker, "dirty=0\nlastCommitXid=" + request.PreXid + "\n");
        var retained = census.ToDictionary(w => w.Path, w => File.ReadAllBytes(w.Path));
        var source = File.ReadAllBytes(image);
        var clean = Run(cancel ? VolumeTopologyMode.Cancel : VolumeTopologyMode.Recover);
        Assert.Equal("cancelled", clean.Outcome);
        Assert.Equal(source, File.ReadAllBytes(image));
        foreach (var wal in retained) Assert.Equal(wal.Value, File.ReadAllBytes(wal.Key));
        File.WriteAllText(Path.Combine(root, "clean-cancelled.json"), clean.Report.GetRawText());
    }

    private static string[] Evidence(string root) => Directory.GetFiles(root, "*", SearchOption.AllDirectories).Order(StringComparer.OrdinalIgnoreCase)
        .Select(path => path + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))).ToArray();

    private sealed class HistoryWireRunner(string root) : IObserverRunner
    {
        private readonly ProcessObserverRunner _inner = new();
        private int _sequence;

        public ObserverRunResult Run(string tool, IReadOnlyList<string> arguments)
        {
            var result = _inner.Run(tool, arguments);
            // Keep diagnostics outside the protected before/after history census.
            var directory = root + "-wire";
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, $"{Interlocked.Increment(ref _sequence):D2}.json"),
                JsonSerializer.Serialize(new { tool, arguments, result.ExitCode, result.StandardOutput, result.StandardError }));
            if (Path.GetFileName(tool) == "VolumeManagementImage.exe")
                Assert.False(string.IsNullOrWhiteSpace(result.StandardOutput),
                    $"Native JSON contract failed: exit={result.ExitCode}; stderr={result.StandardError}; evidence={directory}");
            return result;
        }
    }
}

public sealed class HistoryKeeperTheoryAttribute : TheoryAttribute
{
    public HistoryKeeperTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("APFS_HISTORY_TEST_TOOLS") is null ||
            Environment.GetEnvironmentVariable("APFS_HISTORY_TEST_FIXTURE") is null || Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT") is null)
            Skip = "Private native helper/fixture paths and D: evidence root required.";
    }
}
