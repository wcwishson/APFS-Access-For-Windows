using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class SnapshotBrowseCommandTests : IDisposable
{
    private const string Container = "apfs-container:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private readonly string directory = Path.Combine(Path.GetTempPath(), "snapshot-browse-cli-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "image with spaces.raw");
    private string Session => Path.Combine(directory, "session");
    private string Destination => Path.Combine(directory, "copy output");
    private string Host => Path.Combine(directory, "host-placeholder.bin");
    private string[] Args => ["browse", "--image", Image, "--container-id", Container, "--volume-oid", "101", "--snapshot-xid", "11", "--session-dir", Session];

    public SnapshotBrowseCommandTests()
    {
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Image, new byte[8192]);
        File.WriteAllBytes(Host, [0]);
    }

    public void Dispose() => Directory.Delete(directory, recursive: true);

    [Theory]
    [InlineData("--write")]
    [InlineData("--readwrite")]
    [InlineData("--write-backend")]
    [InlineData("--device")]
    [InlineData("--image")]
    [InlineData("--container-id")]
    [InlineData("--volume-oid")]
    [InlineData("--snapshot-xid")]
    [InlineData("--session-dir")]
    [InlineData("--unknown")]
    public async Task UnsupportedOrDuplicateFlagsNeverPrepareOrLaunch(string flag)
        => await AssertNoLaunch([.. Args, flag, "value"]);

    [Fact]
    public async Task MissingValuesRequiredSelectorsAndRepeatedJsonNeverLaunch()
    {
        await AssertNoLaunch([.. Args, "--copy-out"]);
        await AssertNoLaunch([.. Args, "--copy-out", "--json"]);
        await AssertNoLaunch([.. Args, "--json", "--json"]);
        await AssertNoLaunch([.. Args, "--copy-out", Destination, "--copy-out", Destination]);
        foreach (var flag in new[] { "--image", "--container-id", "--volume-oid", "--snapshot-xid" })
        {
            var args = Args.ToList(); var i = args.IndexOf(flag); args.RemoveRange(i, 2);
            await AssertNoLaunch(args.ToArray());
        }
    }

    [Theory]
    [InlineData("0")]
    [InlineData("011")]
    [InlineData("+11")]
    [InlineData("18446744073709551616")]
    [InlineData("second backup")]
    public async Task InvalidSnapshotSelectorNeverLaunches(string xid)
    {
        var args = Args; args[8] = xid;
        await AssertNoLaunch(args);
    }

    [Fact]
    public async Task ExactlyOneSnapshotSelectorIsRequiredAndDuplicateNamesNeverLaunch()
    {
        await AssertNoLaunch([.. Args, "--snapshot-name", "second backup"]);
        var nameArgs = Args; nameArgs[7] = "--snapshot-name"; nameArgs[8] = "second backup";
        await AssertNoLaunch([.. nameArgs, "--snapshot-xid", "11"]);
        await AssertNoLaunch([.. nameArgs, "--snapshot-name", "second backup"]);
        await AssertNoLaunch(nameArgs.Where((_, index) => index is not (7 or 8)).ToArray());
        await AssertNoLaunch([.. Args.Take(7), "--snapshot-name"]);
    }

    [Theory]
    [InlineData("second backup")]
    [InlineData("Snapshot \u5907\u4efd")]
    [InlineData("11")]
    public void ExactNameSelectorParsesWithoutInventingAnXid(string name)
    {
        var args = Args; args[7] = "--snapshot-name"; args[8] = name;
        var options = SnapshotBrowseCommand.Parse([.. args, "--json"]);
        Assert.Equal(name, options.SnapshotName);
        Assert.Empty(options.SnapshotXid);
        Assert.Equal(Image, options.Image);
        Assert.Equal(Container, options.ContainerId);
        Assert.Equal("101", options.VolumeOid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("backup\0name")]
    [InlineData("backup\nname")]
    [InlineData("backup\u007fname")]
    public async Task EmptyOrControlCharacterNamesNeverPrepareOrLaunch(string name)
    {
        var args = Args; args[7] = "--snapshot-name"; args[8] = name;
        await AssertNoLaunch(args);
    }

    [Fact]
    public void SnapshotNameLengthBoundaryIsPreserved()
    {
        var args = Args; args[7] = "--snapshot-name"; args[8] = new string('n', 255);
        Assert.Equal(args[8], SnapshotBrowseCommand.Parse(args).SnapshotName);
        args[8] += "n";
        Assert.Throws<ArgumentException>(() => SnapshotBrowseCommand.Parse(args));
    }

    [Theory]
    [InlineData(@"relative\folder")]
    [InlineData(@"D:relative")]
    [InlineData(@"\\server\share\folder")]
    [InlineData(@"\\?\D:\folder")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"D:\folder:stream")]
    [InlineData(@"D:\folder\..\other")]
    public async Task BadSessionAndCopyPathsNeverPrepareOrLaunch(string path)
    {
        var args = Args; args[10] = path;
        await AssertNoLaunch(args);
        await AssertNoLaunch([.. Args, "--copy-out", path]);
    }

    [Theory]
    [InlineData("image", @"\\.\PhysicalDrive0")]
    [InlineData("image", @"D:\image.raw:stream")]
    [InlineData("image", "relative.raw")]
    [InlineData("container-id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("container-id", "apfs-container:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("volume-oid", "0")]
    [InlineData("volume-oid", "0101")]
    public async Task InvalidSourceScopeNeverPreparesOrLaunches(string selector, string value)
    {
        var args = Args; args[Array.IndexOf(args, "--" + selector) + 1] = value;
        await AssertNoLaunch(args);
    }

    [Fact]
    public void OrdinaryNonScratchDrivePathsParseAndJsonDoesNotChangeSelection()
    {
        var args = Args; args[10] = @"C:\ApfsAccessSnapshotTests\session";
        var plain = SnapshotBrowseCommand.Parse([.. args, "--copy-out", @"C:\ApfsAccessSnapshotTests\output"]);
        Assert.Equal(plain, SnapshotBrowseCommand.Parse([.. args, "--copy-out", @"C:\ApfsAccessSnapshotTests\output", "--json"]));
        Assert.Equal("11", plain.SnapshotXid);
        Assert.Equal(@"C:\ApfsAccessSnapshotTests\session", plain.SessionDirectory);
    }

    [Theory]
    [InlineData("existing-session-directory")]
    [InlineData("existing-session-file")]
    [InlineData("existing-copy-directory")]
    [InlineData("existing-copy-file")]
    [InlineData("same")]
    [InlineData("copy-inside-session")]
    [InlineData("session-inside-copy")]
    public async Task OutputCollisionsAndNestedPathsNeverLaunchOrOverwrite(string collision)
    {
        var destination = Destination;
        switch (collision)
        {
            case "existing-session-directory": Directory.CreateDirectory(Session); break;
            case "existing-session-file": File.WriteAllText(Session, "session sentinel"); break;
            case "existing-copy-directory": Directory.CreateDirectory(Destination); break;
            case "existing-copy-file": File.WriteAllText(Destination, "copy sentinel"); break;
            case "same": destination = Session; break;
            case "copy-inside-session": destination = Path.Combine(Session, "copy"); break;
            case "session-inside-copy": destination = directory; break;
        }
        await AssertNoLaunch([.. Args, "--copy-out", destination]);
        if (collision == "existing-session-file") Assert.Equal("session sentinel", File.ReadAllText(Session));
        if (collision == "existing-copy-file") Assert.Equal("copy sentinel", File.ReadAllText(Destination));
    }

    [Fact]
    public async Task RejectedExistingSessionCannotOverwritePriorResultEvidence()
    {
        Directory.CreateDirectory(Session);
        var previousResult = Path.Combine(Session, "result.json");
        File.WriteAllText(previousResult, "previous session evidence");
        await AssertNoLaunch(Args);
        Assert.Equal("previous session evidence", File.ReadAllText(previousResult));
        Assert.Single(Directory.EnumerateFileSystemEntries(Session));
    }

    [Fact]
    public async Task HelpNeedsNoPackagedHostAndNeverPreparesSource()
    {
        var result = await Run(["browse", "--help"], NoLaunchDependencies());
        Assert.Equal(0, result.Exit);
        Assert.True(result.Json.GetProperty("success").GetBoolean());
        Assert.Contains("snapshots browse", result.Json.GetProperty("usage").GetString());
        Assert.False(Directory.Exists(Session));
    }

    [Fact]
    public async Task MissingHostAndCancelledRequestDoNotPrepareOrLaunch()
    {
        var result = await Run(Args, NoLaunchDependencies(Path.Combine(directory, "missing-host.bin")));
        Assert.Equal(3, result.Exit);
        Assert.False(result.Json.GetProperty("mountedReadinessProven").GetBoolean());
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        result = await Run(Args, NoLaunchDependencies(), cancelled.Token);
        Assert.Equal(4, result.Exit);
        Assert.False(Directory.Exists(Session));
    }

    [Fact]
    public async Task PendingGateExistsBeforeFastWorkerCanStart()
    {
        var fake = new FakeSupervisor { RequirePendingGate = true };
        var result = await Run([.. Args, "--copy-out", Destination], Dependencies(fake));
        Assert.Equal(0, result.Exit);
        Assert.True(result.Json.GetProperty("teardownProven").GetBoolean());
    }

    [Fact]
    public async Task GracefulBrowseCancellationKeepsLeaseUntilSupervisorProvesTeardown()
    {
        using var cancellation = new CancellationTokenSource();
        var fake = new FakeSupervisor { HoldTeardown = true };
        var run = Run(Args, Dependencies(fake), cancellation.Token);
        try
        {
            await WaitFor(() => File.Exists(Path.Combine(Session, "ready.json")));
            cancellation.Cancel();
            await fake.StopObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(run.IsCompleted);
            Assert.False(fake.StopToken.IsCancellationRequested);
            AssertSourcePinned();
            fake.Teardown.TrySetResult();
            var result = await run;
            Assert.Equal(0, result.Exit);
            Assert.True(result.Json.GetProperty("success").GetBoolean());
            Assert.True(result.Json.GetProperty("mountedReadinessProven").GetBoolean());
            Assert.True(result.Json.GetProperty("teardownProven").GetBoolean());
            Assert.Equal("11", result.Json.GetProperty("selection").GetProperty("snapshotXid").GetString());
            Assert.False(File.Exists(fake.Options!.LifetimeFile));
            Assert.False(Directory.Exists(fake.Options.MountPoint));
            AssertSourceReleased();
            using var persisted = JsonDocument.Parse(File.ReadAllText(Path.Combine(Session, "result.json")));
            Assert.True(persisted.RootElement.GetProperty("success").GetBoolean());
        }
        finally
        {
            cancellation.Cancel(); fake.Teardown.TrySetResult();
            await run;
        }
    }

    [Fact]
    public async Task ControllingInputCloseKeepsOwnershipUntilTeardownIsProven()
    {
        var close = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fake = new FakeSupervisor { HoldTeardown = true };
        var run = Run([.. Args, "--close-on-stdin"], Dependencies(fake, closeInput: _ => close.Task));
        try
        {
            await WaitFor(() => File.Exists(Path.Combine(Session, "ready.json")));
            close.TrySetResult();
            await fake.StopObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(run.IsCompleted);
            Assert.False(fake.StopToken.IsCancellationRequested);
            AssertSourcePinned();
            fake.Teardown.TrySetResult();
            var result = await run;
            Assert.Equal(0, result.Exit);
            Assert.True(result.Json.GetProperty("teardownProven").GetBoolean());
            AssertSourceReleased();
        }
        finally { close.TrySetResult(); fake.Teardown.TrySetResult(); await run; }
    }

    [Fact]
    public async Task InvalidControllerInputStillWaitsForTeardownAndReportsFailure()
    {
        var close = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fake = new FakeSupervisor { HoldTeardown = true };
        var run = Run([.. Args, "--close-on-stdin"], Dependencies(fake, closeInput: _ => close.Task));
        try
        {
            await WaitFor(() => File.Exists(Path.Combine(Session, "ready.json")));
            close.TrySetException(new ArgumentException("Malformed close command."));
            await fake.StopObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(run.IsCompleted);
            AssertSourcePinned();
            fake.Teardown.TrySetResult();
            var result = await run;
            Assert.Equal(2, result.Exit);
            Assert.False(result.Json.GetProperty("success").GetBoolean());
            Assert.True(result.Json.GetProperty("teardownProven").GetBoolean());
            AssertSourceReleased();
        }
        finally { close.TrySetResult(); fake.Teardown.TrySetResult(); await run; }
    }

    [Fact]
    public async Task CloseInputIsExplicitAndDuplicateFlagsNeverLaunch()
    {
        Assert.False(SnapshotBrowseCommand.Parse(Args).CloseOnStdin);
        Assert.True(SnapshotBrowseCommand.Parse([.. Args, "--close-on-stdin"]).CloseOnStdin);
        await AssertNoLaunch([.. Args, "--close-on-stdin", "--close-on-stdin"]);
    }

    [Theory]
    [InlineData("wrong-pid")]
    [InlineData("wrong-xid")]
    [InlineData("unready")]
    [InlineData("unowned")]
    [InlineData("missing-identity")]
    [InlineData("wrong-serial")]
    [InlineData("missing-status")]
    public async Task UnprovenReadinessTimesOutWithoutCopyingAndStopsSupervisor(string refusal)
    {
        var fake = new FakeSupervisor { Refusal = refusal };
        var result = await Run([.. Args, "--copy-out", Destination], Dependencies(fake, TimeSpan.FromMilliseconds(180)));
        Assert.Equal(4, result.Exit);
        Assert.False(result.Json.GetProperty("mountedReadinessProven").GetBoolean());
        Assert.True(result.Json.GetProperty("teardownProven").GetBoolean());
        Assert.False(Directory.Exists(Destination));
        Assert.False(File.Exists(Path.Combine(Session, "ready.json")));
        Assert.True(fake.StopObserved.Task.IsCompletedSuccessfully);
        Assert.False(fake.StopToken.IsCancellationRequested);
        AssertSourceReleased();
    }

    [Fact]
    public async Task CopyOutCopiesBinaryNestedAndEmptyEntriesAndClosesAutomatically()
    {
        var binary = Enumerable.Range(0, 512).Select(i => (byte)i).ToArray();
        var fake = new FakeSupervisor { Populate = mount =>
        {
            Directory.CreateDirectory(Path.Combine(mount, "nested"));
            Directory.CreateDirectory(Path.Combine(mount, "empty directory"));
            File.WriteAllBytes(Path.Combine(mount, "payload.bin"), binary);
            File.WriteAllBytes(Path.Combine(mount, "nested", "empty file"), []);
            File.WriteAllText(Path.Combine(mount, "nested", "text.txt"), "snapshot contents");
        } };
        var result = await Run([.. Args, "--copy-out", Destination, "--json"], Dependencies(fake));
        Assert.Equal(0, result.Exit);
        Assert.True(result.Json.GetProperty("mountedReadinessProven").GetBoolean());
        Assert.True(result.Json.GetProperty("teardownProven").GetBoolean());
        var copied = result.Json.GetProperty("copyOut");
        Assert.Equal(3, copied.GetProperty("files").GetInt32());
        Assert.Equal(3, copied.GetProperty("directories").GetInt32());
        Assert.Equal(512 + "snapshot contents".Length, copied.GetProperty("bytes").GetInt64());
        Assert.Equal(binary, File.ReadAllBytes(Path.Combine(Destination, "payload.bin")));
        Assert.Equal("snapshot contents", File.ReadAllText(Path.Combine(Destination, "nested", "text.txt")));
        Assert.Empty(File.ReadAllBytes(Path.Combine(Destination, "nested", "empty file")));
        Assert.Empty(Directory.EnumerateFileSystemEntries(Path.Combine(Destination, "empty directory")));
        Assert.Equal(binary, File.ReadAllBytes(Path.Combine(fake.Options!.MountPoint!, "payload.bin")));
        Assert.True(fake.StopObserved.Task.IsCompletedSuccessfully);
        AssertSourceReleased();
    }

    [Theory]
    [InlineData("failed-supervisor")]
    [InlineData("host-still-present")]
    [InlineData("mount-still-present")]
    public async Task CopiedContentsDoNotMaskUnprovenTeardown(string failure)
    {
        var fake = new FakeSupervisor { TeardownFailure = failure };
        var result = await Run([.. Args, "--copy-out", Destination], Dependencies(fake));
        Assert.Equal(5, result.Exit);
        Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.True(result.Json.GetProperty("mountedReadinessProven").GetBoolean());
        Assert.True(Directory.Exists(Destination));
        Assert.Contains("teardown", result.Json.GetProperty("error").GetString(), StringComparison.OrdinalIgnoreCase);
        if (failure == "mount-still-present") Assert.True(Directory.Exists(fake.Options!.MountPoint));
    }

    [Fact]
    public async Task HostExitBeforeReadinessNeverReportsMountedOrCopies()
    {
        var fake = new FakeSupervisor { ExitBeforeReady = true };
        var result = await Run([.. Args, "--copy-out", Destination], Dependencies(fake));
        Assert.Equal(5, result.Exit);
        Assert.False(result.Json.GetProperty("mountedReadinessProven").GetBoolean());
        Assert.False(Directory.Exists(Destination));
        AssertSourceReleased();
    }

    [Fact]
    public async Task CopyReadFailureRetainsPartialOutputAndStillStopsSupervisor()
    {
        FileStream? held = null;
        var fake = new FakeSupervisor { Populate = mount =>
        {
            var path = Path.Combine(mount, "locked.bin");
            File.WriteAllBytes(path, [1, 2, 3]);
            held = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
        } };
        try
        {
            var result = await Run([.. Args, "--copy-out", Destination], Dependencies(fake));
            Assert.Equal(5, result.Exit);
            Assert.False(result.Json.GetProperty("success").GetBoolean());
            Assert.True(result.Json.GetProperty("mountedReadinessProven").GetBoolean());
            Assert.True(result.Json.GetProperty("teardownProven").GetBoolean());
            Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("copyOut").ValueKind);
            Assert.True(Directory.Exists(Destination));
            Assert.Empty(Directory.EnumerateFileSystemEntries(Destination));
            Assert.True(fake.StopObserved.Task.IsCompletedSuccessfully);
            AssertSourceReleased();
        }
        finally { held?.Dispose(); }
        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(Path.Combine(fake.Options!.MountPoint!, "locked.bin")));
    }

    [Fact]
    public async Task CopyOutRefusesExistingAndInsideMountDestinationsWithoutChangingFiles()
    {
        var mount = Path.Combine(directory, "ordinary source"); Directory.CreateDirectory(mount);
        File.WriteAllText(Path.Combine(mount, "source.txt"), "source sentinel");
        Directory.CreateDirectory(Destination);
        File.WriteAllText(Path.Combine(Destination, "source.txt"), "destination sentinel");
        await Assert.ThrowsAsync<ArgumentException>(() => SnapshotBrowseCommand.CopyOutAsync(mount, Destination, default));
        await Assert.ThrowsAsync<ArgumentException>(() => SnapshotBrowseCommand.CopyOutAsync(mount, mount, default));
        await Assert.ThrowsAsync<ArgumentException>(() => SnapshotBrowseCommand.CopyOutAsync(mount, Path.Combine(mount, "nested"), default));
        Assert.Equal("destination sentinel", File.ReadAllText(Path.Combine(Destination, "source.txt")));
        Assert.Equal("source sentinel", File.ReadAllText(Path.Combine(mount, "source.txt")));
        Assert.False(Directory.Exists(Path.Combine(mount, "nested")));
    }

    [Fact]
    public async Task CancelledCopyNeverReadsOrDeletesSourceAndRetainsPartialDestination()
    {
        var mount = Path.Combine(directory, "ordinary source"); Directory.CreateDirectory(mount);
        File.WriteAllText(Path.Combine(mount, "source.txt"), "source sentinel");
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => SnapshotBrowseCommand.CopyOutAsync(mount, Destination, cancelled.Token));
        Assert.Equal("source sentinel", File.ReadAllText(Path.Combine(mount, "source.txt")));
        Assert.True(Directory.Exists(Destination));
        Assert.Empty(Directory.EnumerateFileSystemEntries(Destination));
    }

    [Fact]
    public async Task CopyDestinationWithCommonNamePrefixOutsideMountIsAllowed()
    {
        var mount = Path.Combine(directory, "mount"); Directory.CreateDirectory(mount);
        File.WriteAllBytes(Path.Combine(mount, "payload.bin"), [1, 2, 3]);
        var copy = await SnapshotBrowseCommand.CopyOutAsync(mount, mount + "-copy", default);
        Assert.Equal(new SnapshotCopyResult(1, 1, 3), copy);
        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(Path.Combine(mount + "-copy", "payload.bin")));
    }

    [Fact]
    public async Task DefaultSessionLivesUnderConfiguredTempRoot()
    {
        var fake = new FakeSupervisor();
        var args = Args.Take(9).Concat(new[] { "--copy-out", Destination }).ToArray();
        var result = await Run(args, Dependencies(fake));
        Assert.Equal(0, result.Exit);
        var session = result.Json.GetProperty("sessionDirectory").GetString()!;
        Assert.Equal(Path.Combine(Path.GetTempPath(), "ApfsAccess", "SnapshotBrowse"), Path.GetDirectoryName(session));
        Assert.True(Guid.TryParseExact(Path.GetFileName(session), "D", out _));
        Directory.Delete(session, recursive: true);
    }

    private async Task AssertNoLaunch(string[] args)
    {
        var result = await Run(args, NoLaunchDependencies());
        Assert.Equal(2, result.Exit);
        Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.False(result.Json.GetProperty("mountedReadinessProven").GetBoolean());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("selection").ValueKind);
    }

    private SnapshotBrowseDependencies NoLaunchDependencies(string? host = null) => new()
    {
        HostPath = host ?? Host,
        Prepare = (_, _) => throw new InvalidOperationException("Unexpected inventory preparation."),
        Supervise = (_, _) => throw new InvalidOperationException("Unexpected host launch.")
    };

    private SnapshotBrowseDependencies Dependencies(FakeSupervisor fake, TimeSpan? startupTimeout = null,
        Func<CancellationToken, Task>? closeInput = null) => new()
    {
        HostPath = Host,
        StartupTimeout = startupTimeout ?? TimeSpan.FromSeconds(3),
        WaitForCloseInput = closeInput ?? (token => SnapshotBrowseCommand.WaitForCloseInputAsync(Console.In, token)),
        Prepare = (options, token) => NativeSnapshotBrowseLaunch.Prepare(options.Image, options.ContainerId, options.VolumeOid,
            options.SnapshotXid, (_, _, _, _) => Inventory(), token),
        Supervise = fake.Start,
        ReadJson = fake.Read,
        ProbeMount = (mount, serial) =>
        {
            Assert.Equal(fake.Options!.MountPoint, mount);
            Assert.NotEqual(0u, serial);
            AssertSourcePinned();
            return fake.Refusal != "wrong-serial";
        }
    };

    private JsonElement Inventory()
    {
        using var stream = File.OpenRead(Image);
        return JsonSerializer.SerializeToElement(new {
            format = "apfs-access-snapshot-inventory", version = 1, readOnly = true,
            source = new { kind = "image", path = Image, sizeBytes = stream.Length, hashScope = "full", sha256 = Convert.ToHexStringLower(SHA256.HashData(stream)) },
            containerUuid = new string('a', 32), volumeUuid = new string('b', 32),
            volumeId = "apfs-vol:" + new string('a', 32) + ":101", volumeOid = "101", checkpointXid = "20",
            storeOffsetBytes = "4096", storeSizeBytes = "4096",
            snapshots = new[] { new { xid = "11", name = "second backup", createTimeNs = "0", superblockPhysicalBlock = "1",
                omapPhysicalBlock = "2", omapTreePhysicalBlock = "3", rootOid = "4", rootPhysicalBlock = "5", extentrefPhysicalBlock = "6" } }
        });
    }

    private void AssertSourcePinned()
        => Assert.Throws<IOException>(() => { using var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete); });

    private void AssertSourceReleased() { using var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.None); Assert.Equal(8192, writer.Length); }

    private static async Task<(int Exit, JsonElement Json)> Run(string[] args, SnapshotBrowseDependencies deps, CancellationToken token = default)
    {
        var previousOut = Console.Out; var previousError = Console.Error;
        using var output = new StringWriter(); using var error = new StringWriter();
        try
        {
            Console.SetOut(output); Console.SetError(error);
            var exit = await SnapshotBrowseCommand.RunAsync(args, deps, token);
            using var json = JsonDocument.Parse(output.ToString());
            return (exit, json.RootElement.Clone());
        }
        finally { Console.SetOut(previousOut); Console.SetError(previousError); }
    }

    private static async Task WaitFor(Func<bool> predicate)
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!predicate()) await Task.Delay(10, limit.Token);
    }

    // The fake completes only after the command removes its lifetime file. It never starts a process.
    private sealed class FakeSupervisor
    {
        public bool RequirePendingGate { get; init; }
        public string? Refusal { get; init; }
        public string? TeardownFailure { get; init; }
        public bool HoldTeardown { get; init; }
        public bool ExitBeforeReady { get; init; }
        public Action<string>? Populate { get; init; }
        public FsHostSupervisorOptions? Options { get; private set; }
        public CancellationToken StopToken { get; private set; }
        public TaskCompletionSource StopObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Teardown { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<FsHostSupervisorResult> Start(FsHostSupervisorOptions options, CancellationToken token)
        {
            if (RequirePendingGate)
            {
                Assert.True(File.Exists(options.StartupGateFile), "A fast worker must see a pending gate before the supervisor resumes it.");
                Assert.Equal("pending", File.ReadAllText(options.StartupGateFile!));
                Assert.NotEqual(options.StartupGateToken, File.ReadAllText(options.StartupGateFile!));
            }
            Options = options; StopToken = token;
            Assert.True(File.Exists(options.LifetimeFile));
            Assert.True(Directory.Exists(Path.GetDirectoryName(options.MountPoint)));
            Assert.False(Directory.Exists(options.MountPoint));
            Assert.False(File.Exists(options.MountPoint));
            Assert.Contains("--readonly", options.HostArguments);
            Assert.Equal("Disabled", options.HostArguments[Array.IndexOf(options.HostArguments.ToArray(), "--write-backend") + 1]);
            Assert.DoesNotContain("--readwrite", options.HostArguments);
            // Emulate the host creating its mount only after it receives an absent leaf.
            Directory.CreateDirectory(options.MountPoint!);
            Populate?.Invoke(options.MountPoint!);
            return ExitBeforeReady ? Task.FromResult(Terminal()) : Finish();
        }

        private async Task<FsHostSupervisorResult> Finish()
        {
            await WaitFor(() => !File.Exists(Options!.LifetimeFile));
            StopObserved.TrySetResult();
            if (HoldTeardown) await Teardown.Task.WaitAsync(TimeSpan.FromSeconds(10));
            return Terminal();
        }

        private FsHostSupervisorResult Terminal() => new(TeardownFailure == "failed-supervisor" ? 5 : 0,
            new FsHostSupervisorEvidence {
                OriginalHostIdentityAbsent = TeardownFailure != "host-still-present",
                MountAbsenceProven = TeardownFailure != "mount-still-present"
            });

        public JsonElement? Read(string path)
        {
            Assert.NotNull(Options);
            if (path == Options.LaunchRecordPath)
                return JsonSerializer.SerializeToElement(new {
                    supervisionProven = Refusal != "unowned", hostIdentityCaptured = Refusal != "missing-identity", hostPid = 1234
                });
            Assert.Equal(Options.StatusFile, path);
            if (Refusal == "missing-status") return null;
            var status = JsonSerializer.SerializeToNode(new {
                hostPid = 1234, mountReady = true, immutableSnapshot = true, explicitReadOnly = true, writeBackend = "Disabled",
                snapshotContainerId = new string('a', 32), snapshotVolumeOid = 101UL, snapshotXid = "11", snapshotName = "second backup"
            })!.AsObject();
            if (Refusal == "wrong-pid") status["hostPid"] = 5678;
            if (Refusal == "wrong-xid") status["snapshotXid"] = "10";
            if (Refusal == "unready") status["mountReady"] = false;
            return JsonSerializer.SerializeToElement(status);
        }
    }
}
