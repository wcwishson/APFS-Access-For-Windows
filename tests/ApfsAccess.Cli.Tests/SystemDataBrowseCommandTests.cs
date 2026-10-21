using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class SystemDataBrowseCommandTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "system-data-cli-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "pair.apfs");
    private string Host => Path.Combine(directory, "host-placeholder.exe");
    private string Session => Path.Combine(directory, "session");
    private string Output => Path.Combine(directory, "copy");
    private string[] Args => ["browse", "--image", Image, "--container-id", "apfs-container:" + new string('a', 32), "--group-uuid", new string('d', 32),
        "--system-oid", "101", "--data-oid", "102", "--checkpoint-xid", "20", "--session-dir", Session];
    public SystemDataBrowseCommandTests() { Directory.CreateDirectory(directory); File.WriteAllBytes(Image, new byte[4096]); File.WriteAllBytes(Host, [0]); }
    public void Dispose() => Directory.Delete(directory, true);

    [Theory]
    [InlineData("--readwrite")]
    [InlineData("--write-backend")]
    [InlineData("--image")]
    [InlineData("--group-uuid")]
    [InlineData("--system-oid")]
    [InlineData("--data-oid")]
    [InlineData("--checkpoint-xid")]
    [InlineData("--caller-records")]
    public async Task UnknownWritableAndDuplicateFlagsNeverReachLaunch(string flag)
    {
        var result = await Run([.. Args, flag, "value"], new() { HostPath = Host, Prepare = (_, _) => throw new Exception("Prepared invalid request"), Supervise = (_, _) => throw new Exception("Launched invalid request") });
        Assert.Equal(2, result.Exit); Assert.False(result.Json.GetProperty("nativeAdmissionProven").GetBoolean()); Assert.False(Directory.Exists(Session));
    }

    [Fact]
    public async Task ReadOnlyCopyAwaitsOwnedTeardownAndRetainsSourceLease()
    {
        var fake = new Fake { Hold = true }; var task = Run([.. Args, "--copy-out", Output], Deps(fake));
        await fake.Stopping.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(task.IsCompleted); Assert.Throws<IOException>(() => { using var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); });
        fake.Release.TrySetResult(); var result = await task;
        Assert.Equal(0, result.Exit); Assert.True(result.Json.GetProperty("nativeAdmissionProven").GetBoolean()); Assert.True(result.Json.GetProperty("teardownProven").GetBoolean());
        Assert.Equal("independent fake content", File.ReadAllText(Path.Combine(Output, "payload")));
        Assert.Equal("unverified", result.Json.GetProperty("capability").GetProperty("genuineMacCorpus").GetString());
        using var released = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.None);
    }

    [Theory]
    [InlineData("wrong-group")]
    [InlineData("unready")]
    [InlineData("caller-records")]
    public async Task InvalidNativeAdmissionTimesOutAndNeverCopies(string refusal)
    {
        var fake = new Fake { Refusal = refusal }; var result = await Run([.. Args, "--copy-out", Output], Deps(fake));
        Assert.Equal(4, result.Exit); Assert.False(result.Json.GetProperty("nativeAdmissionProven").GetBoolean()); Assert.False(Directory.Exists(Output));
        Assert.True(fake.Stopping.Task.IsCompleted); using var released = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.None);
    }

    [Theory]
    [InlineData("force")]
    [InlineData("present")]
    [InlineData("mount")]
    public async Task SuccessfulCopyCannotMaskBadTeardown(string failure)
    {
        var fake = new Fake { Failure = failure }; var result = await Run([.. Args, "--copy-out", Output], Deps(fake));
        Assert.Equal(5, result.Exit); Assert.False(result.Json.GetProperty("success").GetBoolean()); Assert.True(File.Exists(Path.Combine(Output, "payload")));
    }

    [Fact]
    public async Task PublicDispatchHelpAndCapabilitiesDescribeOnlyTheReadOnlyImageRoute()
    {
        var previous = Console.Out; using var output = new StringWriter();
        try
        {
            Console.SetOut(output); Assert.Equal(0, await Program.Main(["system-data", "browse", "--help"]));
            using (var help = JsonDocument.Parse(output.ToString())) Assert.Equal("system-data-browse", help.RootElement.GetProperty("command").GetString());
            output.GetStringBuilder().Clear(); Assert.Equal(0, await Program.Main(["capabilities"]));
            using var capabilities = JsonDocument.Parse(output.ToString()); var route = capabilities.RootElement.GetProperty("systemDataBrowse");
            Assert.False(route.GetProperty("unifiedMutations").GetBoolean()); Assert.False(route.GetProperty("serviceMount").GetBoolean());
            Assert.Equal("unverified", route.GetProperty("genuineMacCorpus").GetString());
            Assert.Contains("system-data", capabilities.RootElement.GetProperty("commands").EnumerateArray().Select(v => v.GetString()));
        }
        finally { Console.SetOut(previous); }
    }

    [Fact]
    public async Task PublicDispatchRejectsWritableArgumentsBeforeCreatingASession()
    {
        var previous = Console.Out; using var output = new StringWriter();
        try
        {
            Console.SetOut(output); Assert.Equal(2, await Program.Main(["system-data", "browse", "--readwrite"]));
            using var result = JsonDocument.Parse(output.ToString()); Assert.False(result.RootElement.GetProperty("nativeAdmissionProven").GetBoolean());
            Assert.False(Directory.Exists(Session));
        }
        finally { Console.SetOut(previous); }
    }

    [Fact]
    public async Task PendingGateExistsBeforeFastWorkerCanStart()
    {
        var result = await Run([.. Args, "--copy-out", Output], Deps(new Fake { RequirePendingGate = true }));
        Assert.Equal(0, result.Exit);
        Assert.True(result.Json.GetProperty("teardownProven").GetBoolean());
    }

    private SystemDataBrowseDependencies Deps(Fake fake) => new() { HostPath = Host, StartupTimeout = TimeSpan.FromMilliseconds(180),
        Supervise = fake.Start, ReadJson = fake.Read, ProbeMount = (_, serial) => serial != 0 };
    private static async Task<(int Exit, JsonElement Json)> Run(string[] args, SystemDataBrowseDependencies deps)
    {
        var previous = Console.Out; var error = Console.Error; using var output = new StringWriter(); using var errors = new StringWriter();
        try { Console.SetOut(output); Console.SetError(errors); var exit = await SystemDataBrowseCommand.RunAsync(args, deps); using var json = JsonDocument.Parse(output.ToString()); return (exit, json.RootElement.Clone()); }
        finally { Console.SetOut(previous); Console.SetError(error); }
    }
    private sealed class Fake
    {
        public bool RequirePendingGate { get; init; }
        public bool Hold { get; init; }
        public string? Refusal { get; init; }
        public string? Failure { get; init; }
        public TaskCompletionSource Stopping { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private FsHostSupervisorOptions options = null!;
        public async Task<FsHostSupervisorResult> Start(FsHostSupervisorOptions o, CancellationToken token)
        {
            if (RequirePendingGate)
            {
                Assert.True(File.Exists(o.StartupGateFile), "A fast worker must see a pending gate before the supervisor resumes it.");
                Assert.Equal("pending", File.ReadAllText(o.StartupGateFile!));
                Assert.NotEqual(o.StartupGateToken, File.ReadAllText(o.StartupGateFile!));
            }
            options = o; Assert.Contains("--readonly", o.HostArguments); Assert.DoesNotContain("--readwrite", o.HostArguments);
            Directory.CreateDirectory(o.MountPoint!); File.WriteAllText(Path.Combine(o.MountPoint!, "payload"), "independent fake content");
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (File.Exists(o.LifetimeFile)) await Task.Delay(10, deadline.Token);
            Stopping.TrySetResult(); if (Hold) await Release.Task.WaitAsync(TimeSpan.FromSeconds(5));
            return new(0, new() { OriginalHostIdentityAbsent = Failure != "present", MountAbsenceProven = Failure != "mount", ForcedJobTermination = Failure == "force" });
        }
        public JsonElement? Read(string path)
        {
            if (path == options.LaunchRecordPath) return JsonSerializer.SerializeToElement(new { supervisionProven = true, hostIdentityCaptured = true, hostPid = 123 });
            var status = JsonSerializer.SerializeToNode(new { hostPid = 123, mountReady = Refusal != "unready", volumeLabel = "System label",
                systemDataRoute = "ImageTableReadOnly", systemDataAuthority = Refusal == "caller-records" ? "CallerRecords" : "CanonicalSystemTable",
                systemDataWritable = false, systemDataGenuineMacCorpus = "Unverified", explicitReadOnly = true, writeBackend = "Disabled",
                systemDataCheckpointXid = "20", systemDataSystemOid = "101", systemDataDataOid = "102", systemDataGroup = new string(Refusal == "wrong-group" ? 'e' : 'd', 32),
                snapshotContainerId = new string('a', 32), systemDataPairs = 19, walAcceptedSequence = 0, walApfsDurableSequence = 0, walCleanupSequence = 0 });
            return JsonSerializer.SerializeToElement(status);
        }
    }
}
