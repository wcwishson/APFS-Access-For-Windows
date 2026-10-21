using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.StandardMount;

namespace ApfsAccess.Cli;

internal sealed record StandardShareOptionsRequest(string Image, string ContainerId, string VolumeOid,
    string JournalRoot, string SpoolRoot, string RecoveryRoot, string SessionDirectory, int Port, bool CloseOnStdin);

internal static class StandardShareCommand
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    internal const string Usage = "standard-share mount --image FILE --container-id apfs-container:HEX --volume-oid OID --journal-dir EXISTING_DIRECTORY --spool-dir EXISTING_DIRECTORY --recovery-dir EXISTING_DIRECTORY --session-dir NEW_DIRECTORY [--port NUMBER] [--close-on-stdin] [--json]";
    internal static StandardShareOptionsRequest Parse(string[] args)
    {
        if (args.Length == 0 || args[0] != "mount") throw new ArgumentException(Usage);
        var values = new Dictionary<string, string>(StringComparer.Ordinal); var close = false; var json = false;
        for (var i = 1; i < args.Length; ++i)
        {
            var key = args[i];
            if (key == "--close-on-stdin" && !close) { close = true; continue; }
            if (key == "--json" && !json) { json = true; continue; }
            if (key is not ("--image" or "--container-id" or "--volume-oid" or "--journal-dir" or "--spool-dir" or "--recovery-dir" or "--session-dir" or "--port") ||
                ++i >= args.Length || args[i].StartsWith("--", StringComparison.Ordinal) || !values.TryAdd(key, args[i])) throw new ArgumentException(Usage);
        }
        var required = new[] { "--image", "--container-id", "--volume-oid", "--journal-dir", "--spool-dir", "--recovery-dir", "--session-dir" };
        if (required.Any(key => !values.ContainsKey(key))) throw new ArgumentException(Usage);
        var port = 0;
        if (values.TryGetValue("--port", out var text) && (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out port) ||
            port is <= 1024 or > 65535)) throw new ArgumentException("Use a TCP port from 1025 to 65535.");
        NativeApfsSnapshotReader.ValidateRequest(values["--image"], values["--container-id"], values["--volume-oid"]);
        foreach (var key in new[] { "--journal-dir", "--spool-dir", "--recovery-dir" }) NativeApfsVolumeManagement.ValidateStoreRoot(values[key]);
        NativeSnapshotBrowseLaunch.ValidateLocalPath(values["--session-dir"]);
        if (Directory.Exists(values["--session-dir"]) || File.Exists(values["--session-dir"])) throw new ArgumentException("The session directory must be new.");
        return new(values["--image"], values["--container-id"], values["--volume-oid"], values["--journal-dir"],
            values["--spool-dir"], values["--recovery-dir"], values["--session-dir"], port, close);
    }

    internal static async Task<int> RunAsync(string[] args, CancellationToken token = default)
    {
        if (args is ["--help"] or ["help"] or ["mount", "--help"])
        {
            Console.WriteLine(JsonSerializer.Serialize(new { command = "standard-share", usage = Usage,
                profile = "ordinary-image-standard-share-v1", defaultProvider = false, maximumImageBytes = 256L << 20,
                authentication = "ephemeral-loopback", signingRequired = true, leases = false, durableReconnect = false,
                maximumConcurrentPublicSessions = 1, sessionScope = "CurrentWindowsLogon" }));
            return 0;
        }
        StandardShareOptionsRequest? options = null; NativeStandardOwner? owner = null;
        StreamNativeTransport? transport = null; LoopbackStandardMount? mount = null;
        StandardMountRetirement? terminal = null; NativeStandardOwnerExit? ownerExit = null;
        StandardPublicSessionAdmission? admission = null;
        StandardPublicSessionRefusal? admissionRefusal = null;
        StandardNativeRetirement? standaloneRetirement = null;
        var admissionReleased = false;
        string? failure = null, failureStage = null, sharePath = null; var ready = false; var exit = 0;
        Task? failedLaunchCleanup = null;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var inputStop = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; stop.Cancel(); };
        Console.CancelKeyPress += cancel;
        try
        {
            options = Parse(args);
            failureStage = "SessionAdmission";
            admission = StandardPublicSessionAdmission.Acquire();
            failureStage = "NativeOwnerStart";
            owner = NativeStandardOwner.Start(options.Image, options.ContainerId, options.VolumeOid, options.JournalRoot,
                options.SpoolRoot, options.RecoveryRoot, options.SessionDirectory, stop.Token);
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
            startup.CancelAfter(TimeSpan.FromSeconds(60));
            var selected = owner.Selection;
            failureStage = "NativeHello";
            transport = await StreamNativeTransport.ConnectAsync(owner.ToOwner, owner.FromOwner,
                selected.SourceIdentity, selected.VolumeIdentity, selected.CheckpointXid,
                async ct => {
                    var observed = await owner.ObserveExitAsync(ct).ConfigureAwait(false);
                    return new(observed.ProcessExited, observed.JobEmpty, observed.NamespaceAbsent, observed.ExitCode);
                }, startup.Token).ConfigureAwait(false);
            var port = options.Port;
            if (port == 0)
            {
                var probe = new TcpListener(IPAddress.Loopback, 0);
                try { probe.Start(); port = ((IPEndPoint)probe.LocalEndpoint).Port; }
                finally { probe.Stop(); }
            }
            var share = StandardShareOptions.Create(port); sharePath = share.RemotePath;
            failureStage = "LoopbackMapping";
            mount = new(transport, share, new WindowsLoopbackMapping());
            await mount.StartAsync(startup.Token).ConfigureAwait(false);
            ready = mount.CachedStatus.Phase == StandardMountPhase.Serving;
            if (!ready) throw new IOException("Standard-share serving state was not admitted.");
            failureStage = null;
            WriteReadyJson(Path.Combine(options.SessionDirectory, "ready.json"), new {
                schemaVersion = 1, command = "standard-share", ready, sharePath, port, owner.Selection,
                owner.ProcessId, owner.ProcessCreationTimeFileTimeUtc, features = transport.Binding.Features.ToString(),
                profile = "ordinary-image-standard-share-v1", signingRequired = true, innerKernelMount = false,
                maximumConcurrentPublicSessions = 1, sessionScope = "CurrentWindowsLogon" });
            Console.Error.WriteLine($"APFS standard share is ready at {sharePath}. Press Ctrl+C to close.");
            var input = options.CloseOnStdin ? Task.Run(() => SnapshotBrowseCommand.WaitForCloseInputAsync(Console.In, inputStop.Token))
                : Task.Delay(Timeout.Infinite, inputStop.Token);
            var terminated = owner.WaitForExitAsync();
            var closed = await Task.WhenAny(input, terminated, Task.Delay(Timeout.Infinite, stop.Token)).ConfigureAwait(false);
            if (closed == terminated) throw new IOException("The native standard-share owner exited before requested close.");
            if (closed == input) await input.ConfigureAwait(false);
        }
        catch (ArgumentException e) { exit = 2; failure = e.Message; }
        catch (StandardPublicSessionException e) { exit = 6; failure = e.Message; admissionRefusal = e.Reason; failureStage = "SessionAdmission"; }
        catch (OperationCanceledException e) { exit = ready ? 0 : 4; failure = ready ? null : e.Message; }
        catch (Exception e) { exit = 5; failure = e.Message; failureStage = e.Data["StandardShareLaunchStage"] as string ?? failureStage;
            failedLaunchCleanup = e.Data["StandardShareLaunchCleanup"] as Task; }
        finally
        {
            inputStop.Cancel();
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(65));
            try
            {
                if (mount is not null) terminal = await mount.StopAsync(cleanup.Token).ConfigureAwait(false);
                else if (transport is not null) standaloneRetirement = await transport.RetireAsync(cleanup.Token).ConfigureAwait(false);
                if (mount is not null && terminal?.Clean != true) { exit = 5; failure = "Standard-share retirement remains unproved; preserve the session and original journals."; }
                if (mount is not null && terminal?.Clean == true) await mount.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception e) { exit = 5; failure = "Standard-share cleanup remains pending: " + e.Message; }
            try
            {
                if (failedLaunchCleanup is not null) await failedLaunchCleanup.WaitAsync(cleanup.Token).ConfigureAwait(false);
                if (owner is not null)
                {
                    await owner.DisposeAsync().ConfigureAwait(false);
                    ownerExit = await owner.ObserveExitAsync(cleanup.Token).ConfigureAwait(false);
                }
            }
            catch (Exception e) { exit = 5; failure = "Standard-share owner retirement remains pending: " + e.Message; }
            if (admission is not null)
            {
                var originalAbsent = ownerExit is { ProcessExited: true, JobEmpty: true, NamespaceAbsent: true, ExitCode: 0 };
                var canRelease = owner is null ? failedLaunchCleanup is null || failedLaunchCleanup.IsCompletedSuccessfully
                    : originalAbsent && (mount is not null ? terminal?.Clean == true : transport is null ||
                        standaloneRetirement is { OriginalOwnerAbsent: true, NamespaceAbsent: true, Clean: true, Status: 0 } clean &&
                        clean.AcceptedSequence == clean.DurableSequence && clean.DurableSequence == clean.CleanedSequence);
                if (canRelease) { admission.Dispose(); admissionReleased = true; }
                else admission.RetainUntilProcessExit();
            }
            Console.CancelKeyPress -= cancel;
        }
        var result = new { schemaVersion = 1, command = "standard-share", success = exit == 0, exitCode = exit, error = failure, failureStage,
            profile = "ordinary-image-standard-share-v1", sharePath, ready = false, wasReady = ready,
            phase = exit == 0 ? "Closed" : "Failed", terminal, ownerExit, selection = owner?.Selection,
            admission = new { scope = "CurrentWindowsLogon", maximumConcurrentPublicSessions = 1,
                refusal = admissionRefusal?.ToString(), released = admissionReleased, nativeOwnerStarted = owner is not null,
                action = admissionRefusal == StandardPublicSessionRefusal.SessionActive ? "CloseExistingSessionAndRetry" :
                    admissionRefusal is not null ? "FinishExistingSessionRetirement" : null } };
        var serialized = JsonSerializer.Serialize(result, Json);
        if (owner is not null) File.WriteAllText(Path.Combine(options!.SessionDirectory, "result.json"), serialized);
        Console.WriteLine(serialized); return exit;
    }

    private static void WriteReadyJson(string path, object value)
    {
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var created = false;
        try
        {
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                created = true;
                JsonSerializer.Serialize(stream, value, Json);
            }
            File.Move(temporaryPath, path);
        }
        finally
        {
            if (created)
            {
                try { File.Delete(temporaryPath); } catch { }
            }
        }
    }
}
