using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Cli;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

internal static class ImageKeyManagementPackagedRouteProbe
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, Converters = { new JsonStringEnumConverter() } };

    private static async Task<int> Main(string[] args)
    {
        // The existing native driver supplies the managed entry point before its
        // public arguments. The actual process here is the private Tray apphost.
        if (args.Length == 6 && args[0].EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) args = args[1..];
        Process? service = null; Task<string>? serviceOut = null, serviceError = null;
        string? operationDirectory = null, pipe = null; var exitCode = 7;
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(6));
        try
        {
            if (args.Length != 5) throw new ArgumentException();
            var request = JsonSerializer.Deserialize<ImageKeyManagementRequest>(File.ReadAllText(args[0]), Json)!;
            if (!request.IsValid()) throw new ArgumentException();
            using var credentials = request.Action == ImageKeyManagementAction.Observe ? null :
                SupervisedCredentialSet.Receive(SupervisedCredential.TakeStandardInput(), request.CredentialCount, deadline.Token, () => { });
            operationDirectory = Path.Combine(args[3], request.OperationId); Directory.CreateDirectory(operationDirectory);
            var endpointFile = Path.Combine(operationDirectory, "endpoint.json");
            File.WriteAllText(endpointFile, JsonSerializer.Serialize(request.Expected, Json));
            var instance = Guid.NewGuid(); pipe = FusionControlEndpoint.ForPrivateInstance(instance);
            var launch = Info("ApfsAccess.Service.exe", operationDirectory);
            foreach (var pair in new Dictionary<string, string> {
                ["BackendMode"]="Native", ["NativeFsHostPath"]=args[1], ["ManagementJournalRoot"]=args[2],
                ["PrivateControlInstanceId"]=instance.ToString("D"), ["EnableNativeWrite"]="true",
                ["NativeAutoDiscoverPhysicalDrives"]="false", ["AutoMountEnabled"]="false", ["NativeAutoRemountOnReconnect"]="false",
                ["EnablePhysicalVolumeManagement"]="false", ["NativeWriteAllowRawPhysicalDevices"]="false",
                ["EnableImageSnapshots"]="false", ["EnableImageManagementMutations"]="false", ["EnableImageResizeFormat"]="false",
                ["NativeWriteEvidenceStorePath"]=Path.Combine(operationDirectory,"native-evidence.json"), ["PollSeconds"]="2" })
                launch.Environment["Service__" + pair.Key] = pair.Value;
            service = Process.Start(launch) ?? throw new IOException();
            serviceOut = service.StandardOutput.ReadToEndAsync(); serviceError = service.StandardError.ReadToEndAsync();
            File.WriteAllText(Path.Combine(operationDirectory, "service-owner.json"), JsonSerializer.Serialize(new {
                pid = service.Id, creationTimeFileTimeUtc = service.StartTime.ToUniversalTime().ToFileTimeUtc(), instance, pipe }));
            for (var i = 0; ; ++i)
            {
                if (service.HasExited || i == 60) throw new IOException("PrivateServiceReadinessRefused");
                try
                {
                    await using var ready = await NamedPipeMessageClient.ConnectAsync(pipe, 500, deadline.Token);
                    var greeting = await ready.ReadMessageAsync(deadline.Token);
                    if (greeting?.Type == ApfsMessageTypes.StatusChanged) break;
                }
                catch (OperationCanceledException) { throw; }
                catch { }
                await Task.Delay(200, deadline.Token);
            }
            var cli = Info("ApfsAccess.Cli.exe", operationDirectory); cli.RedirectStandardInput = true;
            var action = request.Action switch { ImageKeyManagementAction.ChangePassword => "change-password",
                ImageKeyManagementAction.RotateVolumeKey => "rotate", ImageKeyManagementAction.Encrypt => "encrypt",
                ImageKeyManagementAction.Observe => "observe", _ => "decrypt" };
            foreach (var argument in new[] { "image-keys", action, "--endpoint", endpointFile,
                "--operation-id", request.OperationId, "--private-instance", instance.ToString("D") }) cli.ArgumentList.Add(argument);
            if (credentials is not null) cli.ArgumentList.Add("--credential-stdin");
            using var child = Process.Start(cli) ?? throw new IOException();
            var stdout = child.StandardOutput.ReadToEndAsync(); var stderr = child.StandardError.ReadToEndAsync();
            if (credentials is not null) await credentials.SendAsync(child.StandardInput.BaseStream, deadline.Token);
            child.StandardInput.Close();
            await child.WaitForExitAsync(deadline.Token);
            var output = await stdout; var diagnostics = await stderr;
            File.WriteAllText(Path.Combine(operationDirectory, "cli-result.json"), output);
            File.WriteAllText(Path.Combine(operationDirectory, "cli-diagnostic.log"), diagnostics);
            var result = await Query(pipe, request.OperationId, deadline.Token);
            if (result.KeyManagement != request || result.Fingerprint != ApfsOperationFingerprint.ComputeForResult(result) ||
                result.Success != (child.ExitCode == 0)) throw new IOException("PublicReceiptBindingRefused");
            exitCode = child.ExitCode;
            if (result.Success)
            {
                var receipt = result.KeyManagementReceipt ?? throw new IOException();
                if (!receipt.Proves(request)) throw new IOException();
                using var file = new FileStream(args[4], FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                JsonSerializer.Serialize(file, receipt, Json); file.Flush(true);
                Console.WriteLine("PUBLIC_CLI_AUTHENTICATED_SERVICE_NATIVE_KEYS_PASS");
            }
        }
        catch (Exception error) { Console.WriteLine(JsonSerializer.Serialize(new { refused = true, errorType = error.GetType().Name })); }
        finally
        {
            if (service is not null)
            {
                using var retirement = new CancellationTokenSource(TimeSpan.FromSeconds(100));
                try
                {
                    if (!service.HasExited && pipe is not null) await Quit(pipe, retirement.Token);
                    await service.WaitForExitAsync(retirement.Token);
                    if (serviceOut is not null) File.WriteAllText(Path.Combine(operationDirectory!, "service-stdout.log"), await serviceOut);
                    if (serviceError is not null) File.WriteAllText(Path.Combine(operationDirectory!, "service-stderr.log"), await serviceError);
                    if (service.ExitCode != 0) exitCode = 7;
                    File.WriteAllText(Path.Combine(operationDirectory!, "service-retired.json"), JsonSerializer.Serialize(new {
                        pid = service.Id, service.ExitCode, exited = service.HasExited, forced = false }));
                    service.Dispose();
                }
                catch { exitCode = 7; Console.WriteLine("PRIVATE_SERVICE_RETIREMENT_PENDING"); }
            }
        }
        return exitCode;
    }

    private static ProcessStartInfo Info(string name, string root)
    {
        var info = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, name)) { UseShellExecute = false, CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var key in info.Environment.Keys.Where(k => k.StartsWith("APFSACCESS_", StringComparison.OrdinalIgnoreCase) ||
            k.StartsWith("Service__", StringComparison.OrdinalIgnoreCase)).ToArray()) info.Environment.Remove(key);
        info.Environment["APFSACCESS_RUNTIME_ROOT"] = Path.Combine(root, "runtime");
        info.Environment["APFSACCESS_SPOOL_ROOT"] = Path.Combine(root, "spool");
        info.Environment["TEMP"] = info.Environment["TMP"] = Path.Combine(root, "temp");
        Directory.CreateDirectory(info.Environment["TEMP"]!); return info;
    }

    private static async Task<OperationResultPayload> Query(string pipe, string id, CancellationToken token)
    {
        await using var peer = await NamedPipeMessageClient.ConnectAsync(pipe, 2000, token);
        _ = await peer.ReadMessageAsync(token);
        await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery, new OperationResultQueryPayload(id), id, 2), token);
        var response = await peer.ReadMessageAsync(token) ?? throw new IOException();
        if (!PipeMessageCodec.Validate(response).IsValid || !PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result) ||
            result is null || result.OperationId != id) throw new IOException("PublicOperationQueryRefused");
        return result;
    }

    private static async Task Quit(string pipe, CancellationToken token)
    {
        await using var peer = await NamedPipeMessageClient.ConnectAsync(pipe, 2000, token);
        _ = await peer.ReadMessageAsync(token);
        var id = Guid.NewGuid().ToString("D");
        await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,
            new ControlOperationRequestPayload(id, ApfsControlCommands.Quit, null, ExpiresAtUtc: DateTime.UtcNow.AddSeconds(60)), id, 2), token);
        while (true)
        {
            var response = await peer.ReadMessageAsync(token) ?? throw new IOException();
            if (response.Type != ApfsMessageTypes.OperationResult || response.RequestId != id) continue;
            if (!PipeMessageCodec.Validate(response).IsValid || !PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result) || result is null)
                throw new IOException();
            if (result.State is ApfsOperationStates.Accepted or ApfsOperationStates.InProgress)
            {
                await Task.Delay(200, token);
                await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery, new OperationResultQueryPayload(id), id, 2), token); continue;
            }
            if (!result.Success) throw new IOException(); return;
        }
    }
}
