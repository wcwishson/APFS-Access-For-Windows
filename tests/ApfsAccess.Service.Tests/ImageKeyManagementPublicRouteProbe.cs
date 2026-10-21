using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

internal static class ImageKeyManagementPublicRouteProbe
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, Converters = { new JsonStringEnumConverter() } };

    internal static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length != 5) throw new ArgumentException();
            var request = JsonSerializer.Deserialize<ImageKeyManagementRequest>(File.ReadAllText(args[0]), Json)!;
            if (!request.IsValid()) throw new ArgumentException();
            CheckBinding(request);
            var operationDirectory = Path.Combine(args[3], request.OperationId);
            Directory.CreateDirectory(operationDirectory);
            var temp = Path.Combine(operationDirectory, "temp"); Directory.CreateDirectory(temp);
            Environment.SetEnvironmentVariable("TEMP", temp); Environment.SetEnvironmentVariable("TMP", temp);
            var endpointFile = Path.Combine(operationDirectory, "endpoint.json");
            File.WriteAllText(endpointFile, JsonSerializer.Serialize(request.Expected, Json));
            var options = new ServiceHostOptions { BackendMode = "Native", EnableNativeWrite = true,
                ManagementJournalRoot = args[2], NativeFsHostPath = args[1], NativeAutoDiscoverPhysicalDrives = false,
                NativeDeviceCandidates = [], AutoMountEnabled = false, PrivateControlInstanceId = Guid.NewGuid() };
            using var backend = new NativeApfsBackend(options);
            var publisher = new RuntimeStatusPublisher();
            using var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, backend, new NoMountPolicy(), publisher, new FixedOptions(options));
            var executor = new AgentControlCommandExecutor(worker);
            var operationType = typeof(AgentControlCommandExecutor).Assembly.GetType("ApfsAccess.Service.AgentControlOperationService", true)!;
            var operationConstructor = operationType.GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic).Single();
            var operations = operationConstructor.Invoke([new Func<ControlOperationRequestPayload, CancellationToken, Task<OperationResultPayload>>(executor.ExecuteAsync),
                Path.Combine(operationDirectory, "evidence"), null, null, null, null]);
            var constructor = typeof(TrayPipeHostService).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, null,
                [typeof(Microsoft.Extensions.Logging.ILogger<TrayPipeHostService>), typeof(RuntimeStatusPublisher), typeof(ApfsMountWorker),
                 typeof(IHostApplicationLifetime), operationType, typeof(string)], null)!;
            using var host = (TrayPipeHostService)constructor.Invoke([NullLogger<TrayPipeHostService>.Instance, publisher, worker,
                new Lifetime(), operations, FusionControlEndpoint.ForPrivateInstance(options.PrivateControlInstanceId.Value)]);
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            await host.StartAsync(deadline.Token);
            try
            {
                var cli = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "ApfsAccess.Cli.dll"));
                var main = cli.GetType("ApfsAccess.Cli.Program", true)!.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;
                var action = request.Action switch { ImageKeyManagementAction.ChangePassword => "change-password",
                    ImageKeyManagementAction.RotateVolumeKey => "rotate", ImageKeyManagementAction.Encrypt => "encrypt", _ => "decrypt" };
                var resultCode = await (Task<int>)main.Invoke(null, [new[] { "image-keys", action, "--endpoint", endpointFile,
                    "--credential-stdin", "--operation-id", request.OperationId, "--private-instance", options.PrivateControlInstanceId.Value.ToString("D") }])!;
                var result = (OperationResultPayload?)operationType.GetMethod("Query")!.Invoke(operations, [request.OperationId])
                    ?? throw new IOException("Missing durable operation result.");
                if (!PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, request.OperationId, 2)).IsValid ||
                    result.KeyManagement != request || result.Fingerprint != ApfsOperationFingerprint.ComputeForResult(result) ||
                    result.Success != (resultCode == 0)) throw new IOException("Public operation evidence mismatch.");
                if (result.Success)
                {
                    var receipt = result.KeyManagementReceipt ?? throw new IOException();
                    if (!receipt.Proves(request) || (await backend.GetMountStateAsync(deadline.Token)).Count != 0) throw new IOException();
                    if (receipt.After.Mode == ImageEncryptionMode.SoftwareOneKeyGenerationZero)
                    {
                        var volumes = await backend.ProbeVolumesAsync(receipt.After.ImagePath, deadline.Token);
                        if (volumes.Count != 1 || volumes[0].RegisteredImage != receipt.After.ToWritableEncryptedProfile() ||
                            volumes[0].EncryptionState != EncryptedVolumeState.Locked) throw new IOException("Fresh locked registration missing.");
                    }
                    using var output = new FileStream(args[4], FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                    JsonSerializer.Serialize(output, receipt, Json); output.Flush(true);
                    Console.WriteLine("PUBLIC_CLI_AUTHENTICATED_SERVICE_NATIVE_KEYS_PASS");
                }
                return resultCode;
            }
            finally { await host.StopAsync(CancellationToken.None); await (Task)operationType.GetMethod("StopAsync")!.Invoke(operations, [CancellationToken.None])!; }
        }
        catch (Exception e) { Console.WriteLine(JsonSerializer.Serialize(new { refused = true, errorType = e.GetType().Name })); return 7; }
    }

    private static void CheckBinding(ImageKeyManagementRequest request)
    {
        var expiry = DateTime.UtcNow.AddMinutes(4);
        var control = new ControlOperationRequestPayload(request.OperationId, ApfsControlCommands.ImageKeyManagement, null,
            ExpiresAtUtc: expiry, KeyManagement: request);
        if (!PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, control, request.OperationId, 2)).IsValid)
            throw new IOException("Valid key-management wire request refused.");
        var altered = control with { KeyManagement = request with { Expected = request.Expected with { CheckpointXid = request.Expected.CheckpointXid + 1 } } };
        if (ApfsOperationFingerprint.Compute(control) == ApfsOperationFingerprint.Compute(altered)) throw new IOException("Endpoint not fingerprinted.");
        altered = control with { KeyManagement = request with { OperationId = Guid.NewGuid().ToString("D") } };
        if (PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, altered, request.OperationId, 2)).IsValid)
            throw new IOException("Different credential operation identity admitted.");
    }

    private sealed class NoMountPolicy : IMountPolicy
    { public bool ShouldAutoMount(VolumeInfo volume) => false; public char SelectDriveLetter(VolumeInfo v, IReadOnlySet<char> used) => throw new InvalidOperationException("No mounts in this gate."); }
    private sealed class FixedOptions(ServiceHostOptions value) : IOptionsMonitor<ServiceHostOptions>
    { public ServiceHostOptions CurrentValue => value; public ServiceHostOptions Get(string? name) => value; public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null; }
    private sealed class Lifetime : IHostApplicationLifetime
    { public CancellationToken ApplicationStarted => default; public CancellationToken ApplicationStopping => default; public CancellationToken ApplicationStopped => default; public void StopApplication() { } }
}
