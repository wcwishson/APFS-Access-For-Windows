using System.Globalization;
using System.IO.Pipes;
using System.Text.Json;
using ApfsAccess.Cli;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

// Task-1 additive projection: canonical catalog IDs flow through the CLI
// `list` (volumes) and `status` (mounted volumes) JSON outputs untouched by
// filtering. Legacy volume-id form is unchanged.
public sealed class CatalogProjectionTests
{
    private const string DeviceId = @"\\.\PhysicalDrive2";
    private const string VolumeId = DeviceId + "|LegacyName";
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";
    private const string CatalogVolumeId = "apfs-vol:" + ContainerHex + ":101";

    [Fact]
    public async Task ListProjectsCatalogFieldsOnVolumes()
    {
        var pipeName = NewPipeName("CatalogList");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(pipeName, async (peer, cancellationToken) =>
        {
            var request = await ReadMessageAsync(peer, cancellationToken);
            Assert.Equal(ApfsMessageTypes.InventoryRequested, request.Type);
            var inventory = new InventoryPayload(
                new[]
                {
                    new DeviceInventory(
                        new DeviceInfo(DeviceId, "USB APFS", true),
                        new[]
                        {
                            new VolumeInfo(
                                VolumeId, DeviceId, "LegacyName", SupportsReadWrite: false,
                                CatalogVolumeId: CatalogVolumeId,
                                CatalogContainerUuid: ContainerHex,
                                CatalogVolumeObjectId: 101UL,
                                CatalogDecision: ApfsCapabilityDecision.Writable,
                                CatalogReasons: Array.Empty<string>(),
                                CatalogAutoMountAllowed: true),
                        }),
                },
                DateTime.UtcNow);
            await peer.SendAsync(
                PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory, request.RequestId),
                cancellationToken);
        }, serverCancellation.Token);

        var result = await InvokeAsync(
            "list",
            "--device-id", DeviceId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var volume = json.RootElement.GetProperty("devices")[0].GetProperty("volumes")[0];
        Assert.Equal(VolumeId, volume.GetProperty("volumeId").GetString());
        Assert.Equal(CatalogVolumeId, volume.GetProperty("catalogVolumeId").GetString());
        Assert.Equal(ContainerHex, volume.GetProperty("catalogContainerUuid").GetString());
        Assert.Equal(101UL, volume.GetProperty("catalogVolumeObjectId").GetUInt64());
        Assert.Equal("Writable", volume.GetProperty("catalogDecision").GetString());
        Assert.True(volume.GetProperty("catalogAutoMountAllowed").GetBoolean());
    }

    [Fact]
    public async Task ListEmitsCatalogFieldNamesEvenWhenNull()
    {
        var pipeName = NewPipeName("CatalogListNull");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(pipeName, async (peer, cancellationToken) =>
        {
            var request = await ReadMessageAsync(peer, cancellationToken);
            var inventory = new InventoryPayload(
                new[]
                {
                    new DeviceInventory(
                        new DeviceInfo(DeviceId, "USB APFS", true),
                        new[] { new VolumeInfo(VolumeId, DeviceId, "LegacyName", SupportsReadWrite: false) }),
                },
                DateTime.UtcNow);
            await peer.SendAsync(
                PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory, request.RequestId),
                cancellationToken);
        }, serverCancellation.Token);

        var result = await InvokeAsync(
            "list",
            "--device-id", DeviceId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var volume = json.RootElement.GetProperty("devices")[0].GetProperty("volumes")[0];
        foreach (var name in new[]
                 {
                     "catalogVolumeId", "catalogContainerUuid", "catalogVolumeObjectId",
                     "catalogDecision", "catalogReasons", "catalogAutoMountAllowed",
                 })
        {
            Assert.True(volume.TryGetProperty(name, out _), $"Missing additive field '{name}'.");
        }
    }

    [Fact]
    public async Task StatusProjectsCatalogFieldsOnMountedVolumes()
    {
        var pipeName = NewPipeName("CatalogStatus");
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = RunSingleServerAsync(
            pipeName,
            (_, _) => Task.CompletedTask,
            serverCancellation.Token,
            mountedVolumes: new[]
            {
                new MountedVolumeDisplay(
                    VolumeId, @"E:\", "LegacyName", DeviceId, "USB APFS", MountAccessMode.ReadOnly,
                    CatalogVolumeId: CatalogVolumeId,
                    CatalogContainerUuid: ContainerHex,
                    CatalogVolumeObjectId: 101UL,
                    CatalogDecision: ApfsCapabilityDecision.Writable,
                    CatalogReasons: Array.Empty<string>(),
                    CatalogAutoMountAllowed: true),
            });

        var result = await InvokeAsync(
            "status",
            "--volume-id", VolumeId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000");
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        var volume = json.RootElement.GetProperty("status").GetProperty("mountedVolumes")[0];
        Assert.Equal(VolumeId, volume.GetProperty("volumeId").GetString());
        Assert.Equal(CatalogVolumeId, volume.GetProperty("catalogVolumeId").GetString());
        Assert.Equal(ContainerHex, volume.GetProperty("catalogContainerUuid").GetString());
        Assert.Equal(101UL, volume.GetProperty("catalogVolumeObjectId").GetUInt64());
    }

    private static async Task RunSingleServerAsync(
        string pipeName,
        Func<PipePeer, CancellationToken, Task> handler,
        CancellationToken cancellationToken,
        IReadOnlyList<MountedVolumeDisplay>? mountedVolumes = null)
    {
        await using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        await server.WaitForConnectionAsync(cancellationToken);
        await using var peer = new PipePeer(server);
        var status = new StatusChangedPayload(
            RuntimeState.MountedRo,
            new[] { @"E:\" },
            null,
            DateTime.UtcNow,
            Array.Empty<string>(),
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes: mountedVolumes,
            WriteBackend: "Native");
        await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status), cancellationToken);
        await handler(peer, cancellationToken);
    }

    private static async Task<PipeEnvelope> ReadMessageAsync(PipePeer peer, CancellationToken cancellationToken)
        => (await peer.ReadMessageAsync(cancellationToken)) ?? throw new Xunit.Sdk.XunitException("The fake service received EOF unexpectedly.");

    private static string NewPipeName(string suffix)
        => $"ApfsAccess.Cli.Tests.{suffix}.{Guid.NewGuid():N}";

    private static async Task<(int ExitCode, string Output)> InvokeAsync(params string[] args)
    {
        var original = Console.Out;
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        Console.SetOut(writer);
        try
        {
            return (await Program.RunForTestAsync(args), writer.ToString());
        }
        finally
        {
            Console.SetOut(original);
        }
    }
}
