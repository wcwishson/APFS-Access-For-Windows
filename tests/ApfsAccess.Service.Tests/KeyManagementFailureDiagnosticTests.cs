using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    private const string NativeRefusal = "ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileOpen:win32=32:attempts=4";

    [Theory]
    [InlineData("valid", true, true)]
    [InlineData("wrong-exit-type", false, false)]
    [InlineData("zero-exit", false, false)]
    [InlineData("missing-exit", false, false)]
    [InlineData("wrong-reason-type", true, false)]
    [InlineData("control-reason", true, false)]
    [InlineData("oversize-reason", true, false)]
    [InlineData("unrelated-exception", false, false)]
    public async Task ObserveFailurePublishesOnlyBoundedNativeFields(string vector, bool exitExpected, bool reasonExpected)
    {
        Exception failure = vector == "unrelated-exception" ? new InvalidOperationException("PRIVATE EXCEPTION TEXT") :
            new IOException("PRIVATE EXCEPTION TEXT");
        if (vector != "missing-exit") failure.Data["NativeExitCode"] = vector switch
        {
            "wrong-exit-type" => (object)"13", "zero-exit" => 0, _ => 13,
        };
        failure.Data["NativeObservationRefusal"] = vector switch
        {
            "wrong-reason-type" => (object)13,
            "control-reason" => NativeRefusal + "\nPRIVATE LINE",
            "oversize-reason" => new string('x', 4097),
            _ => NativeRefusal,
        };
        var backend = new KeyDiagnosticBackend(failure);
        using var worker = CreateWorker(backend, autoMountEnabled: false);
        var executor = CreateExecutor(worker);
        executor.KeyManagementCredentialReceiver = (_, _, _, _, _) => throw new InvalidOperationException("Observe requested credentials.");
        var id = Guid.NewGuid().ToString("D");
        var endpoint = new ImageKeyManagementEndpoint(@"D:\offline-diagnostic.apfs", "image-writer-v1:test:0:1048576",
            0, 1048576, "11111111-2222-3333-4444-555555555555", "66666666-7777-8888-9999-aaaaaaaaaaaa",
            21, 7, ImageEncryptionMode.Plain);
        var request = new ControlOperationRequestPayload(id, ApfsControlCommands.ImageKeyManagement, null,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(1), KeyManagement: new(id, ImageKeyManagementAction.Observe, endpoint));
        Assert.True(request.KeyManagement.IsValid());

        var result = await executor.ExecuteAsync(request, CancellationToken.None);

        Assert.Equal(1, backend.Calls);
        Assert.False(result.Success);
        Assert.Equal(ApfsOperationCodes.OperationFailed, result.Code);
        Assert.Equal("not-proven", result.OwnershipProof);
        Assert.Equal("not-proven", result.DurabilityProof);
        Assert.Null(result.KeyManagementReceipt);
        Assert.DoesNotContain("PRIVATE", result.Diagnostic);
        Assert.Equal(exitExpected, result.Diagnostic!.Contains("NativeExitCode=13.", StringComparison.Ordinal));
        Assert.Equal(reasonExpected, result.Diagnostic.Contains("NativeObservationRefusal=" + NativeRefusal, StringComparison.Ordinal));
        if (!reasonExpected) Assert.DoesNotContain("NativeObservationRefusal=", result.Diagnostic);
    }

    [Theory]
    [InlineData(ImageKeyManagementAction.ChangePassword)]
    [InlineData(ImageKeyManagementAction.RotateVolumeKey)]
    [InlineData(ImageKeyManagementAction.Encrypt)]
    [InlineData(ImageKeyManagementAction.Decrypt)]
    public void CredentialActionsNeverExposeObservationFailureData(ImageKeyManagementAction action)
    {
        var failure = new IOException("PRIVATE EXCEPTION TEXT");
        failure.Data["NativeExitCode"] = 13;
        failure.Data["NativeObservationRefusal"] = NativeRefusal;
        var result = AgentControlCommandExecutor.KeyManagementFailureDiagnostic(action, failure);
        Assert.DoesNotContain("PRIVATE", result);
        Assert.DoesNotContain("NativeExitCode", result);
        Assert.DoesNotContain("NativeObservationRefusal", result);
    }

    private sealed class KeyDiagnosticBackend(Exception failure) : IApfsBackend, IImageKeyManagementObserver
    {
        public int Calls { get; private set; }
        public Task<ImageKeyManagementReceipt> ObserveImageKeysAsync(ImageKeyManagementRequest request, CancellationToken token)
        {
            Calls++;
            return Task.FromException<ImageKeyManagementReceipt>(failure);
        }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => Task.FromResult<IReadOnlyList<DeviceInfo>>([]);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => Task.FromResult<IReadOnlyList<VolumeInfo>>([]);
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token) => Task.FromResult<IReadOnlyList<MountedVolumeState>>([]);
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token) => throw new InvalidOperationException("Diagnostic gate must not mount.");
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token) => throw new InvalidOperationException("Diagnostic gate must not unmount.");
    }
}
