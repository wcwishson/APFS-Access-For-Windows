using ApfsAccess.Core;
namespace ApfsAccess.Ipc.Tests;

public sealed class DriveLetterPreferenceTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void PreferenceRequestRoundTripsInBothSchemas(int schema)
    {
        var request = new DriveLetterPreferenceRequestPayload("device", "volume", "fbda2042-9e07-420e-aea1-eafefed58643", "T");
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.DriveLetterPreferenceRequested, request, "request", schema);
        Assert.True(PipeMessageCodec.Validate(envelope).IsValid);
        Assert.True(PipeMessageCodec.TryDeserialize(PipeMessageCodec.Serialize(envelope), out var decoded));
        Assert.True(PipeMessageCodec.TryGetPayload<DriveLetterPreferenceRequestPayload>(decoded!, out var actual));
        Assert.Equal(request, actual);
    }
    [Fact]
    public void LegacyMountedPayloadDefaultsPreferenceToNullAndNewFieldRoundTrips()
    {
        var volume = new MountedVolumeDisplay("volume", "R:\\", "Name", "device", "Disk", MountAccessMode.ReadOnly);
        var envelope = PipeMessageCodec.Create("test", volume);
        envelope.Payload!.Remove("driveLetterPreference");
        Assert.True(PipeMessageCodec.TryGetPayload<MountedVolumeDisplay>(envelope, out var legacy));
        Assert.Null(legacy!.DriveLetterPreference);
        var preference = new DriveLetterPreference("uuid", "T", "R", "preference-occupied", "Preferred T: occupied; using R: temporarily", "RST", true);
        var enriched = PipeMessageCodec.Create("test", volume with { DriveLetterPreference = preference });
        Assert.True(PipeMessageCodec.TryGetPayload<MountedVolumeDisplay>(enriched, out var actual));
        Assert.Equal(preference, actual!.DriveLetterPreference);
    }
}
