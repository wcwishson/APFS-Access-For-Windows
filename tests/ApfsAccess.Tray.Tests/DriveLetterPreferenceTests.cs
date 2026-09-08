using ApfsAccess.Core;
using ApfsAccess.Ipc;
namespace ApfsAccess.Tray.Tests;

public sealed class DriveLetterPreferenceTests
{
    [Theory]
    [InlineData("preference-occupied", "Preferred T: occupied; using R: temporarily")]
    [InlineData("next-mount", "Preferred T:; applies on next mount")]
    [InlineData("storage-unavailable", "Saved letter unavailable. Try again.")]
    public void PresenterKeepsActualLetterAndExposesPreference(string state, string text)
    {
        var preference = new DriveLetterPreference("fbda2042-9e07-420e-aea1-eafefed58643", "T", "R", state, text, "RST", true);
        var volume = new MountedVolumeDisplay("volume", "R:\\", "Same name", "device", "Disk", MountAccessMode.ReadOnly, DriveLetterPreference: preference);
        var status = new StatusChangedPayload(RuntimeState.MountedRo, ["R:\\"], null, DateTime.UtcNow, [], false, [], [volume]);
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.Equal("R:", row.MountPoint); Assert.Equal(preference, row.DriveLetterPreference);
        Assert.Equal("device", row.DeviceId); Assert.Contains(text, row.Summary);
    }
    [Fact]
    public void LegacyStatusOffersNoPreferenceIdentity()
    {
        var volume = new MountedVolumeDisplay("volume", "R:\\", "Name", "device", "Disk", MountAccessMode.ReadOnly);
        var status = new StatusChangedPayload(RuntimeState.MountedRo, [], null, DateTime.UtcNow, [], false, [], [volume]);
        Assert.Null(Assert.Single(DriveDashboardPresenter.BuildRows(status)).DriveLetterPreference);
    }
}
