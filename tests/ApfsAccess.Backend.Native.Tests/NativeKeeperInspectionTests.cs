using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeKeeperInspectionTests
{
    [Theory]
    [InlineData("prepared")] [InlineData("accepted")] [InlineData("anchor-durable")]
    public void OnlyExactSavedOwnFamilyCanProceedToNativeOwnerRecovery(string state)
    {
        var r = NativeVolumeImageManagementTests.Request();
        var wire = Inspection(r, "completed", state);
        Assert.Throws<InvalidDataException>(() => NativeManagementJournalAdmission.ValidateInspection(wire, r.JournalRoot, r.SourceIdentity, null));
        NativeManagementJournalAdmission.ValidateInspection(wire, r.JournalRoot, r.SourceIdentity, r);
        Assert.Throws<InvalidDataException>(() => NativeManagementJournalAdmission.ValidateInspection(Inspection(r, "prepared", state), r.JournalRoot, r.SourceIdentity, r));
        Assert.Throws<InvalidDataException>(() => NativeManagementJournalAdmission.ValidateInspection(Inspection(r, "completed", "invalid"), r.JournalRoot, r.SourceIdentity, r));
        Assert.Throws<InvalidDataException>(() => NativeManagementJournalAdmission.ValidateInspection(wire, r.JournalRoot, new string('e', 80), r));
    }
    [Fact]
    public void CompletedAndCancelledBothFamiliesAdmit()
    { var r = NativeVolumeImageManagementTests.Request(); NativeManagementJournalAdmission.ValidateInspection(Inspection(r, "cancelled", "completed"), r.JournalRoot, r.SourceIdentity, null); }
    private static ObserverRunResult Inspection(VolumeTopologyRequest r, string vmt, string vif)
    {
        var admitted = new[] { vmt, vif }.All(s => s is "completed" or "cancelled" or "missing");
        return new(admitted ? 0 : 1, JsonSerializer.Serialize(new { schemaVersion = 1, admitted,
            error = admitted ? "" : "VolumeKeeperAdmissionBlocked:vif1:" + vif, sourceIdentity = r.SourceIdentity, locator = r.SourceIdentity[..64],
            journals = new[] { new { family = "vmt1", path = Path.Combine(r.JournalRoot, "original.vmt1"), state = vmt, error = "" },
                new { family = "vif1", path = Path.Combine(r.JournalRoot, "original.vif1"), state = vif, error = vif == "invalid" ? "bad frame" : "" } } }), "");
    }
}
