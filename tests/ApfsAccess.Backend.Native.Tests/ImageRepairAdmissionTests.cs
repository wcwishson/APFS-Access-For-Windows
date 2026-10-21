using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ImageRepairAdmissionTests
{
    private static ImageRepairIntent Intent(string root) => ImageRepairPersistence.Create(new("", DateTime.UtcNow.AddMinutes(2),
        new(@"D:\repair.apfs", "apfs-container:" + new string('a', 32), new string('b', 32), "101", "7", "0", "2097152"),
        "original-recovery", "selected-v1:" + new string('a', 64), new string('b', 64), "0",
        "windows-image-v1:" + new string('a', 48) + "0000000000000000" + "0000000000200000" + ":123", new string('c', 64)),
        root, Guid.NewGuid().ToString("N"));
    [Theory]
    [InlineData("offered")] [InlineData("applying")] [InlineData("recovery-required")]
    public void ImageRepair_SharedNativeAdmissionBlocksAcceptedLineageButOffersAloneDoNotBlock(string state)
    {
        var root = Directory.CreateDirectory(Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!,
            "admit-" + Guid.NewGuid().ToString("N"))).FullName;
        var original = Intent(root); var pending = state != "offered";
        var intent = original with { State = state, AcceptedOperationId = pending ? Guid.NewGuid().ToString("D") : null,
            AcceptedFingerprint = pending ? "sha256:" + new string('e', 64) : null };
        var path = ImageRepairPersistence.PathFor(root, intent.Offer.PlanId);
        File.WriteAllBytes(path, ImageRepairPersistence.Encode(intent));
        if (pending)
        {
            Assert.Throws<IOException>(() => NativeManagementJournalAdmission.RequireClearRoot(root, true));
            Assert.Throws<IOException>(() => ImageRepairPersistence.RequireNoPending(root));
            Assert.Throws<IOException>(() => ImageRepairPersistence.RequireNoPending(root, new string('f', 64)));
            ImageRepairPersistence.RequireNoPending(root, intent.Offer.PlanId);
        }
        else { NativeManagementJournalAdmission.RequireClearRoot(root); ImageRepairPersistence.RequireNoPending(root); }
        Assert.True(File.Exists(path));
    }
    [Theory]
    [InlineData("tmp")] [InlineData("corrupt")]
    public void ImageRepair_IncompleteOrCorruptIntentBlocksBothNativeAdmissionAndDirectLaunchGuard(string kind)
    {
        var root = Directory.CreateDirectory(Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!,
            "admit-" + Guid.NewGuid().ToString("N"))).FullName;
        var path = Path.Combine(root, ImageRepairPersistence.Prefix + new string('d', 64) + (kind == "tmp" ? ".interrupted.tmp" : ".json"));
        File.WriteAllText(path, "preserve this invalid authority");
        Assert.Throws<InvalidDataException>(() => NativeManagementJournalAdmission.RequireClearRoot(root, true));
        Assert.Throws<InvalidDataException>(() => ImageRepairPersistence.RequireNoPending(root));
        Assert.Equal("preserve this invalid authority", File.ReadAllText(path));
    }
}
