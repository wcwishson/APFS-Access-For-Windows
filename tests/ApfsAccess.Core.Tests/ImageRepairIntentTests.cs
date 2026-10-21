using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class ImageRepairIntentTests
{
    [Fact]
    public void ExistingDOriginalCommitmentAndFrameRemainByteCompatible()
    {
        var old = Intent();
        var intent = ImageRepairPersistence.Create(old.Offer with
        { ExpiresAtUtc = new DateTime(2026, 10, 17, 12, 0, 0, DateTimeKind.Utc) }, old.JournalRoot, old.Nonce);
        Assert.Equal("ecd3060a30be6f8f9dc31ce00f27d13eae753d6a8e6dae5ebbaf4f20d2651a4f", intent.Offer.PlanId);
        Assert.Equal("9f7334390db928d38d52d7ff592d5f08dd672affe1193ed519166ef497d9fcc7",
            Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(ImageRepairPersistence.Encode(intent))));
    }

    [Theory]
    [InlineData(@"C:\images\repair.apfs", @"C:\journal")]
    [InlineData(@"D:\images\repair.apfs", @"D:\journal")]
    [InlineData(@"Z:\images\repair.apfs", @"Z:\journal")]
    public void LocalOfferAndOriginalBindingDoNotRequireDrivePresence(string image, string root)
    {
        var prior = Intent();
        var intent = ImageRepairPersistence.Create(prior.Offer with
        { Scope = prior.Offer.Scope with { ImagePath = image } }, root, prior.Nonce);
        ImageRepairPersistence.Validate(intent, root);
        Assert.True(ImageRepairPersistence.ValidOffer(intent.Offer));
        Assert.True(ImageRepairPersistence.ValidReceipt(new(intent.Offer.PlanId, "refused", intent.Offer,
            intent.JournalPath, intent.EvidenceDirectory, "RepairRefused", 4)));
        Assert.Throws<InvalidDataException>(() => ImageRepairPersistence.Validate(intent with
        { JournalPath = Path.Combine(root, "foreign.rct2") }, root));
        Assert.Throws<InvalidDataException>(() => ImageRepairPersistence.Validate(intent with
        { Offer = intent.Offer with { Scope = intent.Offer.Scope with { CheckpointXid = "8" } } }, root));
    }

    [Theory]
    [InlineData(@"\\server\share\repair.apfs")]
    [InlineData(@"\\?\C:\images\repair.apfs")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"C:repair.apfs")]
    [InlineData(@"C:\images\repair.apfs:stream")]
    [InlineData(@"C:\images\..\repair.apfs")]
    [InlineData(@"C:\images\\repair.apfs")]
    [InlineData(@"C:\images.\repair.apfs")]
    [InlineData(@"C:\images \repair.apfs")]
    public void UnsafePathsCannotEnterOfferOrOriginal(string path)
    {
        Assert.False(ImageRepairPersistence.LocalPath(path));
        var prior = Intent();
        Assert.False(ImageRepairPersistence.ValidOffer(prior.Offer with
        { Scope = prior.Offer.Scope with { ImagePath = path } }));
        Assert.Throws<InvalidDataException>(() => ImageRepairPersistence.Create(prior.Offer, path, prior.Nonce));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void AuthorityReadRejectsReparseFileOrParentAndPreservesOriginal(bool parentAlias)
    {
        var root = Directory.CreateDirectory(Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!,
            "repair-alias-" + Guid.NewGuid().ToString("N"))).FullName;
        var original = Intent(root);
        var path = ImageRepairPersistence.PathFor(root, original.Offer.PlanId);
        var bytes = ImageRepairPersistence.Encode(original);
        File.WriteAllBytes(path, bytes);
        if (parentAlias)
        {
            var alias = root + "-link";
            Directory.CreateSymbolicLink(alias, root);
            try { Assert.Throws<InvalidDataException>(() => ImageRepairPersistence.Read(Path.Combine(alias, Path.GetFileName(path)), alias)); }
            finally { Directory.Delete(alias); }
        }
        else
        {
            var alias = Path.Combine(root, "alias.json");
            File.CreateSymbolicLink(alias, path);
            try { Assert.Throws<InvalidDataException>(() => ImageRepairPersistence.Read(alias, root)); }
            finally { File.Delete(alias); }
        }
        Assert.Equal(bytes, File.ReadAllBytes(path));
        Assert.Equal(original, ImageRepairPersistence.ReadVerified(path, root, bytes));
    }

    [Fact]
    public void DurableReadbackRequiresExactBytesEvenWhenReplacementFrameIsValid()
    {
        var root = Directory.CreateDirectory(Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!,
            "readback-" + Guid.NewGuid().ToString("N"))).FullName;
        var intent = Intent(root); var path = ImageRepairPersistence.PathFor(root, intent.Offer.PlanId);
        var bytes = ImageRepairPersistence.Encode(intent);
        File.WriteAllBytes(path, bytes);
        Assert.Equal(intent, ImageRepairPersistence.ReadVerified(path, root, bytes));
        File.WriteAllBytes(path, System.Text.Encoding.UTF8.GetBytes(" \r\n" + System.Text.Encoding.UTF8.GetString(bytes)));
        Assert.Equal(intent, ImageRepairPersistence.Read(path, root));
        var error = Assert.Throws<IOException>(() => ImageRepairPersistence.ReadVerified(path, root, bytes));
        Assert.Equal("ImageRepairIntentDurableReadbackFailed", error.Message);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void DurableReadbackUsesHeldBoundedAuthorityReader(bool concurrentWriter)
    {
        var root = Directory.CreateDirectory(Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!,
            "readback-" + Guid.NewGuid().ToString("N"))).FullName;
        var intent = Intent(root); var path = ImageRepairPersistence.PathFor(root, intent.Offer.PlanId);
        var bytes = ImageRepairPersistence.Encode(intent); File.WriteAllBytes(path, bytes);
        if (!concurrentWriter)
        { using var output = new FileStream(path, FileMode.Open, FileAccess.Write); output.SetLength(256 * 1024 + 1); }
        using var writer = concurrentWriter ? new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite) : null;
        if (concurrentWriter) Assert.Throws<IOException>(() => ImageRepairPersistence.ReadVerified(path, root, bytes));
        else Assert.Throws<InvalidDataException>(() => ImageRepairPersistence.ReadVerified(path, root, bytes));
    }

    [Theory]
    [InlineData("missing")] [InlineData("empty")] [InlineData("accepted")]
    public void JournalLeaseFileIsDistinguishedFromAcceptedContentWithoutParsingOrDeleting(string state)
    {
        var root = Directory.CreateDirectory(Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!,
            "journal-" + Guid.NewGuid().ToString("N"))).FullName;
        var intent = Intent(root); Directory.CreateDirectory(Path.GetDirectoryName(intent.JournalPath)!);
        if (state != "missing") File.WriteAllBytes(intent.JournalPath, state == "empty" ? [] : [1, 2, 3]);
        Assert.Equal(state != "accepted", ImageRepairPersistence.JournalUnaccepted(intent.JournalPath, root));
        Assert.Equal(state != "missing", File.Exists(intent.JournalPath));
        if (state == "accepted") Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(intent.JournalPath));
    }

    private static ImageRepairIntent Intent(string root = @"D:\journal") => ImageRepairPersistence.Create(new("", DateTime.UtcNow.AddMinutes(5),
        new(@"D:\image.apfs", "apfs-container:" + new string('a', 32), new string('b', 32), "101", "7", "0", "2097152"),
        "original-recovery", "selected-v1:" + new string('a', 64), new string('b', 64), "1",
        "windows-image-v1:" + new string('a', 48) + "0000000000000000" + "0000000000200000" + ":123",
        new string('c', 64)), root, "0123456789abcdef0123456789abcdef");

    [Theory]
    [InlineData("oversized")] [InlineData("duplicate")] [InlineData("scope-unknown")] [InlineData("writer")]
    public void AuthorityReaderRejectsOversizeDuplicateNestedUnknownAndConcurrentWriter(string kind)
    {
        var root = Directory.CreateDirectory(Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT") ??
            throw new InvalidOperationException("D test root required"), "repair-reader-" + Guid.NewGuid().ToString("N"))).FullName;
        var intent = Intent(root); var path = ImageRepairPersistence.PathFor(root, intent.Offer.PlanId);
        File.WriteAllBytes(path, ImageRepairPersistence.Encode(intent));
        Assert.Equal(intent, ImageRepairPersistence.Read(path, root));
        if (kind == "oversized")
        { using var output = new FileStream(path, FileMode.Create, FileAccess.Write); output.SetLength(256 * 1024 + 1); }
        if (kind is "duplicate" or "scope-unknown")
        {
            var payload = System.Text.Json.JsonSerializer.Serialize(intent, ImageRepairPersistence.Json);
            payload = kind == "duplicate" ? payload.Insert(1, "\"state\":\"applying\",") : payload.Replace("\"scope\":{", "\"scope\":{\"unknownAuthority\":true,");
            var bytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new { schema = 1, digest = ImageRepairPersistence.Hash(payload), payload });
            File.WriteAllBytes(path, bytes);
        }
        using var writer = kind == "writer" ? new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite) : null;
        if (kind == "writer") Assert.Throws<IOException>(() => ImageRepairPersistence.Read(path, root));
        else Assert.Throws<InvalidDataException>(() => ImageRepairPersistence.Read(path, root));
    }

    [Fact]
    public void OpaquePlanCommitsNativeSourceCountScopeAndOriginalPaths()
    {
        var intent = Intent();
        ImageRepairPersistence.Validate(intent, @"D:\journal");
        foreach (var changed in new[] {
            intent with { Offer = intent.Offer with { ExpectedCount = "2" } },
            intent with { Offer = intent.Offer with { SourceSha256 = new string('d', 64) } },
            intent with { Offer = intent.Offer with { SourceIdentity = intent.Offer.SourceIdentity + "0" } },
            intent with { Offer = intent.Offer with { Scope = intent.Offer.Scope with { CheckpointXid = "8" } } },
            intent with { JournalPath = @"D:\journal\adopted.rct2" } })
            Assert.Throws<InvalidDataException>(() => ImageRepairPersistence.Validate(changed, @"D:\journal"));
    }

    [Fact]
    public void OnlyAcceptedLineageBlocksAndMayBecomeNativeReconciliationException()
    {
        var intent = Intent();
        Assert.False(intent.Pending);
        Assert.True((intent with { State = "applying" }).Pending);
        Assert.True((intent with { State = "recovery-required" }).Pending);
        Assert.False((intent with { State = "expired" }).Pending);
    }
}
