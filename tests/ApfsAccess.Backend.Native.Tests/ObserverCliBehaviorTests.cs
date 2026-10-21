using System.Runtime.InteropServices;
using System.Text.Json;

namespace ApfsAccess.Backend.Native.Tests;

// Direct CLI behavior of the stable observer binary: alias rejection,
// atomic --out publication, fusion geometry binding, and fail-closed
// malformed inputs. RED-first: each case fails against the pre-hardening
// observer (direct passthrough hashing, clobbering --out, unchecked fusion).
public sealed class ObserverCliBehaviorTests
{
    private static string RealObserverPath()
    {
        if (Environment.GetEnvironmentVariable("APFS_VERIFY_TEST_OBSERVER") is { Length: > 0 })
            return StagedPackagedObserver.StableObserverPath();
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var level = 0; level < 14 && directory is not null; level++)
        {
            var candidate = Path.Combine(
                directory.FullName, "build", "ApfsAccess.ApfsRwEngine", "Release", "ApfsObserver.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        Assert.Fail(
            "Integration requires build/ApfsAccess.ApfsRwEngine/Release/ApfsObserver.exe; refusing to skip.");
        throw new InvalidOperationException("Unreachable.");
    }

    private static ProcessObserverRunner Runner(TimeSpan? timeout = null) => new()
    {
        Timeout = timeout ?? TimeSpan.FromSeconds(60),
    };

    private static void WriteCVolumeFixture(string imagePath, Guid containerUuid, Guid partitionUuid)
    {
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P",
                PartitionUuid: partitionUuid,
                ContainerUuid: containerUuid,
                Volumes: [new CatalogVolumeSpec("Data")])]));
    }

    [Fact]
    public void FusionSameFileInputs_AreRejectedAsAliases()
    {
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-alias");
        var imagePath = Path.Combine(temp.Path, "member.apfs.img");
        WriteCVolumeFixture(imagePath, Guid.NewGuid(), Guid.NewGuid());
        var aliasPath = Path.Combine(temp.Path, "alias.apfs.img");
        Assert.True(CreateHardLink(aliasPath, imagePath, nint.Zero), "test requires hard-link creation");

        var result = Runner().Run(observerPath,
            ["--store-a", imagePath, "--store-b", aliasPath,
             "--profile", "fusion-alias", "--mode", "fusion"]);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("alias", result.StandardError, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OutRefusesToClobberExistingEvidence()
    {
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-noclobber");
        var imagePath = Path.Combine(temp.Path, "single.apfs.img");
        WriteCVolumeFixture(imagePath, Guid.NewGuid(), Guid.NewGuid());
        var outPath = Path.Combine(temp.Path, "evidence.json");
        File.WriteAllText(outPath, "{}");

        var result = Runner().Run(observerPath,
            ["--image", imagePath, "--profile", "noclobber", "--mode", "collect",
             "--out", outPath]);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("already exists", result.StandardError, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("{}", File.ReadAllText(outPath));
    }

    [Fact]
    public void OutRefusesSymlinkedDestination()
    {
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-symlinkout");
        var imagePath = Path.Combine(temp.Path, "single.apfs.img");
        WriteCVolumeFixture(imagePath, Guid.NewGuid(), Guid.NewGuid());
        var realOut = Path.Combine(temp.Path, "real.json");
        var linkOut = Path.Combine(temp.Path, "link.json");
        File.CreateSymbolicLink(linkOut, realOut);

        var result = Runner().Run(observerPath,
            ["--image", imagePath, "--profile", "symlinkout", "--mode", "collect",
             "--out", linkOut]);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("symlink", result.StandardError, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(realOut));
    }

    [Fact]
    public void OutRefusesToOverwriteItsOwnInput()
    {
        // --out naming an input path must fail, never truncate evidence input.
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-selfout");
        var imagePath = Path.Combine(temp.Path, "single.apfs.img");
        WriteCVolumeFixture(imagePath, Guid.NewGuid(), Guid.NewGuid());

        var result = Runner().Run(observerPath,
            ["--image", imagePath, "--profile", "selfout", "--mode", "collect",
             "--out", imagePath]);

        Assert.NotEqual(0, result.ExitCode);
    }

    [Fact]
    public void OutUnderSymlinkedGrandparentDirectory_IsRefused()
    {
        // N1: a symlinked grandparent redirects the atomic rename exactly
        // like a symlinked parent; the immediate parent alone is real here.
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-grandparent");
        var imagePath = Path.Combine(temp.Path, "single.apfs.img");
        WriteCVolumeFixture(imagePath, Guid.NewGuid(), Guid.NewGuid());
        var realDir = Path.Combine(temp.Path, "realdir");
        Directory.CreateDirectory(realDir);
        var subDir = Path.Combine(realDir, "sub");
        Directory.CreateDirectory(subDir);
        var linkDir = Path.Combine(temp.Path, "linkdir");
        Directory.CreateSymbolicLink(linkDir, realDir);
        var outPath = Path.Combine(linkDir, "sub", "evidence.json");

        var result = Runner().Run(observerPath,
            ["--image", imagePath, "--profile", "grandparent", "--mode", "collect",
             "--out", outPath]);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("symlink", result.StandardError, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(Path.Combine(realDir, "sub", "evidence.json")));
    }

    [Fact]
    public void FusionEvidence_BindsPerStoreGeometryAndHashes()
    {
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-fusionbind");
        var containerUuid = Guid.NewGuid();
        var imageA = Path.Combine(temp.Path, "fusion-a.apfs.img");
        var imageB = Path.Combine(temp.Path, "fusion-b.apfs.img");
        WriteCVolumeFixture(imageA, containerUuid, Guid.NewGuid());
        WriteCVolumeFixture(imageB, containerUuid, Guid.NewGuid());
        var outPath = Path.Combine(temp.Path, "fusion.json");

        var result = Runner().Run(observerPath,
            ["--store-a", imageA, "--store-b", imageB, "--profile", "fusion-bind",
             "--mode", "fusion", "--out", outPath]);

        Assert.Equal(0, result.ExitCode);
        using var document = JsonDocument.Parse(File.ReadAllText(outPath));
        var root = document.RootElement;
        Assert.Equal("fusion", root.GetProperty("mode").GetString());
        var stores = root.GetProperty("topology").GetProperty("stores");
        Assert.Equal(2, stores.GetArrayLength());
        foreach (var store in stores.EnumerateArray())
        {
            Assert.True(store.TryGetProperty("blockSizeBytes", out var blockSize));
            Assert.True(store.TryGetProperty("totalBlocks", out var totalBlocks));
            Assert.True(blockSize.GetInt64() >= 512);
            Assert.True(totalBlocks.GetInt64() >= 1);
        }
        // Both members share one container block geometry.
        Assert.Equal(
            stores[0].GetProperty("blockSizeBytes").GetInt64(),
            stores[1].GetProperty("blockSizeBytes").GetInt64());
        // Each input hash independently binds its bytes.
        Assert.Equal(Sha256Of(imageA), root.GetProperty("source").GetProperty("sha256").GetString());
        var secondary = root.GetProperty("secondarySources");
        Assert.Equal(Sha256Of(imageB), secondary[0].GetProperty("sha256").GetString());
        // Distinct partition identities across members.
        var partitions = root.GetProperty("topology").GetProperty("partitions");
        var guids = partitions.EnumerateArray().Select(static entry => entry.GetProperty("uuid").GetString());
        Assert.Equal(2, guids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void FusionMultiStoreInput_IsRejectedAsAmbiguous()
    {
        // One image holding two APFS partitions is not a single member.
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-ambiguous");
        var containerUuid = Guid.NewGuid();
        var twoStore = Path.Combine(temp.Path, "twostore.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            twoStore,
            new CatalogFixtureSpec(16,
            [
                new CatalogPartitionSpec("P1", PartitionUuid: Guid.NewGuid(), ContainerUuid: containerUuid,
                    Volumes: [new CatalogVolumeSpec("Data")]),
                new CatalogPartitionSpec("P2", PartitionUuid: Guid.NewGuid(), ContainerUuid: containerUuid,
                    Volumes: [new CatalogVolumeSpec("Data2")]),
            ]));
        var imageB = Path.Combine(temp.Path, "b.apfs.img");
        WriteCVolumeFixture(imageB, containerUuid, Guid.NewGuid());

        var result = Runner().Run(observerPath,
            ["--store-a", twoStore, "--store-b", imageB, "--profile", "fusion-ambiguous",
             "--mode", "fusion"]);

        Assert.NotEqual(0, result.ExitCode);
    }

    [Fact]
    public void FusionSharedPartitionIdentity_IsRejected()
    {
        // Bit-identical copy: same partition GUID on both sides.
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-samepart");
        var containerUuid = Guid.NewGuid();
        var partitionUuid = Guid.NewGuid();
        var imageA = Path.Combine(temp.Path, "a.apfs.img");
        var imageB = Path.Combine(temp.Path, "b.apfs.img");
        WriteCVolumeFixture(imageA, containerUuid, partitionUuid);
        File.Copy(imageA, imageB, overwrite: true);

        var result = Runner().Run(observerPath,
            ["--store-a", imageA, "--store-b", imageB, "--profile", "fusion-samepart",
             "--mode", "fusion"]);

        Assert.NotEqual(0, result.ExitCode);
    }

    [Fact]
    public void ObserverPortableSourcesAvoidWindowsIncludes()
    {
        // A7: the portable parser/hash surface must stay free of Windows-only
        // includes so the observer keeps building on macOS (NotReached here).
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var level = 0; level < 14 && directory is not null; level++)
        {
            var candidate = Path.Combine(
                directory.FullName, "src-native", "ApfsAccess.ApfsRwEngine");
            var portableHeaders = new[]
            {
                Path.Combine(candidate, "include", "ApfsFormat.h"),
                Path.Combine(candidate, "include", "RandomAccessSource.h"),
                Path.Combine(candidate, "include", "ApfsContainerCatalog.h"),
                Path.Combine(candidate, "tools", "Sha256.h"),
                Path.Combine(candidate, "tools", "Sha256Portable.cpp"),
            };
            if (!portableHeaders.All(File.Exists))
            {
                directory = directory.Parent;
                continue;
            }

            foreach (var path in portableHeaders)
            {
                var text = File.ReadAllText(path);
                Assert.DoesNotContain("Windows.h", text);
                Assert.DoesNotContain("bcrypt.h", text);
                Assert.DoesNotContain("BlockDevice.h", text);
            }

            return;
        }

        Assert.Fail("Could not locate src-native/ApfsAccess.ApfsRwEngine from test host.");
    }

    private static string Sha256Of(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateHardLink(string newFileName, string existingFileName, nint reserved);
}
