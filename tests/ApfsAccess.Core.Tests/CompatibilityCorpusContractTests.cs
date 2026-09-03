using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace ApfsAccess.Core.Tests;

public sealed class CompatibilityCorpusContractTests
{
    [Fact]
    public async Task Validator_AcceptsCompleteObservedManifest()
    {
        var result = await ValidateAsync(ValidManifest());

        Assert.True(result.ExitCode == 0, result.StdErr);
        Assert.Contains("manifest valid", result.StdOut, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Validator_EnforcesJsonSchema()
    {
        await AssertRejectedAsync(
            manifest => manifest["unexpected"] = true,
            "schema");
    }

    [Theory]
    [InlineData("../../escape.sparseimage")]
    [InlineData("/tmp/escape.sparseimage")]
    [InlineData("C:/escape.sparseimage")]
    public async Task Validator_RejectsUnsafeArtifactPath(string path)
    {
        await AssertRejectedAsync(
            manifest => manifest["artifacts"]![0]!["path"] = path,
            "path");
    }

    [Fact]
    public async Task Validator_RejectsArtifactStorageMismatch()
    {
        await AssertRejectedAsync(
            manifest => manifest["artifacts"]![0]!["storage"] = "external",
            "storage");
    }

    [Fact]
    public async Task Validator_RejectsMissingRawApfsObservation()
    {
        await AssertRejectedAsync(
            manifest => manifest["topology"]!["volumes"]![0]!.AsObject().Remove("incompatibleFeatureBits"),
            "incompatibleFeatureBits");
    }

    [Fact]
    public async Task Validator_RejectsCloneWhoseSharedExtentHasOnlyOneOwner()
    {
        var manifest = ValidManifest();
        manifest["profile"] = "clones";
        manifest["features"]!.AsArray().Add("Clones");
        var source = manifest["content"]!["files"]![0]!.AsObject();
        source["cloneId"] = "clone:c1";
        var clone = source.DeepClone().AsObject();
        clone["id"] = "file:clone";
        clone["path"] = "clone.txt";
        clone["metadataId"] = "metadata:clone";
        clone["extentIds"] = new JsonArray("extent:clone");
        manifest["content"]!["files"]!.AsArray().Add(clone);
        manifest["content"]!["metadata"]!.AsArray().Add(new JsonObject
        {
            ["id"] = "metadata:clone",
            ["fileId"] = "file:clone",
            ["inode"] = 43,
            ["mode"] = 420,
            ["uid"] = 501,
            ["gid"] = 20,
            ["nlink"] = 1,
            ["logicalSizeBytes"] = 12,
            ["allocatedSizeBytes"] = 4096,
            ["flags"] = new JsonArray(),
            ["evidenceArtifactId"] = "artifact:observer"
        });
        manifest["content"]!["extents"]!.AsArray().Add(new JsonObject
        {
            ["id"] = "extent:clone",
            ["fileIds"] = new JsonArray("file:clone"),
            ["logicalOffset"] = 0,
            ["lengthBytes"] = 12,
            ["physicalOffset"] = 4096,
            ["kind"] = "data",
            ["refCount"] = 2,
            ["evidenceArtifactId"] = "artifact:observer"
        });
        manifest["content"]!["clones"]!.AsArray().Add(new JsonObject
        {
            ["id"] = "clone:c1",
            ["sourceFileId"] = "file:readme",
            ["cloneFileId"] = "file:clone",
            ["sharedExtentIds"] = new JsonArray("extent:clone"),
            ["evidenceArtifactId"] = "artifact:observer"
        });

        var result = await ValidateAsync(manifest);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("shared extent must belong to source and clone", result.StdErr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Validator_RejectsTopologyRecordPointingAtSecondObserverArtifact()
    {
        await AssertRejectedAsync(
            manifest =>
            {
                manifest["artifacts"]!.AsArray().Add(new JsonObject
                {
                    ["id"] = "artifact:observer-2",
                    ["path"] = "evidence/second-observer.json",
                    ["kind"] = "observer-output",
                    ["storage"] = "destination",
                    ["sha256"] = new string('d', 64),
                    ["sizeBytes"] = 512,
                    ["readOnly"] = true,
                    ["storeId"] = null
                });
                manifest["topology"]!["volumes"]![0]!["evidenceArtifactId"] = "artifact:observer-2";
                manifest["sha256"] = ArtifactSetSha256(manifest["artifacts"]!.AsArray());
            },
            "single observation evidence");
    }

    [Fact]
    public async Task Validator_RejectsClonePointingAtAlternateObserverArtifact()
    {
        var manifest = ValidManifest();
        manifest["profile"] = "clones";
        manifest["features"]!.AsArray().Add("Clones");
        manifest["artifacts"]!.AsArray().Add(new JsonObject
        {
            ["id"] = "artifact:observer-2",
            ["path"] = "evidence/second-observer.json",
            ["kind"] = "observer-output",
            ["storage"] = "destination",
            ["sha256"] = new string('d', 64),
            ["sizeBytes"] = 512,
            ["readOnly"] = true,
            ["storeId"] = null
        });
        var source = manifest["content"]!["files"]![0]!.AsObject();
        source["cloneId"] = "clone:c1";
        var clone = source.DeepClone().AsObject();
        clone["id"] = "file:clone";
        clone["path"] = "clone.txt";
        clone["metadataId"] = "metadata:clone";
        clone["extentIds"] = new JsonArray("extent:readme");
        manifest["content"]!["files"]!.AsArray().Add(clone);
        manifest["content"]!["metadata"]!.AsArray().Add(new JsonObject
        {
            ["id"] = "metadata:clone",
            ["fileId"] = "file:clone",
            ["inode"] = 43,
            ["mode"] = 420,
            ["uid"] = 501,
            ["gid"] = 20,
            ["nlink"] = 1,
            ["logicalSizeBytes"] = 12,
            ["allocatedSizeBytes"] = 4096,
            ["flags"] = new JsonArray(),
            ["evidenceArtifactId"] = "artifact:observer"
        });
        var extent = manifest["content"]!["extents"]![0]!.AsObject();
        extent["fileIds"] = new JsonArray("file:readme", "file:clone");
        extent["refCount"] = 2;
        manifest["content"]!["clones"]!.AsArray().Add(new JsonObject
        {
            ["id"] = "clone:c1",
            ["sourceFileId"] = "file:readme",
            ["cloneFileId"] = "file:clone",
            ["sharedExtentIds"] = new JsonArray("extent:readme"),
            ["evidenceArtifactId"] = "artifact:observer-2"
        });
        manifest["sha256"] = ArtifactSetSha256(manifest["artifacts"]!.AsArray());

        var result = await ValidateAsync(manifest);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("single observation evidence", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Validator_AcceptsCompleteFusionManifest()
    {
        var result = await ValidateAsync(ValidFusionManifest());

        Assert.True(result.ExitCode == 0, result.StdErr);
        Assert.Contains("manifest valid", result.StdOut, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Validator_RejectsFusionMemberThatIsNotARawStore()
    {
        var manifest = ValidFusionManifest();
        manifest["artifacts"]![0]!["kind"] = "sparse-image";

        var result = await ValidateAsync(manifest);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("raw-store", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Validator_RejectsFusionWithSwappedStoreBinding()
    {
        var manifest = ValidFusionManifest();
        manifest["topology"]!["stores"]![0]!["artifactId"] = "artifact:store-b";

        var result = await ValidateAsync(manifest);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("binding", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Generator_AvoidsGnuOnlyFindOptions()
    {
        var source = File.ReadAllText(RepoFile("scripts/create_apfs_compatibility_fixtures.sh"));

        Assert.DoesNotContain("-maxdepth", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProbeSymlink_CreatesFileDirectoryAndDanglingLinks()
    {
        var root = ScratchPath($"probe-symlinks-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var target = Path.Combine(root, "target.txt");
        await File.WriteAllTextAsync(target, "probe");
        var dirTarget = Path.Combine(root, "realdir");
        Directory.CreateDirectory(dirTarget);
        var missing = Path.Combine(root, "missing.txt");
        var fileLink = Path.Combine(root, "file-link");
        var dirLink = Path.Combine(root, "dir-link");
        var danglingLink = Path.Combine(root, "dangling-link");
        var script = BashQuote(ToBashPath(RepoFile("scripts/create_apfs_compatibility_fixtures.sh")));

        var result = await RunBashAsync([
            "-c",
            $"source {script} && " +
            $"make_probe_symlink file {BashQuote(ToBashPath(target))} {BashQuote(ToBashPath(fileLink))} && " +
            $"make_probe_symlink dir {BashQuote(ToBashPath(dirTarget))} {BashQuote(ToBashPath(dirLink))} && " +
            $"make_probe_symlink dangling {BashQuote(ToBashPath(missing))} {BashQuote(ToBashPath(danglingLink))}"
        ], timeout: TimeSpan.FromSeconds(60));

        Assert.True(result.ExitCode == 0, result.StdErr);
        Assert.Equal(CanonicalLinkTarget(target), CanonicalLinkTarget(new FileInfo(fileLink).LinkTarget));
        Assert.Equal(CanonicalLinkTarget(dirTarget), CanonicalLinkTarget(new DirectoryInfo(dirLink).LinkTarget));
        Assert.Equal(CanonicalLinkTarget(missing), CanonicalLinkTarget(new FileInfo(danglingLink).LinkTarget));
    }

    private static string? CanonicalLinkTarget(string? target)
    {
        // Windows may report symlink targets in extended-length (\\?\) form.
        if (target is null)
        {
            return null;
        }

        var canonical = target.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        const string extendedPrefix = @"\\?\";
        if (canonical.StartsWith(extendedPrefix, StringComparison.Ordinal))
        {
            canonical = canonical[extendedPrefix.Length..];
        }

        return canonical;
    }

    [Fact]
    public async Task ProbeSymlink_RefusesOrdinaryDestination()
    {
        var root = ScratchPath($"probe-symlink-refusal-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var target = Path.Combine(root, "target.txt");
        await File.WriteAllTextAsync(target, "probe");
        var occupied = Path.Combine(root, "occupied.txt");
        await File.WriteAllTextAsync(occupied, "ordinary file, not a link");
        var script = BashQuote(ToBashPath(RepoFile("scripts/create_apfs_compatibility_fixtures.sh")));

        var result = await RunBashAsync([
            "-c",
            $"source {script} && make_probe_symlink file {BashQuote(ToBashPath(target))} {BashQuote(ToBashPath(occupied))}"
        ], timeout: TimeSpan.FromSeconds(60));

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("not a symlink", result.StdErr, StringComparison.OrdinalIgnoreCase);
        Assert.Null(new FileInfo(occupied).LinkTarget);
    }

    [Fact]
    public async Task Validator_RejectsFusionMissingObservedMember()
    {
        await AssertRejectedAsync(
            manifest =>
            {
                manifest["profile"] = "fusion";
                manifest["features"]!.AsArray().Add("Fusion");
                manifest["topology"]!["containers"]![0]!["fusion"] = true;
                manifest["fusion"] = new JsonObject
                {
                    ["containerId"] = "container:c1",
                    ["memberStoreIds"] = new JsonArray("store:s1"),
                    ["artifactIds"] = new JsonArray("artifact:image")
                };
            },
            "exactly two observed member stores");
    }

    [Fact]
    public async Task Validator_RejectsMissingPerVolumePolicy()
    {
        await AssertRejectedAsync(
            manifest => manifest["mountPolicies"]!.AsArray().Clear(),
            "exactly one mount policy");
    }

    [Fact]
    public async Task Validator_RejectsInlineCredentialMaterial()
    {
        await AssertRejectedAsync(
            manifest => manifest["credentials"]!.AsArray().Add(new JsonObject
            {
                ["volumeId"] = "volume:v1",
                ["externalReference"] = "keychain:apfs-access-test",
                ["password"] = "inline-material"
            }),
            "secret-like property");
    }

    [Fact]
    public async Task Validator_RequiresOwnedVersionedObservationContract()
    {
        await AssertRejectedAsync(
            manifest => manifest.AsObject().Remove("observation"),
            "observation");

        await AssertRejectedAsync(
            manifest => manifest["observation"]!["observerVersion"] = "0.0.0",
            "observerVersion");
    }

    [Fact]
    public async Task Validator_RequiresObservationToMatchItsEvidenceArtifact()
    {
        await AssertRejectedAsync(
            manifest => manifest["observation"]!["evidenceArtifactId"] = "artifact:image",
            "observation evidence");

        await AssertRejectedAsync(
            manifest => manifest["observation"]!["recordSha256"] = new string('e', 64),
            "observation hash");
    }

    [Fact]
    public async Task SelfTest_LateFailureRemovesSelfTestRoot()
    {
        var tempRoot = ScratchPath("temp");
        Directory.CreateDirectory(tempRoot);
        var beforeRoots = SelfTestRoots(tempRoot);
        var beforeStaging = StagingEntries(tempRoot);
        var extraEnvironment = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["APFS_SELF_TEST_FAIL_AT"] = "late-probes"
        };

        var result = await RunScriptAsync(["--self-test"], timeout: TimeSpan.FromMinutes(10), extraEnvironment: extraEnvironment);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("injected self-test failure", result.StdErr, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(SelfTestRoots(tempRoot).Except(beforeRoots, StringComparer.OrdinalIgnoreCase));
        Assert.Empty(StagingEntries(tempRoot).Except(beforeStaging, StringComparer.OrdinalIgnoreCase));
    }

    private static HashSet<string> SelfTestRoots(string tempRoot)
    {
        try
        {
            return new HashSet<string>(Directory.GetDirectories(tempRoot, "apfs-compat-self-test.*"), StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is IOException || exception is UnauthorizedAccessException)
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private static HashSet<string> StagingEntries(string tempRoot)
    {
        try
        {
            return new HashSet<string>(Directory.EnumerateFileSystemEntries(tempRoot, "*.task0.*", SearchOption.AllDirectories), StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is IOException || exception is UnauthorizedAccessException)
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task SelfTest_ExecutesFakeDarwinGenerationContracts()
    {
        var result = await RunScriptAsync(["--self-test"], timeout: TimeSpan.FromSeconds(300));

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("SELF-TEST PASS: 18 generated profiles", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: authoritative observations enforced", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: volume group uses -groupWith", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: staged cleanup", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: corruption source read-only", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: fusion identities observed", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: BSD file command vectors", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: symlink path containment", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: C0a observer publication fail-closed", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: contract-only synthetic observations", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: single observation authority", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: fusion sealed store binding", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: portable depth-one checks", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: symlinked output parents refused", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: Fusion recipe pair uniqueness", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: immutable registration-window cleanup", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: atomic no-replace destination race", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: no-follow declared outputs", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: encrypted create and attach vectors", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("SELF-TEST PASS: streamed artifact hashing", result.StdOut, StringComparison.Ordinal);
    }

    [Fact]
    public void Generator_DoesNotMaterializeArtifactsForHashing()
    {
        var source = File.ReadAllText(RepoFile("scripts/create_apfs_compatibility_fixtures.sh"));

        Assert.DoesNotContain("read_bytes()", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Generation_RejectsObserverInjection()
    {
        var result = await RunScriptAsync([
            "--destination", ScratchPath($"observer-injection-{Guid.NewGuid():N}"),
            "--observer", RepoFile("scripts/create_apfs_compatibility_fixtures.sh")
        ]);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("unknown argument: --observer", result.StdErr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Generation_FailsClosedOffMacOsWithoutCreatingDestination()
    {
        if (OperatingSystem.IsMacOS())
        {
            return;
        }

        var destination = ScratchPath($"off-macos-{Guid.NewGuid():N}");
        var result = await RunScriptAsync([
            "--destination", destination,
            "--profile", "single-volume"
        ]);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("generation requires Darwin", result.StdErr, StringComparison.Ordinal);
        Assert.False(Directory.Exists(destination));
    }

    private static async Task AssertRejectedAsync(Action<JsonObject> mutate, string expectedError)
    {
        var manifest = ValidManifest();
        mutate(manifest);

        var result = await ValidateAsync(manifest);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(expectedError, result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    private static Task<ScriptResult> ValidateAsync(JsonObject manifest)
        => RunScriptAsync(["--validate-manifest", "-"], manifest.ToJsonString());

    private static JsonObject ValidManifest()
    {
        var manifest = JsonNode.Parse(
            """
            {
              "schemaVersion": 1,
              "fixtureId": "single-volume-basic",
              "profile": "single-volume",
              "macOS": { "version": "15.6.1", "build": "24G90" },
              "features": [ "SingleVolume", "PosixMetadata" ],
              "topology": {
                "disks": [
                  { "id": "disk:d1", "deviceIdentifier": "disk4", "uuid": "10000000-0000-4000-8000-000000000001", "sizeBytes": 1048576, "evidenceArtifactId": "artifact:observer" }
                ],
                "partitions": [
                  { "id": "partition:p1", "uuid": "20000000-0000-4000-8000-000000000002", "diskId": "disk:d1", "index": 1, "startByte": 4096, "sizeBytes": 1044480, "evidenceArtifactId": "artifact:observer" }
                ],
                "stores": [
                  { "id": "store:s1", "uuid": "30000000-0000-4000-8000-000000000003", "partitionId": "partition:p1", "containerId": "container:c1", "artifactId": "artifact:image", "sizeBytes": 1044480, "evidenceArtifactId": "artifact:observer" }
                ],
                "containers": [
                  { "id": "container:c1", "uuid": "40000000-0000-4000-8000-000000000004", "blockSizeBytes": 4096, "storeIds": [ "store:s1" ], "volumeIds": [ "volume:v1" ], "fusion": false, "compatibleFeatureBits": [ "0x1" ], "unknownFeatureBits": [], "incompatibleFeatureBits": [], "evidenceArtifactId": "artifact:observer" }
                ],
                "volumes": [
                  { "id": "volume:v1", "uuid": "50000000-0000-4000-8000-000000000005", "objectId": "7", "containerId": "container:c1", "name": "APFSAccess-single-volume", "roles": [ "data" ], "groupId": null, "caseMode": "insensitive", "encryptionMode": "none", "locked": false, "compatibleFeatureBits": [ "0x1" ], "unknownFeatureBits": [], "incompatibleFeatureBits": [], "evidenceArtifactId": "artifact:observer" }
                ],
                "groups": []
              },
              "mountPolicies": [
                { "volumeId": "volume:v1", "requestedAccess": "read-write", "decision": "read-write", "autoMount": true, "reasons": [] }
              ],
              "credentials": [],
              "observation": {
                "format": "apfs-access-raw-evidence",
                "version": 1,
                "observerId": "apfs-access-owned-raw-observer",
                "observerVersion": "1.0.0",
                "mode": "collect",
                "evidenceArtifactId": "artifact:observer",
                "recordSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
              },
              "content": {
                "files": [
                  { "id": "file:readme", "volumeId": "volume:v1", "path": "readme.txt", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "sizeBytes": 12, "metadataId": "metadata:readme", "xattrIds": [], "extentIds": [ "extent:readme" ], "linkIds": [], "cloneId": null }
                ],
                "metadata": [
                  { "id": "metadata:readme", "fileId": "file:readme", "inode": 42, "mode": 420, "uid": 501, "gid": 20, "nlink": 1, "logicalSizeBytes": 12, "allocatedSizeBytes": 4096, "flags": [], "evidenceArtifactId": "artifact:observer" }
                ],
                "acls": [],
                "xattrs": [],
                "resourceForks": [],
                "compression": [],
                "extents": [
                  { "id": "extent:readme", "fileIds": [ "file:readme" ], "logicalOffset": 0, "lengthBytes": 12, "physicalOffset": 4096, "kind": "data", "refCount": 1, "evidenceArtifactId": "artifact:observer" }
                ],
                "links": [],
                "clones": [],
                "snapshots": []
              },
              "artifacts": [
                { "id": "artifact:image", "path": "images/single-volume.sparseimage", "kind": "sparse-image", "storage": "destination", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sizeBytes": 1048576, "readOnly": true, "storeId": "store:s1" },
                { "id": "artifact:observer", "path": "evidence/single-volume-observer.json", "kind": "observer-output", "storage": "destination", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "sizeBytes": 512, "readOnly": true, "storeId": null }
              ],
              "corruption": null,
              "fusion": null,
              "sha256": "replace-me",
              "expectedManifest": "manifests/single-volume.json"
            }
            """)!.AsObject();

        manifest["sha256"] = ArtifactSetSha256(manifest["artifacts"]!.AsArray());
        return manifest;
    }

    private static JsonObject ValidFusionManifest()
    {
        var manifest = JsonNode.Parse(
            """
            {
              "schemaVersion": 1,
              "fixtureId": "fusion-two-store",
              "profile": "fusion",
              "macOS": { "version": "15.6.1", "build": "24G90" },
              "features": [ "Fusion", "PosixMetadata" ],
              "topology": {
                "disks": [
                  { "id": "disk:d1", "deviceIdentifier": "disk4", "uuid": "10000000-0000-4000-8000-000000000001", "sizeBytes": 1048576, "evidenceArtifactId": "artifact:observer" },
                  { "id": "disk:d2", "deviceIdentifier": "disk5", "uuid": "10000000-0000-4000-8000-000000000002", "sizeBytes": 1048576, "evidenceArtifactId": "artifact:observer" }
                ],
                "partitions": [
                  { "id": "partition:p1", "uuid": "20000000-0000-4000-8000-000000000002", "diskId": "disk:d1", "index": 1, "startByte": 4096, "sizeBytes": 1044480, "evidenceArtifactId": "artifact:observer" },
                  { "id": "partition:p2", "uuid": "20000000-0000-4000-8000-000000000003", "diskId": "disk:d2", "index": 1, "startByte": 4096, "sizeBytes": 1044480, "evidenceArtifactId": "artifact:observer" }
                ],
                "stores": [
                  { "id": "store:s1", "uuid": "30000000-0000-4000-8000-000000000003", "partitionId": "partition:p1", "containerId": "container:c1", "artifactId": "artifact:store-a", "sizeBytes": 1044480, "evidenceArtifactId": "artifact:observer" },
                  { "id": "store:s2", "uuid": "30000000-0000-4000-8000-000000000004", "partitionId": "partition:p2", "containerId": "container:c1", "artifactId": "artifact:store-b", "sizeBytes": 1044480, "evidenceArtifactId": "artifact:observer" }
                ],
                "containers": [
                  { "id": "container:c1", "uuid": "40000000-0000-4000-8000-000000000004", "blockSizeBytes": 4096, "storeIds": [ "store:s1", "store:s2" ], "volumeIds": [ "volume:v1" ], "fusion": true, "compatibleFeatureBits": [ "0x1" ], "unknownFeatureBits": [], "incompatibleFeatureBits": [], "evidenceArtifactId": "artifact:observer" }
                ],
                "volumes": [
                  { "id": "volume:v1", "uuid": "50000000-0000-4000-8000-000000000005", "objectId": "7", "containerId": "container:c1", "name": "APFSAccess-fusion", "roles": [ "data" ], "groupId": null, "caseMode": "insensitive", "encryptionMode": "none", "locked": false, "compatibleFeatureBits": [ "0x1" ], "unknownFeatureBits": [], "incompatibleFeatureBits": [], "evidenceArtifactId": "artifact:observer" }
                ],
                "groups": []
              },
              "mountPolicies": [
                { "volumeId": "volume:v1", "requestedAccess": "read-write", "decision": "read-write", "autoMount": true, "reasons": [] }
              ],
              "credentials": [],
              "observation": {
                "format": "apfs-access-raw-evidence",
                "version": 1,
                "observerId": "apfs-access-owned-raw-observer",
                "observerVersion": "1.0.0",
                "mode": "fusion",
                "evidenceArtifactId": "artifact:observer",
                "recordSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
              },
              "content": {
                "files": [
                  { "id": "file:readme", "volumeId": "volume:v1", "path": "readme.txt", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "sizeBytes": 12, "metadataId": "metadata:readme", "xattrIds": [], "extentIds": [ "extent:readme" ], "linkIds": [], "cloneId": null }
                ],
                "metadata": [
                  { "id": "metadata:readme", "fileId": "file:readme", "inode": 42, "mode": 420, "uid": 501, "gid": 20, "nlink": 1, "logicalSizeBytes": 12, "allocatedSizeBytes": 4096, "flags": [], "evidenceArtifactId": "artifact:observer" }
                ],
                "acls": [],
                "xattrs": [],
                "resourceForks": [],
                "compression": [],
                "extents": [
                  { "id": "extent:readme", "fileIds": [ "file:readme" ], "logicalOffset": 0, "lengthBytes": 12, "physicalOffset": 4096, "kind": "data", "refCount": 1, "evidenceArtifactId": "artifact:observer" }
                ],
                "links": [],
                "clones": [],
                "snapshots": []
              },
              "artifacts": [
                { "id": "artifact:store-a", "path": "images/fusion-store-a.img", "kind": "raw-store", "storage": "destination", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sizeBytes": 8192, "readOnly": true, "storeId": "store:s1" },
                { "id": "artifact:store-b", "path": "images/fusion-store-b.img", "kind": "raw-store", "storage": "destination", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "sizeBytes": 8192, "readOnly": true, "storeId": "store:s2" },
                { "id": "artifact:observer", "path": "evidence/fusion-observer.json", "kind": "observer-output", "storage": "destination", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "sizeBytes": 512, "readOnly": true, "storeId": null }
              ],
              "corruption": null,
              "fusion": {
                "containerId": "container:c1",
                "memberStoreIds": [ "store:s1", "store:s2" ],
                "artifactIds": [ "artifact:store-a", "artifact:store-b" ]
              },
              "sha256": "replace-me",
              "expectedManifest": "manifests/fusion.json"
            }
            """)!.AsObject();

        manifest["sha256"] = ArtifactSetSha256(manifest["artifacts"]!.AsArray());
        return manifest;
    }

    private static string ArtifactSetSha256(JsonArray artifacts)
    {
        var index = artifacts
            .Select(artifact => (Id: artifact!["id"]!.GetValue<string>(), Hash: artifact["sha256"]!.GetValue<string>()))
            .OrderBy(item => item.Id, StringComparer.Ordinal);
        var payload = string.Concat(index.Select(item => $"{item.Id}:{item.Hash}\n"));
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(payload)));
    }

    private static async Task<ScriptResult> RunScriptAsync(
        IReadOnlyList<string> arguments,
        string? standardInput = null,
        TimeSpan? timeout = null,
        IDictionary<string, string>? extraEnvironment = null)
    {
        var bashArguments = new List<string> { "scripts/create_apfs_compatibility_fixtures.sh" };
        bashArguments.AddRange(arguments);
        return await RunBashAsync(bashArguments, standardInput, timeout, extraEnvironment);
    }

    private static async Task<ScriptResult> RunBashAsync(
        IReadOnlyList<string> arguments,
        string? standardInput = null,
        TimeSpan? timeout = null,
        IDictionary<string, string>? extraEnvironment = null)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = BashPath(),
            WorkingDirectory = RepoRoot(),
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        var scriptTemp = ScratchPath("temp");
        Directory.CreateDirectory(scriptTemp);
        startInfo.Environment["TEMP"] = scriptTemp;
        startInfo.Environment["TMP"] = scriptTemp;
        startInfo.Environment["TMPDIR"] = ToBashPath(scriptTemp);
        if (extraEnvironment is not null)
        {
            foreach (var entry in extraEnvironment)
            {
                startInfo.Environment[entry.Key] = entry.Value;
            }
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start Bash.");
        if (standardInput is not null)
        {
            await process.StandardInput.WriteAsync(standardInput);
        }
        process.StandardInput.Close();

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        using var cancellation = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(20));
        try
        {
            await process.WaitForExitAsync(cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Compatibility fixture script timed out.");
        }

        return new ScriptResult(process.ExitCode, await outputTask, await errorTask);
    }

    private static string BashPath()
    {
        if (!OperatingSystem.IsWindows())
        {
            return "/bin/bash";
        }

        foreach (var candidate in new[]
        {
            @"C:\Program Files\Git\bin\bash.exe",
            @"C:\Program Files\Git\usr\bin\bash.exe"
        })
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException("Git Bash is required for the compatibility corpus contract tests.");
    }

    private static string RepoFile(string relativePath)
        => Path.Combine(RepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar));

    private static string BashQuote(string value)
        => "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";

    private static string ToBashPath(string path)
    {
        var fullPath = Path.GetFullPath(path).Replace('\\', '/');
        if (OperatingSystem.IsWindows() && fullPath.Length >= 3 && fullPath[1] == ':')
        {
            return $"/{char.ToLowerInvariant(fullPath[0])}{fullPath[2..]}";
        }

        return fullPath;
    }

    private static string ScratchPath(string leaf)
    {
        // Windows runs keep every test/build/temp artifact on the D: drive.
        // Non-Windows hosts fall back to a writable temp root instead of a
        // drive-rooted scratch directory that a normal test process cannot create.
        var baseDir = OperatingSystem.IsWindows()
            ? Path.Combine(Path.GetPathRoot(RepoRoot())!, "ApfsAccessScratch", "Task0ContractTests")
            : Path.Combine(Path.GetTempPath(), "ApfsAccessScratch", "Task0ContractTests");
        return Path.Combine(baseDir, leaf);
    }

    private static string RepoRoot()
    {
        var sourceRoot = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(SourceFile())!, "..", ".."));
        if (File.Exists(Path.Combine(sourceRoot, "APFSAccess.sln")))
        {
            return sourceRoot;
        }

        foreach (var start in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory })
        {
            var directory = new DirectoryInfo(start);
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "APFSAccess.sln")))
            {
                directory = directory.Parent;
            }

            if (directory is not null)
            {
                return directory.FullName;
            }
        }

        throw new DirectoryNotFoundException("Unable to locate the APFS Access source root.");
    }

    private static string SourceFile([CallerFilePath] string path = "") => path;

    private sealed record ScriptResult(int ExitCode, string StdOut, string StdErr);
}
