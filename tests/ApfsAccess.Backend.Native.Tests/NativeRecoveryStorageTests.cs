using System.Collections;
using System.Diagnostics;
using System.Reflection;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeRecoveryStorageTests
{
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Volume = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static string Identity => "apfs-recovery-v1-" + new string('A', 43);

    [Fact]
    public void NamespaceMaterialMatchesPreservedPhysicalGuidByteOrderAndHash()
    {
        var partition = Guid.Parse("ad5417e5-775b-4ea1-bc68-2c794301dc6d");
        var bytes = NativeRecoveryStorage.BuildNamespaceMaterial(partition, "055066cd975a4448954c4eab521a5263", 1026, false)!;
        Assert.Equal("01e51754ad5b77a14ebc682c794301dc6d055066cd975a4448954c4eab521a5263010204000000000000", Convert.ToHexStringLower(bytes));
        Assert.Equal("apfs-recovery-v1-qVfof8h5-2GLuP800FeVYdLgAHTeLmPFYW_3wubt61Q", NativeRecoveryStorage.NamespaceRecoveryIdentity(bytes));
        Assert.Null(NativeRecoveryStorage.BuildNamespaceMaterial(null, Container, 101, false));
        Assert.Null(NativeRecoveryStorage.BuildNamespaceMaterial(null, new string('0', 32), 101, true));
        Assert.Null(NativeRecoveryStorage.BuildNamespaceMaterial(null, Container, 0, true));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void NamespacePublicationIsImmutableAndRefusesTornOrConflictingFinal(bool torn)
    {
        using var temp = DTempDirectory.Create("namespace-publication");
        var partition = Guid.Parse("ad5417e5-775b-4ea1-bc68-2c794301dc6d");
        var id = NativeApfsBackend.BuildRecoveryIdentityFromComponents(partition, Container, 101, false)!;
        void Publish() => NativeRecoveryStorage.EnsureNamespaceWitness(temp.Path, ApfsTopology.BuildPartitionId(partition), Container, 101, id, false);
        Publish();
        var path = NativeRecoveryStorage.NamespaceWitnessPath(temp.Path, id);
        var before = File.ReadAllBytes(path); var stamp = File.GetLastWriteTimeUtc(path);
        Publish(); Assert.Equal(before, File.ReadAllBytes(path)); Assert.Equal(stamp, File.GetLastWriteTimeUtc(path));
        Assert.Single(Directory.GetFiles(temp.Path));
        var corrupt = torn ? before[..41] : before.ToArray();
        if (!torn) corrupt[17] ^= 1;
        File.WriteAllBytes(path, corrupt);
        Assert.Throws<IOException>(Publish);
        Assert.Equal(corrupt, File.ReadAllBytes(path)); Assert.Single(Directory.GetFiles(temp.Path));
    }

    [Fact]
    public void NamespaceEmitterRequiresExactTargetAndCanonicalPhysicalPartition()
    {
        using var temp = DTempDirectory.Create("namespace-target");
        var partition = Guid.Parse("ad5417e5-775b-4ea1-bc68-2c794301dc6d");
        var id = NativeApfsBackend.BuildRecoveryIdentityFromComponents(partition, Container, 101, false)!;
        Assert.Throws<IOException>(() => NativeRecoveryStorage.EnsureNamespaceWitness(temp.Path, null, Container, 101, id, false));
        Assert.Throws<IOException>(() => NativeRecoveryStorage.EnsureNamespaceWitness(temp.Path, partition.ToString("D"), Container, 101, id, false));
        Assert.Throws<IOException>(() => NativeRecoveryStorage.EnsureNamespaceWitness(temp.Path, "apfs-part:" + Guid.Empty.ToString("D"), Container, 101, id, true));
        Assert.Throws<IOException>(() => NativeRecoveryStorage.EnsureNamespaceWitness(temp.Path, ApfsTopology.BuildPartitionId(partition), Container, 102, id, false));
        Assert.Throws<InvalidDataException>(() => NativeRecoveryStorage.NamespaceWitnessPath(temp.Path, id[..^1] + "B"));
        Assert.Empty(Directory.GetFiles(temp.Path));
    }

    [Fact]
    public void ForeignClassificationRequiresEveryClosureContainerOrRealDistinctPhysicalPartitions()
    {
        var partition = Guid.Parse("ad5417e5-775b-4ea1-bc68-2c794301dc6d");
        var other = Guid.Parse("11111111-2222-3333-4444-555555555555");
        var selected = new NativeRecoveryStorage.NamespaceIdentity(partition, Container, 101);
        Assert.True(NativeRecoveryStorage.IsForeignNamespace(new(partition, new string('b', 32), 101), [selected]));
        Assert.True(NativeRecoveryStorage.IsForeignNamespace(new(other, Container, 999), [selected]));
        Assert.False(NativeRecoveryStorage.IsForeignNamespace(new(Guid.Empty, Container, 999), [selected]));
        Assert.False(NativeRecoveryStorage.IsForeignNamespace(new(partition, Container, 999), [selected]));
        Assert.False(NativeRecoveryStorage.IsForeignNamespace(new(partition, Container, 999), [selected with { PartitionGuid = Guid.Empty }]));
        Assert.False(NativeRecoveryStorage.IsForeignNamespace(new(partition, new string('b', 32), 999),
            [selected, new(partition, new string('b', 32), 102)]));
        Assert.False(NativeRecoveryStorage.IsForeignNamespace(new(partition, new string('b', 32), 999), []));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void CurrentCensusJoinsClosureBeforeAnyLaunchOrAfterContainerReplacement(bool oldContainerLaunched)
    {
        using var temp = DTempDirectory.Create("current-closure-union");
        var journals = Path.Combine(temp.Path, "journals"); var spool = Path.Combine(temp.Path, "spool"); var recovery = Path.Combine(temp.Path, "recovery");
        Directory.CreateDirectory(journals); Directory.CreateDirectory(spool); Directory.CreateDirectory(recovery);
        var original = Path.Combine(temp.Path, "original.apfs"); var image = Path.Combine(temp.Path, "current.apfs");
        File.WriteAllBytes(original, new byte[2097152]);
        NativeOrdinaryImageOwnership.RegisterFreshCopy(new(original, image), journals, spool, recovery);
        var inventory = Inventory(image);
        var id = NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, Container, 101, true)!;
        inventory = inventory with { Volumes = [inventory.Volumes[0] with { RecoveryIdentity = id }] };
        if (oldContainerLaunched)
        {
            var oldContainer = new string('d', 32);
            var launch = new ProcessStartInfo("no-process-launched.exe"); launch.Environment["APFSACCESS_SPOOL_ROOT"] = spool;
            launch.Environment["APFSACCESS_RECOVERY_ROOT"] = recovery;
            NativeOrdinaryImageOwnership.CaptureLaunch(launch, journals, image, "0", [inventory.Volumes[0] with {
                CatalogContainerUuid = oldContainer, RecoveryIdentity = NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, oldContainer, 101, true) }]);
        }
        var scope = VerifyScopeDerivation.TryDerive(inventory, inventory.Volumes[0]).Scope!;
        var wal = NativeRecoveryStorage.CanonicalWal(spool, id); Directory.CreateDirectory(Path.GetDirectoryName(wal)!); File.WriteAllBytes(wal, []);
        Assert.Equal(wal, Assert.Single(NativeRecoveryStorage.BindCensus(scope, inventory, [(Volume, "101")], spool, recovery, journals)).Path);
        var unknown = NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, Container, 999, true)!;
        NativeRecoveryStorage.EnsureNamespaceWitness(journals, null, Container, 999, unknown, true);
        var unknownWal = NativeRecoveryStorage.CanonicalWal(spool, unknown); Directory.CreateDirectory(Path.GetDirectoryName(unknownWal)!);
        File.WriteAllText(unknownWal, "current-container unknown OID cannot be excluded");
        var before = File.ReadAllBytes(unknownWal);
        var error = Assert.Throws<IOException>(() => NativeRecoveryStorage.BindCensus(scope, inventory, [(Volume, "101")], spool, recovery, journals));
        Assert.Contains("NamespaceScopeAmbiguous", error.Message); Assert.Equal(before, File.ReadAllBytes(unknownWal));
    }

    [Fact]
    public void ExplicitCurrentAdmissionPublishesOnlyAfterEveryRecoveryIdentityMatches()
    {
        using var temp = DTempDirectory.Create("current-namespace-admission");
        var image = Path.Combine(temp.Path, "image.apfs"); File.WriteAllBytes(image, new byte[2097152]);
        var inventory = Inventory(image);
        var scope = VerifyScopeDerivation.TryDerive(inventory, inventory.Volumes[0]).Scope!;
        var root = Path.Combine(temp.Path, "journals"); Directory.CreateDirectory(root);
        Assert.Throws<IOException>(() => NativeRecoveryStorage.EnsureCurrentNamespaceWitnesses(scope, inventory, root));
        Assert.Empty(Directory.GetFiles(root));
        var id = NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, Container, 101, true)!;
        inventory = inventory with { Volumes = [inventory.Volumes[0] with { RecoveryIdentity = id }] };
        NativeRecoveryStorage.EnsureCurrentNamespaceWitnesses(scope, inventory, root);
        Assert.Equal(NativeRecoveryStorage.BuildNamespaceMaterial(null, Container, 101, true),
            File.ReadAllBytes(NativeRecoveryStorage.NamespaceWitnessPath(root, id)));
    }

    public static IEnumerable<object[]> RawJournalLaunchCases()
    {
        foreach (var container in new[] { false, true })
        {
            yield return [container, false, "clear"];
            yield return [container, false, "missing"];
            foreach (var evidence in new[] { "clear", "native-vmt1", "native-vif1", "missing", "blank", "absent", "file",
                "relative", "unc", "ads", "managed-unknown", "repair-corrupt", "repair-incomplete" })
                yield return [container, true, evidence];
        }
    }

    [Theory]
    [MemberData(nameof(RawJournalLaunchCases))]
    public void OrdinaryAndContainerLaunchPublishBeforeProcessStartOnlyForReadWrite(bool containerLaunch, bool writable, string evidence)
    {
        using var temp = DTempDirectory.Create("namespace-launch");
        var journalRoot = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(journalRoot);
        string? configuredRoot = evidence switch {
            "missing" => null, "blank" => " ", "absent" => Path.Combine(temp.Path, "not-created"),
            "file" => Path.Combine(temp.Path, "not-directory"), "relative" => "relative-journal",
            "unc" => @"\\localhost\untrusted\journal", "ads" => journalRoot + ":stream", _ => journalRoot
        };
        if (evidence == "file") File.WriteAllText(configuredRoot!, "not a directory");
        var retainedPath = evidence switch {
            "native-vmt1" => Path.Combine(journalRoot, new string('a', 64) + ".vmt1"),
            "native-vif1" => Path.Combine(journalRoot, new string('a', 64) + ".vif1"),
            "managed-unknown" => Path.Combine(journalRoot, "managed-unproved.tmp"),
            "repair-corrupt" => Path.Combine(journalRoot, ImageRepairPersistence.Prefix + new string('b', 64) + ".json"),
            "repair-incomplete" => Path.Combine(journalRoot, ImageRepairPersistence.Prefix + "pending.tmp"), _ => null
        };
        // These bytes are opaque here: only held-source native admission can
        // classify a native journal as completed, pending, corrupt, or foreign.
        if (retainedPath is not null) File.WriteAllText(retainedPath, "preserved original evidence");
        var allowed = !writable || evidence is "clear" or "native-vmt1" or "native-vif1";
        var partition = Guid.Parse("ad5417e5-775b-4ea1-bc68-2c794301dc6d");
        // No source or native process is opened. The lifecycle hook stops at the launch boundary.
        const string device = @"\\.\PhysicalDrive999";
        var identity = NativeApfsBackend.BuildRecoveryIdentityFromComponents(partition, Container, 101, false)!;
        var row = new VolumeInfo("apfs-vol:" + Container + ":101", device, "Data", true, NativeVolumePath: device + "|Data",
            RecoveryIdentity: identity, CatalogContainerUuid: Container, CatalogVolumeObjectId: 101, CatalogVolumeUuid: Volume);
        var siblingIdentity = NativeApfsBackend.BuildRecoveryIdentityFromComponents(partition, Container, 102, false)!;
        var sibling = row with { VolumeId = "apfs-vol:" + Container + ":102", VolumeName = "ReadOnly", CatalogVolumeObjectId = 102,
            RecoveryIdentity = siblingIdentity };
        var started = false;
        using var backend = new NativeApfsBackend(new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false,
            NativeFsHostPath = Path.Combine(Environment.SystemDirectory, "PING.EXE"), ManagementJournalRoot = configuredRoot,
            NativeWriteEvidenceStorePath = Path.Combine(temp.Path, "evidence.json") },
            new HostProcessLifecycleTestHooks { StartProcess = start => {
                started = true;
                var arguments = start.ArgumentList.ToArray();
                Assert.Equal(writable ? 1 : 0, arguments.Count(a => a == "--management-journal-directory"));
                if (writable) Assert.Equal(configuredRoot, arguments[Array.IndexOf(arguments, "--management-journal-directory") + 1]);
                Assert.Equal(writable, File.Exists(NativeRecoveryStorage.NamespaceWitnessPath(journalRoot, identity)));
                Assert.Equal(containerLaunch && writable, File.Exists(NativeRecoveryStorage.NamespaceWitnessPath(journalRoot, siblingIdentity)));
                throw new InvalidOperationException("NamespaceLaunchBoundaryReached");
            } });
        var type = typeof(NativeApfsBackend);
        var targetType = type.GetNestedType("VolumeMountTarget", BindingFlags.NonPublic)!;
        var target = Activator.CreateInstance(targetType, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null,
            [device, 0UL, identity, (ulong?)101, Container, null, ApfsTopology.BuildPartitionId(partition)], null)!;
        ((IDictionary)type.GetField("_mountTargetsByVolumeId", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(backend)!).Add(row.VolumeId, target);
        var siblingTarget = Activator.CreateInstance(targetType, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null,
            [device, 0UL, siblingIdentity, (ulong?)102, Container, null, ApfsTopology.BuildPartitionId(partition)], null)!;
        ((IDictionary)type.GetField("_mountTargetsByVolumeId", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(backend)!).Add(sibling.VolumeId, siblingTarget);
        TargetInvocationException thrown;
        if (containerLaunch)
        {
            var manifest = new WrittenContainerManifest(Path.Combine(temp.Path, "manifest.json"), new string('a', 64), Container, device, 0,
                [new(101, Container, "Data", "R:\\", writable, identity), new(102, Container, "ReadOnly", "S:\\", false, siblingIdentity)]);
            thrown = Assert.Throws<TargetInvocationException>(() => type.GetMethod("StartContainerOwnerProcess", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(backend, [manifest, row, writable, new[] { row, sibling }]));
        }
        else
            thrown = Assert.Throws<TargetInvocationException>(() => type.GetMethod("StartHostProcess", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(backend, [row, "R:\\", writable ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly, null]));
        if (allowed)
            Assert.Equal("NamespaceLaunchBoundaryReached", Assert.IsType<InvalidOperationException>(thrown.GetBaseException()).Message);
        else
        {
            if (evidence is "repair-corrupt" or "repair-incomplete")
                Assert.Equal(evidence == "repair-corrupt" ? "ImageRepairIntentSchemaInvalid" : "ImageRepairIncompleteIntentPreserved",
                    Assert.IsType<InvalidDataException>(thrown.InnerException).Message);
            else Assert.True(thrown.InnerException is IOException or ArgumentException, thrown.ToString());
            Assert.Empty(Directory.GetFiles(journalRoot, "spool-namespace-*"));
        }
        Assert.Equal(allowed, started);
        Assert.False(Directory.Exists(Path.Combine(temp.Path, "not-created")));
        if (retainedPath is not null) Assert.Equal("preserved original evidence", File.ReadAllText(retainedPath));
    }

    [Theory]
    [InlineData("target")]
    [InlineData("hash")]
    public void InvalidLaterReadOnlyContainerMemberRefusesBeforeAnyWitnessOrProcess(string fault)
    {
        using var temp = DTempDirectory.Create("namespace-launch-invalid-later");
        const string device = @"\\.\PhysicalDrive999";
        var partition = Guid.Parse("ad5417e5-775b-4ea1-bc68-2c794301dc6d");
        var firstId = NativeApfsBackend.BuildRecoveryIdentityFromComponents(partition, Container, 101, false)!;
        var secondId = NativeApfsBackend.BuildRecoveryIdentityFromComponents(partition, fault == "hash" ? new string('c', 32) : Container, 102, false)!;
        var first = new VolumeInfo("apfs-vol:" + Container + ":101", device, "Data", true, NativeVolumePath: device + "|Data",
            RecoveryIdentity: firstId, CatalogContainerUuid: Container, CatalogVolumeObjectId: 101, CatalogVolumeUuid: Volume);
        var second = first with { VolumeId = "apfs-vol:" + Container + ":102", VolumeName = "ReadOnly", CatalogVolumeObjectId = 102,
            RecoveryIdentity = secondId };
        var started = false;
        using var backend = new NativeApfsBackend(new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false,
            NativeFsHostPath = Path.Combine(Environment.SystemDirectory, "PING.EXE"), ManagementJournalRoot = temp.Path,
            NativeWriteEvidenceStorePath = Path.Combine(temp.Path, "evidence.json") },
            new HostProcessLifecycleTestHooks { StartProcess = _ => { started = true; throw new InvalidOperationException("UnexpectedStart"); } });
        var type = typeof(NativeApfsBackend);
        var targetType = type.GetNestedType("VolumeMountTarget", BindingFlags.NonPublic)!;
        var targets = (IDictionary)type.GetField("_mountTargetsByVolumeId", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(backend)!;
        foreach (var row in new[] { first, second })
            targets.Add(row.VolumeId, Activator.CreateInstance(targetType, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null,
                [device, row == second && fault == "target" ? 4096UL : 0UL, row.RecoveryIdentity, row.CatalogVolumeObjectId,
                    Container, null, ApfsTopology.BuildPartitionId(partition)], null)!);
        var manifest = new WrittenContainerManifest(Path.Combine(temp.Path, "manifest.json"), new string('a', 64), Container, device, 0,
            [new(101, Container, "Data", "R:\\", true, firstId), new(102, Container, "ReadOnly", "S:\\", false, secondId)]);
        var thrown = Assert.Throws<TargetInvocationException>(() => type.GetMethod("StartContainerOwnerProcess", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(backend, [manifest, first, true, new[] { first, second }]));
        Assert.IsType<IOException>(thrown.GetBaseException());
        Assert.False(started);
        Assert.Empty(Directory.GetFiles(temp.Path, "spool-namespace-*"));
    }

    [Theory]
    [InlineData("format")] [InlineData("erase")]
    public void OnlyOriginalCanonicalFormatDestinationCanJoinSiblingDisposition(string operation)
    {
        using var temp = DTempDirectory.Create("format-destination-disposition");
        var spool = Path.Combine(temp.Path, "spool"); var recovery = Path.Combine(temp.Path, "recovery");
        Directory.CreateDirectory(spool); Directory.CreateDirectory(recovery);
        var destination = NativeApfsVolumeImageManagement.DestinationWal(spool, new string('c', 32));
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.WriteAllBytes(destination, []);
        var request = NativeVolumeImageManagementTests.Request(operation) with { SpoolRoot = spool, Name = "Fresh", CaseSensitive = false,
            ImageOptions = new("2097152", "2097152", new string('c', 32), new string('d', 32), destination) };
        Assert.Throws<IOException>(() => NativeRecoveryStorage.RequireDisposition(spool, recovery, request.SiblingWals));
        NativeRecoveryStorage.RequireDisposition(request, recovery);
        Assert.Throws<InvalidDataException>(() => NativeRecoveryStorage.RequireDisposition(request with {
            ImageOptions = request.ImageOptions! with { NewContainerUuid = new string('e', 32) } }, recovery));
        var unrelated = Path.Combine(spool, "historical", "write-ahead.wal"); Directory.CreateDirectory(Path.GetDirectoryName(unrelated)!);
        File.WriteAllText(unrelated, "retained unknown evidence");
        Assert.Throws<IOException>(() => NativeRecoveryStorage.RequireDisposition(request, recovery));
        Assert.Equal("retained unknown evidence", File.ReadAllText(unrelated)); Assert.True(File.Exists(destination));
    }

    [Fact]
    public void CompleteNativeCensusUsesExactExistingLaunchIdentityAndPreservesUnknownEvidence()
    {
        using var temp = DTempDirectory.Create("production-census");
        var spool = Path.Combine(temp.Path, "spool"); var recovery = Path.Combine(temp.Path, "recovery");
        Directory.CreateDirectory(spool); Directory.CreateDirectory(recovery);
        var image = Path.Combine(temp.Path, "image.apfs"); var inventory = Inventory(image);
        var scope = VerifyScopeDerivation.TryDerive(inventory, inventory.Volumes[0]).Scope!;
        var census = NativeRecoveryStorage.BindCensus(scope, inventory, [(Volume, "101")], spool, recovery);
        var wal = Assert.Single(census);
        Assert.Equal(Path.Combine(spool, "apfs_recovery_v1_" + Identity[17..], "write-ahead.wal"), wal.Path);
        Assert.False(Directory.Exists(Path.GetDirectoryName(wal.Path)));
        Assert.Throws<InvalidDataException>(() => NativeRecoveryStorage.BindCensus(scope,
            inventory with { Volumes = [inventory.Volumes[0] with { RecoveryIdentity = null }] }, [(Volume, "101")], spool, recovery));
        Assert.Throws<InvalidDataException>(() => NativeRecoveryStorage.BindCensus(scope, inventory, [(Volume, "102")], spool, recovery));
        var legacy = Path.Combine(spool, "legacy-session"); Directory.CreateDirectory(legacy);
        var evidence = Path.Combine(legacy, "write-ahead.wal"); File.WriteAllText(evidence, "unproved retained WAL");
        Assert.Throws<IOException>(() => NativeRecoveryStorage.BindCensus(scope, inventory, [(Volume, "101")], spool, recovery));
        Assert.Equal("unproved retained WAL", File.ReadAllText(evidence));
    }

    [Theory]
    [InlineData(".vmt1")]
    [InlineData(".vif1")]
    public void EitherJournalFamilyBlocksMutationRegardlessOfImageLengthOrMetadata(string extension)
    {
        using var temp = DTempDirectory.Create("shared-management-root");
        NativeManagementJournalAdmission.RequireClearRoot(temp.Path);
        var journal = Path.Combine(temp.Path, new string('a', 64) + extension);
        File.WriteAllText(journal, "unproved accepted original file ID and offset");
        Assert.Throws<IOException>(() => NativeManagementJournalAdmission.RequireClearRoot(temp.Path));
        Assert.True(File.Exists(journal));
        Assert.Throws<IOException>(() => NativeManagementJournalAdmission.RequireClearRoot(null));
    }

    internal static DeviceInventory Inventory(string image)
    {
        var cid = ApfsTopology.BuildContainerId(Container); var vid = ApfsTopology.BuildVolumeId(Container, 101);
        var disk = "apfs-disk:image"; var store = "apfs-store:image";
        var row = new VolumeInfo(vid, image, "Main", true, SupportsNativeWrite: true, RecoveryIdentity: Identity,
            CatalogVolumeId: vid, CatalogContainerUuid: Container, CatalogVolumeObjectId: 101, CatalogVolumeUuid: Volume,
            CatalogDecision: ApfsCapabilityDecision.Writable, CatalogReasons: [], CatalogAutoMountAllowed: true);
        var topology = new ApfsTopologySnapshot([new(disk, image, null, 2097152)], [],
            [new(store, Container, "", cid, 0, 2097152, DiskId: disk)],
            [new(cid, Container, 4096, [store], [vid], false, "7", [], [], [])],
            [new(vid, Volume, "101", cid, "Main", true, ["data"], 64, null, "sensitive", "none", false, [], [], [], "7", "7")], []);
        return new(new(image, "Image", true), [row], new(1, image, [disk], topology));
    }
}
