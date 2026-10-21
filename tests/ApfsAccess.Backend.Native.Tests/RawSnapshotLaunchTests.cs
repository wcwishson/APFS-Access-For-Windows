using System.Diagnostics;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class RawSnapshotLaunchTests
{
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Device = @"\\.\PhysicalDrive2";

    [Fact]
    public void RawSnapshotsDefaultOffAndRoundTripIndependently()
    {
        var defaults = new ServiceHostOptions();
        Assert.False(defaults.EnableRawSnapshots);
        Assert.Null(defaults.RawSnapshotHardwareQualification);
        var options = JsonSerializer.Deserialize<ServiceHostOptions>("{\"EnableRawSnapshots\":true}")!;
        Assert.True(options.EnableRawSnapshots);
        Assert.False(options.EnableImageSnapshots);
        Assert.False(options.EnableRetainedPhysicalSnapshotInventory);
        Assert.False(options.NativeWriteAllowRawPhysicalDevices);
        Assert.Null(options.RawSnapshotHardwareQualification);
        Assert.True(JsonSerializer.Deserialize<ServiceHostOptions>(JsonSerializer.Serialize(options))!.EnableRawSnapshots);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(2u)]
    [InlineData(3u)]
    public void ExplicitSchemesRoundTripAndEmitExactlyOneIdentitySelector(uint? vpdType)
    {
        var (options, manifest, volumes) = Profile();
        if (vpdType is not null)
        {
            options.RawSnapshotHardwareQualification!.Scheme = RawSnapshotHardwareQualificationScheme.QualifiedDeviceVpd;
            options.RawSnapshotHardwareQualification.QualifiedSerial = null;
            options.RawSnapshotHardwareQualification.QualifiedVpdType = vpdType;
        }
        options = JsonSerializer.Deserialize<ServiceHostOptions>(JsonSerializer.Serialize(options))!;
        var launch = Launch(options, manifest);
        Assert.True(NativeRawSnapshotLaunch.ShouldEnable(options, manifest, volumes, true));
        Assert.True(NativeRawSnapshotLaunch.AppendArgument(launch, options, manifest, volumes, true, out var retained));
        Assert.True(NativeRawSnapshotLaunch.QualificationMatches(retained, options.RawSnapshotHardwareQualification));
        Assert.Equal("7", Value("--raw-snapshot-qualified-bus"));
        Assert.Equal("Example Devices", Value("--raw-snapshot-qualified-vendor"));
        Assert.Equal("Snapshot Test Unit", Value("--raw-snapshot-qualified-product"));
        Assert.Equal(vpdType is null, launch.ArgumentList.Contains("--raw-snapshot-qualified-serial"));
        Assert.Equal(vpdType is not null, launch.ArgumentList.Contains("--raw-snapshot-qualified-vpd-type"));
        Assert.Equal(4, launch.ArgumentList.Count(arg => arg.StartsWith("--raw-snapshot-qualified-", StringComparison.Ordinal)));
        Assert.Equal(vpdType?.ToString() ?? "TEST-UNIT-A7B9", Value(vpdType is null ?
            "--raw-snapshot-qualified-serial" : "--raw-snapshot-qualified-vpd-type"));
        string Value(string name) => launch.ArgumentList[launch.ArgumentList.IndexOf(name) + 1];
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("missing-scheme")]
    [InlineData("unknown-scheme")]
    [InlineData("missing-bus")]
    [InlineData("missing-vendor")]
    [InlineData("missing-product")]
    [InlineData("missing-serial")]
    [InlineData("empty-serial")]
    [InlineData("short-serial")]
    [InlineData("generic-vendor")]
    [InlineData("generic-product")]
    [InlineData("generic-serial")]
    [InlineData("punctuated-generic-serial")]
    [InlineData("repeated-serial")]
    [InlineData("nonascii-vendor")]
    [InlineData("nonascii-product")]
    [InlineData("nonascii-serial")]
    [InlineData("control-serial")]
    [InlineData("padded-vendor")]
    [InlineData("padded-serial")]
    [InlineData("oversized-serial")]
    [InlineData("serial-with-vpd")]
    [InlineData("serial-with-vpd-zero")]
    [InlineData("vpd-with-serial")]
    [InlineData("vpd-with-empty-serial")]
    [InlineData("vpd-without-type")]
    public void MissingMixedOrGenericQualificationAddsNoHardwareOrEnableArguments(string refusal)
    {
        var (options, manifest, volumes) = Profile();
        var qualification = options.RawSnapshotHardwareQualification!;
        switch (refusal)
        {
            case "missing": options.RawSnapshotHardwareQualification = null; break;
            case "missing-scheme": qualification.Scheme = RawSnapshotHardwareQualificationScheme.Unavailable; break;
            case "unknown-scheme": qualification.Scheme = (RawSnapshotHardwareQualificationScheme)99; break;
            case "missing-bus": qualification.BusType = null; break;
            case "missing-vendor": qualification.Vendor = null; break;
            case "missing-product": qualification.Product = null; break;
            case "missing-serial": qualification.QualifiedSerial = null; break;
            case "empty-serial": qualification.QualifiedSerial = ""; break;
            case "short-serial": qualification.QualifiedSerial = "A7B"; break;
            case "generic-vendor": qualification.Vendor = "Generic"; break;
            case "generic-product": qualification.Product = "USB"; break;
            case "generic-serial": qualification.QualifiedSerial = "0123456789"; break;
            case "punctuated-generic-serial": qualification.QualifiedSerial = "Serial_Number"; break;
            case "repeated-serial": qualification.QualifiedSerial = "AAAAAA"; break;
            case "nonascii-vendor": qualification.Vendor = "Vend\u00e9r"; break;
            case "nonascii-product": qualification.Product = "Unit\u00e9"; break;
            case "nonascii-serial": qualification.QualifiedSerial = "Unit-\u00e9-1234"; break;
            case "control-serial": qualification.QualifiedSerial = "Unit-1234\n"; break;
            case "padded-vendor": qualification.Vendor = " Example Devices"; break;
            case "padded-serial": qualification.QualifiedSerial = "TEST-UNIT-A7B9 "; break;
            case "oversized-serial": qualification.QualifiedSerial = new string('A', 128) + "B"; break;
            case "serial-with-vpd": qualification.QualifiedVpdType = 2; break;
            case "serial-with-vpd-zero": qualification.QualifiedVpdType = 0; break;
            case "vpd-with-serial": qualification.Scheme = RawSnapshotHardwareQualificationScheme.QualifiedDeviceVpd; qualification.QualifiedVpdType = 2; break;
            case "vpd-with-empty-serial": qualification.Scheme = RawSnapshotHardwareQualificationScheme.QualifiedDeviceVpd; qualification.QualifiedVpdType = 2; qualification.QualifiedSerial = ""; break;
            case "vpd-without-type": qualification.Scheme = RawSnapshotHardwareQualificationScheme.QualifiedDeviceVpd; qualification.QualifiedSerial = null; break;
        }
        var launch = Launch(options, manifest);
        var original = launch.ArgumentList.ToArray();
        Assert.False(NativeRawSnapshotLaunch.ShouldEnable(options, manifest, volumes, true));
        Assert.False(NativeRawSnapshotLaunch.AppendArgument(launch, options, manifest, volumes, true, out var retained));
        Assert.Null(retained);
        Assert.Equal(original, launch.ArgumentList.ToArray());
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(14u)]
    [InlineData(15u)]
    [InlineData(16u)]
    [InlineData(21u)]
    [InlineData(127u)]
    [InlineData(uint.MaxValue)]
    public void UnknownOrVirtualBusRefusesQualification(uint bus)
    {
        var (options, manifest, volumes) = Profile();
        options.RawSnapshotHardwareQualification!.BusType = bus;
        Assert.False(NativeRawSnapshotLaunch.ShouldEnable(options, manifest, volumes, true));
        Assert.False(NativeRawSnapshotLaunch.AppendArgument(Launch(options, manifest), options, manifest, volumes, true));
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(4u)]
    [InlineData(8u)]
    [InlineData(uint.MaxValue)]
    public void OtherVpdTypesRefuseQualification(uint vpdType)
    {
        var (options, manifest, volumes) = Profile();
        options.RawSnapshotHardwareQualification!.Scheme = RawSnapshotHardwareQualificationScheme.QualifiedDeviceVpd;
        options.RawSnapshotHardwareQualification.QualifiedSerial = null;
        options.RawSnapshotHardwareQualification.QualifiedVpdType = vpdType;
        Assert.False(NativeRawSnapshotLaunch.ShouldEnable(options, manifest, volumes, true));
        Assert.False(NativeRawSnapshotLaunch.AppendArgument(Launch(options, manifest), options, manifest, volumes, true));
    }

    [Fact]
    public void ArgumentListPreservesAsciiSpacesAndQuotesAndSnapshotDoesNotAliasOptions()
    {
        var (options, manifest, volumes) = Profile();
        options.RawSnapshotHardwareQualification!.Vendor = "Example \"Devices\"";
        options.RawSnapshotHardwareQualification.Product = @"Snapshot Test\Unit";
        var launch = Launch(options, manifest);
        Assert.True(NativeRawSnapshotLaunch.AppendArgument(launch, options, manifest, volumes, true, out var retained));
        Assert.Equal("Example \"Devices\"", launch.ArgumentList[launch.ArgumentList.IndexOf("--raw-snapshot-qualified-vendor") + 1]);
        Assert.Equal(@"Snapshot Test\Unit", launch.ArgumentList[launch.ArgumentList.IndexOf("--raw-snapshot-qualified-product") + 1]);
        Assert.Empty(launch.Arguments);
        options.RawSnapshotHardwareQualification.QualifiedSerial = "TEST-UNIT-C8D2";
        Assert.Equal("TEST-UNIT-A7B9", retained!.QualifiedSerial);
        Assert.False(NativeRawSnapshotLaunch.QualificationMatches(retained, options.RawSnapshotHardwareQualification));
        Assert.Equal("TEST-UNIT-A7B9", launch.ArgumentList[launch.ArgumentList.IndexOf("--raw-snapshot-qualified-serial") + 1]);
    }

    [Theory]
    [InlineData("--raw-snapshot-qualified-serial")]
    [InlineData("--raw-snapshot-qualified-vpd-type")]
    [InlineData("--enable-raw-snapshots")]
    public void PreexistingQualificationOrEnableArgumentsRefuseWithoutPartialAppend(string duplicate)
    {
        var (options, manifest, volumes) = Profile();
        var launch = Launch(options, manifest);
        launch.ArgumentList.Add(duplicate);
        var original = launch.ArgumentList.ToArray();
        Assert.False(NativeRawSnapshotLaunch.AppendArgument(launch, options, manifest, volumes, true));
        Assert.Equal(original, launch.ArgumentList.ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CompleteRawOwnerGetsRuntimeFlagWithOrWithoutInventory(bool inventory)
    {
        var (options, manifest, volumes) = Profile();
        options.EnableRetainedPhysicalSnapshotInventory = inventory;
        var launch = Launch(options, manifest);
        if (NativePhysicalSnapshotInventoryLaunch.ShouldEnable(options, manifest, volumes[0], true))
            launch.ArgumentList.Add("--enable-retained-physical-snapshot-inventory");
        Assert.True(NativeRawSnapshotLaunch.AppendArgument(launch, options, manifest, volumes, true));
        Assert.Contains("--enable-raw-snapshots", launch.ArgumentList);
        Assert.Equal(inventory, launch.ArgumentList.Contains("--enable-retained-physical-snapshot-inventory"));
        Assert.DoesNotContain("--enable-image-snapshots", launch.ArgumentList);
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("native-write-disabled")]
    [InlineData("raw-admission-disabled")]
    [InlineData("scaffold")]
    [InlineData("overlay")]
    [InlineData("readonly-owner")]
    [InlineData("image")]
    [InlineData("physical-prefix-only")]
    [InlineData("manifest-missing")]
    [InlineData("checksum")]
    [InlineData("empty")]
    [InlineData("missing-peer")]
    [InlineData("extra-peer")]
    [InlineData("readonly-peer")]
    [InlineData("encrypted-peer")]
    [InlineData("fusion-peer")]
    [InlineData("catalog-refused-peer")]
    [InlineData("source-peer")]
    [InlineData("container-peer")]
    [InlineData("identity-peer")]
    [InlineData("missing-identity")]
    [InlineData("duplicate-identity")]
    [InlineData("duplicate-oid")]
    public void IncompleteOrMixedProfileNeverAddsRuntimeFlag(string refusal)
    {
        var (options, manifest, volumes) = Profile();
        var writeCapable = refusal != "readonly-owner";
        switch (refusal)
        {
            case "disabled": options.EnableRawSnapshots = false; break;
            case "native-write-disabled": options.EnableNativeWrite = false; break;
            case "raw-admission-disabled": options.NativeWriteAllowRawPhysicalDevices = false; break;
            case "scaffold": options.NativeWriteRequireCanonicalCommit = false; break;
            case "overlay": options.WriteBackendMode = "Overlay"; break;
            case "image": manifest = manifest with { Device = @"D:\image.apfs" }; break;
            case "physical-prefix-only": manifest = manifest with { Device = @"\\.\PhysicalDrive2-extra" }; break;
            case "manifest-missing": manifest = manifest with { ManifestPath = "" }; break;
            case "checksum": manifest = manifest with { ManifestSha256 = new string('0', 64) }; break;
            case "empty": manifest = manifest with { Volumes = [] }; volumes = []; break;
            case "missing-peer": volumes = [volumes[0]]; break;
            case "extra-peer": volumes = [.. volumes, volumes[0]]; break;
            case "readonly-peer": manifest = manifest with { Volumes = [manifest.Volumes[0], manifest.Volumes[1] with { RequestedWrite = false }] }; break;
            case "encrypted-peer": volumes[1] = volumes[1] with { IsEncrypted = true }; break;
            case "fusion-peer": volumes[1] = volumes[1] with { WriteUnsupportedFeatures = ["FusionBacked"] }; break;
            case "catalog-refused-peer": volumes[1] = volumes[1] with { CatalogDecision = ApfsCapabilityDecision.Readable }; break;
            case "source-peer": volumes[1] = volumes[1] with { DeviceId = @"\\.\PhysicalDrive3" }; break;
            case "container-peer": volumes[1] = volumes[1] with { CatalogContainerUuid = new string('b', 32) }; break;
            case "identity-peer": volumes[1] = volumes[1] with { RecoveryIdentity = "replacement" }; break;
            case "missing-identity": manifest = manifest with { Volumes = [manifest.Volumes[0], manifest.Volumes[1] with { RecoveryIdentity = "" }] }; break;
            case "duplicate-identity": manifest = manifest with { Volumes = [manifest.Volumes[0], manifest.Volumes[1] with { RecoveryIdentity = manifest.Volumes[0].RecoveryIdentity }] }; break;
            case "duplicate-oid": manifest = manifest with { Volumes = [manifest.Volumes[0], manifest.Volumes[0]] }; break;
        }
        if (refusal != "checksum") manifest = Seal(manifest);
        var launch = Launch(options, manifest);
        Assert.False(NativeRawSnapshotLaunch.AppendArgument(launch, options, manifest, volumes, writeCapable));
        Assert.DoesNotContain("--enable-raw-snapshots", launch.ArgumentList);
    }

    [Theory]
    [InlineData("--readwrite")]
    [InlineData("--allow-raw-physical-write")]
    [InlineData("--container-manifest")]
    [InlineData("--container-manifest-sha256")]
    [InlineData("--write-backend")]
    [InlineData("--write-require-canonical-commit")]
    public void LaunchArgumentsMustCarryTheAdmittedContract(string missing)
    {
        var (options, manifest, volumes) = Profile();
        var launch = Launch(options, manifest);
        launch.ArgumentList.Remove(missing);
        Assert.False(NativeRawSnapshotLaunch.AppendArgument(launch, options, manifest, volumes, true));
        Assert.DoesNotContain("--enable-raw-snapshots", launch.ArgumentList);
    }

    [Theory]
    [InlineData("--readonly")]
    [InlineData("--enable-image-snapshots")]
    public void ConflictingLaunchModesRefuseRuntimeFlag(string conflicting)
    {
        var (options, manifest, volumes) = Profile();
        var launch = Launch(options, manifest);
        launch.ArgumentList.Add(conflicting);
        Assert.False(NativeRawSnapshotLaunch.AppendArgument(launch, options, manifest, volumes, true));
    }

    [Fact]
    public void ImageSnapshotsKeepTheirExistingLaunchProfileWhenRawOptionIsEnabled()
    {
        var (options, manifest, volumes) = Profile();
        options.EnableImageSnapshots = true;
        options.NativeWriteAllowRawPhysicalDevices = false;
        volumes = volumes.Select(volume => volume with { DeviceId = @"D:\image.apfs" }).ToArray();
        manifest = Seal(manifest with { Device = volumes[0].DeviceId, DeviceOffsetBytes = 0 });
        Assert.True(NativeImageSnapshotLaunch.ShouldEnable(options, manifest, volumes[0], true));
        Assert.False(NativeRawSnapshotLaunch.ShouldEnable(options, manifest, volumes, true));
    }

    private static (ServiceHostOptions Options, WrittenContainerManifest Manifest, VolumeInfo[] Volumes) Profile()
    {
        var options = new ServiceHostOptions { EnableRawSnapshots = true, EnableNativeWrite = true,
            NativeWriteAllowRawPhysicalDevices = true, WriteBackendMode = "Native",
            RawSnapshotHardwareQualification = TestQualification() };
        var volumes = new[] { 101UL, 102UL }.Select(oid => new VolumeInfo($"apfs-vol:{Container}:{oid}", Device,
            $"Volume-{oid}", true, RecoveryIdentity: $"rec-{oid}", CatalogContainerUuid: Container,
            CatalogVolumeObjectId: oid)).ToArray();
        var manifest = Seal(new WrittenContainerManifest(@"D:\ApfsAccessScratch\raw.container-manifest.json", "", Container,
            Device, 8192, [new(101, Container, "Main", "R:\\", true, "rec-101"),
                new(102, Container, "Peer", "S:\\", true, "rec-102")]));
        return (options, manifest, volumes);
    }

    internal static RawSnapshotHardwareQualification TestQualification() => new()
    {
        Scheme = RawSnapshotHardwareQualificationScheme.QualifiedSerialTuple, BusType = 7,
        Vendor = "Example Devices", Product = "Snapshot Test Unit", QualifiedSerial = "TEST-UNIT-A7B9",
    };

    private static WrittenContainerManifest Seal(WrittenContainerManifest manifest) => manifest with
    {
        ManifestSha256 = ContainerManifestWriter.ComputeManifestSha256(manifest.ContainerUuid, manifest.Device,
            manifest.DeviceOffsetBytes, manifest.Volumes)
    };

    private static ProcessStartInfo Launch(ServiceHostOptions options, WrittenContainerManifest manifest)
    {
        var launch = new ProcessStartInfo();
        foreach (var arg in new[] { "--container-manifest", manifest.ManifestPath, "--container-manifest-sha256",
            manifest.ManifestSha256, "--readwrite", "--allow-raw-physical-write", "--write-backend", options.WriteBackendMode,
            "--write-require-canonical-commit", "true" }) launch.ArgumentList.Add(arg);
        return launch;
    }
}
