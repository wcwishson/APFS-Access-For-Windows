using System.Text.Json;
using System.Text.RegularExpressions;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;

ProbeSettings settings;
try
{
    settings = ProbeCommandLine.Parse(args);
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    ProbeCommandLine.WriteUsage(Console.Error);
    return 1;
}

if (settings.ShowHelp)
{
    ProbeCommandLine.WriteUsage(Console.Out);
    return 0;
}

try
{
    if (settings.Command == ProbeCommand.CreateTestImage)
    {
        var image = SyntheticApfsTestImage.Create(settings.ImagePath!, settings.ImageSizeMiB);
        if (settings.AsJson)
        {
            var json = JsonSerializer.Serialize(image, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = true,
            });
            Console.WriteLine(json);
        }
        else
        {
            Console.WriteLine($"Created APFS Access synthetic test image: {image.ImagePath}");
            Console.WriteLine($"  Size: {image.SizeMiB} MiB");
            Console.WriteLine($"  Block size: {image.BlockSize}");
            Console.WriteLine($"  Total blocks: {image.TotalBlocks}");
            Console.WriteLine("  Compatibility: APFS Access image-backed validation only; not macOS-compatible formatter output yet.");
        }

        return 0;
    }

    var options = new ServiceHostOptions
    {
        BackendMode = "Native",
        NativeFsHostPath = settings.NativeFsHostPath,
        NativeDeviceCandidates = string.IsNullOrWhiteSpace(settings.DeviceId)
            ? []
            : [settings.DeviceId],
        NativeAutoDiscoverPhysicalDrives = string.IsNullOrWhiteSpace(settings.DeviceId),
        NativeMaxPhysicalDriveIndex = settings.MaxPhysicalDriveIndex,
    };

    using var backend = new NativeApfsBackend(options);
    var devices = await backend.ProbeDevicesAsync(CancellationToken.None).ConfigureAwait(false);
    var probedDevices = new List<ProbedDevice>(devices.Count);
    foreach (var device in devices.OrderBy(x => x.DeviceId, StringComparer.OrdinalIgnoreCase))
    {
        var volumes = await backend.ProbeVolumesAsync(device.DeviceId, CancellationToken.None).ConfigureAwait(false);
        var probedVolumes = volumes
            .OrderBy(x => x.VolumeName, StringComparer.OrdinalIgnoreCase)
            .Select(volume => new ProbedVolume(
                VolumeId: volume.VolumeId,
                DeviceId: volume.DeviceId,
                VolumeName: volume.VolumeName,
                ProfileId: BuildValidationEvidenceProfileId(volume.DeviceId, volume.VolumeName),
                SupportsReadWrite: volume.SupportsReadWrite,
                SupportsNativeWrite: volume.SupportsNativeWrite,
                IsEncrypted: volume.IsEncrypted,
                SupportsExplorerMount: volume.SupportsExplorerMount,
                NativeWriteReadiness: volume.NativeWriteReadiness.ToString(),
                WriteBlockReason: volume.WriteBlockReason,
                WriteIncompatibilities: volume.WriteIncompatibilities ?? Array.Empty<string>(),
                WriteUnsupportedFeatures: volume.WriteUnsupportedFeatures ?? Array.Empty<string>()))
            .ToArray();

        probedDevices.Add(new ProbedDevice(
            DeviceId: device.DeviceId,
            DisplayName: device.DisplayName,
            IsConnected: device.IsConnected,
            Volumes: probedVolumes));
    }

    var payload = new ProbePayload(
        GeneratedUtc: DateTime.UtcNow,
        RequestedDeviceId: settings.DeviceId,
        MaxPhysicalDriveIndex: settings.MaxPhysicalDriveIndex,
        Devices: probedDevices.ToArray());

    if (settings.AsJson)
    {
        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
        });
        Console.WriteLine(json);
    }
    else
    {
        foreach (var device in payload.Devices)
        {
            Console.WriteLine($"{device.DeviceId} | {device.DisplayName} | Connected={device.IsConnected}");
            foreach (var volume in device.Volumes)
            {
                Console.WriteLine($"  - {volume.VolumeName} | {volume.VolumeId} | {volume.ProfileId}");
            }
        }
    }

    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

static string BuildValidationEvidenceProfileId(string deviceId, string volumeName)
{
    var scope = IsRawPhysicalDevice(deviceId)
        ? "raw"
        : IsFixtureImagePath(deviceId)
            ? "image"
            : "device";
    return $"{scope}::{NormalizeValidationEvidenceProfileToken(deviceId)}::{NormalizeValidationEvidenceProfileToken(volumeName)}";
}

static string NormalizeValidationEvidenceProfileToken(string? value)
{
    var normalized = Regex.Replace((value ?? string.Empty).Trim().ToLowerInvariant(), @"\s+", " ");
    return string.IsNullOrWhiteSpace(normalized)
        ? "unknown"
        : normalized;
}

static bool IsRawPhysicalDevice(string? deviceId)
    => !string.IsNullOrWhiteSpace(deviceId) &&
       (deviceId.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
        deviceId.StartsWith(@"\\?\PhysicalDrive", StringComparison.OrdinalIgnoreCase));

static bool IsFixtureImagePath(string? devicePath)
{
    if (string.IsNullOrWhiteSpace(devicePath) || IsRawPhysicalDevice(devicePath))
    {
        return false;
    }

    var normalized = devicePath.Trim().ToLowerInvariant();
    if (normalized.EndsWith(".apfs.img", StringComparison.Ordinal) ||
        normalized.EndsWith(".img", StringComparison.Ordinal) ||
        normalized.EndsWith(".apfs.fixture", StringComparison.Ordinal))
    {
        return true;
    }

    var extension = Path.GetExtension(normalized);
    return string.Equals(extension, ".img", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(extension, ".apfs", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(extension, ".fixture", StringComparison.OrdinalIgnoreCase);
}

internal sealed record ProbePayload(
    DateTime GeneratedUtc,
    string? RequestedDeviceId,
    int MaxPhysicalDriveIndex,
    IReadOnlyList<ProbedDevice> Devices);

internal sealed record ProbedDevice(
    string DeviceId,
    string DisplayName,
    bool IsConnected,
    IReadOnlyList<ProbedVolume> Volumes);

internal sealed record ProbedVolume(
    string VolumeId,
    string DeviceId,
    string VolumeName,
    string ProfileId,
    bool SupportsReadWrite,
    bool SupportsNativeWrite,
    bool IsEncrypted,
    bool SupportsExplorerMount,
    string NativeWriteReadiness,
    string? WriteBlockReason,
    IReadOnlyList<string> WriteIncompatibilities,
    IReadOnlyList<string> WriteUnsupportedFeatures);

internal sealed record ProbeSettings(
    ProbeCommand Command,
    string? DeviceId,
    int MaxPhysicalDriveIndex,
    string? NativeFsHostPath,
    bool AsJson,
    bool ShowHelp,
    string? ImagePath,
    int ImageSizeMiB);

internal enum ProbeCommand
{
    Probe,
    CreateTestImage,
}

internal static class ProbeCommandLine
{
    public static ProbeSettings Parse(string[] args)
    {
        var command = ProbeCommand.Probe;
        string? deviceId = null;
        string? nativeFsHostPath = null;
        string? imagePath = null;
        var maxPhysicalDriveIndex = 8;
        var imageSizeMiB = SyntheticApfsTestImage.DefaultSizeMiB;
        var asJson = false;
        var showHelp = false;

        var startIndex = 0;
        if (args.Length > 0 && !args[0].StartsWith("-", StringComparison.Ordinal))
        {
            switch (args[0].Trim().ToLowerInvariant())
            {
                case "probe":
                    command = ProbeCommand.Probe;
                    startIndex = 1;
                    break;
                case "create-test-image":
                    command = ProbeCommand.CreateTestImage;
                    startIndex = 1;
                    break;
                default:
                    throw new ArgumentException($"Unknown command: {args[0]}");
            }
        }

        for (var index = startIndex; index < args.Length; index++)
        {
            var arg = args[index];
            switch (arg)
            {
                case "--device":
                    deviceId = RequireValue(args, ref index, arg);
                    break;
                case "--max-physical-drive-index":
                {
                    var rawValue = RequireValue(args, ref index, arg);
                    if (!int.TryParse(rawValue, out maxPhysicalDriveIndex))
                    {
                        throw new ArgumentException($"Invalid integer for {arg}: {rawValue}");
                    }
                    maxPhysicalDriveIndex = Math.Clamp(maxPhysicalDriveIndex, 0, 128);
                    break;
                }
                case "--native-fs-host-path":
                    nativeFsHostPath = RequireValue(args, ref index, arg);
                    break;
                case "--path":
                case "--image":
                    imagePath = RequireValue(args, ref index, arg);
                    break;
                case "--size-mib":
                {
                    var rawValue = RequireValue(args, ref index, arg);
                    if (!int.TryParse(rawValue, out imageSizeMiB))
                    {
                        throw new ArgumentException($"Invalid integer for {arg}: {rawValue}");
                    }
                    break;
                }
                case "--as-json":
                    asJson = true;
                    break;
                case "-h":
                case "--help":
                case "/?":
                    showHelp = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown argument: {arg}");
            }
        }

        if (command == ProbeCommand.CreateTestImage && !showHelp && string.IsNullOrWhiteSpace(imagePath))
        {
            throw new ArgumentException("Missing required --path for create-test-image.");
        }

        return new ProbeSettings(
            command,
            deviceId,
            maxPhysicalDriveIndex,
            nativeFsHostPath,
            asJson,
            showHelp,
            imagePath,
            imageSizeMiB);
    }

    public static void WriteUsage(TextWriter writer)
    {
        writer.WriteLine("Usage:");
        writer.WriteLine("  ApfsAccess.NativeProbe probe [--device <id>] [--max-physical-drive-index <n>] [--native-fs-host-path <path>] [--as-json]");
        writer.WriteLine("  ApfsAccess.NativeProbe create-test-image --path <file.apfs.img> [--size-mib <4-1024>] [--as-json]");
        writer.WriteLine();
        writer.WriteLine("The create-test-image command creates a new normal file only and refuses to overwrite existing files.");
    }

    private static string RequireValue(string[] args, ref int index, string option)
    {
        if (index + 1 >= args.Length)
        {
            throw new ArgumentException($"Missing value for {option}");
        }

        index++;
        return args[index];
    }
}
