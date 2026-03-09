namespace ApfsAccess.Core;

public sealed record WriteGateDecision(bool AllowWrite, string GateState, string? Reason);

public static class WriteGatePolicy
{
    public static WriteGateDecision EvaluateForRequest(ServiceHostOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!options.EnableNativeWrite)
        {
            return new WriteGateDecision(false, "Disabled", "Native write feature flag is disabled.");
        }

        var channelEnabled =
            string.Equals(options.WriteRolloutChannel, "Pilot", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(options.WriteRolloutChannel, "Enabled", StringComparison.OrdinalIgnoreCase);
        if (!channelEnabled)
        {
            return new WriteGateDecision(
                false,
                "RolloutBlocked",
                $"Rollout channel '{options.WriteRolloutChannel}' does not allow write mounts."
            );
        }

        return new WriteGateDecision(true, "Enabled", null);
    }

    public static WriteGateDecision EvaluateForVolume(ServiceHostOptions options, VolumeInfo volume)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(volume);

        var requestDecision = EvaluateForRequest(options);
        if (!requestDecision.AllowWrite)
        {
            return requestDecision;
        }

        var pilotChannel = string.Equals(options.WriteRolloutChannel, "Pilot", StringComparison.OrdinalIgnoreCase);
        if (pilotChannel &&
            options.NativeWritePilotVolumeAllowList is { Length: > 0 } &&
            !IsPilotAllowListed(options.NativeWritePilotVolumeAllowList, volume))
        {
            return new WriteGateDecision(
                false,
                "PilotAllowListBlocked",
                $"Volume '{volume.VolumeName}' is not in Service.NativeWritePilotVolumeAllowList."
            );
        }

        if (volume.IsEncrypted)
        {
            return new WriteGateDecision(
                false,
                "EncryptedUnsupported",
                "Encrypted APFS write support is not available in this release."
            );
        }

        var unsupportedFeatureIssues =
            volume.WriteUnsupportedFeatures is { Count: > 0 }
                ? volume.WriteUnsupportedFeatures
                : volume.WriteIncompatibilities;

        if (!options.AllowWriteOnUnsupportedFeatures &&
            unsupportedFeatureIssues is { Count: > 0 })
        {
            var reason = string.Join(" ", unsupportedFeatureIssues);
            return new WriteGateDecision(
                false,
                "VolumeIncompatibility",
                string.IsNullOrWhiteSpace(reason)
                    ? "Volume has unsupported APFS feature flags for writable mode."
                    : reason
            );
        }

        if (!options.NativeWriteAllowRawPhysicalDevices &&
            IsRawPhysicalDevice(volume.DeviceId))
        {
            return new WriteGateDecision(
                false,
                "RawPhysicalWriteBlocked",
                "Raw physical APFS write is disabled; set Service.NativeWriteAllowRawPhysicalDevices=true for pilot testing."
            );
        }

        if (IsRawPhysicalDevice(volume.DeviceId) &&
            options.NativeWriteHardwarePilotDeviceAllowList is { Length: > 0 } &&
            !IsHardwarePilotAllowListed(options.NativeWriteHardwarePilotDeviceAllowList, volume.DeviceId))
        {
            return new WriteGateDecision(
                false,
                "HardwarePilotAllowListBlocked",
                $"Device '{volume.DeviceId}' is not in Service.NativeWriteHardwarePilotDeviceAllowList."
            );
        }

        if (IsRawPhysicalDevice(volume.DeviceId) &&
            string.Equals(options.NativeWritePromotionPolicy, "ScaffoldOnly", StringComparison.OrdinalIgnoreCase))
        {
            return new WriteGateDecision(
                false,
                "PromotionPolicyBlocked",
                "Native write promotion policy is ScaffoldOnly; physical-device write is blocked until pilot validation."
            );
        }

        // Promotion evidence thresholds (crash/hardware/macOS/power-loss) are enforced by
        // the native backend using persisted validation evidence. Service-level pre-gates
        // should only enforce static capability/safety constraints and let backend runtime
        // evidence decide Pilot/Stable promotion.

        if (volume.SupportsNativeWrite)
        {
            return new WriteGateDecision(true, "Enabled", null);
        }

        if (!options.AllowWriteOnUnsupportedFeatures)
        {
            var reason = string.IsNullOrWhiteSpace(volume.WriteBlockReason)
                ? "Volume capability does not allow native write in this build."
                : volume.WriteBlockReason;
            return new WriteGateDecision(false, "VolumeCapability", reason);
        }

        return new WriteGateDecision(
            true,
            "Override",
            "Write override is enabled for an unsupported volume; use only for testing."
        );
    }

    private static bool IsPilotAllowListed(IReadOnlyList<string> allowList, VolumeInfo volume)
    {
        foreach (var entry in allowList)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                continue;
            }

            var token = entry.Trim();
            if (string.Equals(token, volume.VolumeId, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(token, volume.VolumeName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!string.IsNullOrWhiteSpace(volume.NativeVolumePath) &&
                volume.NativeVolumePath.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsHardwarePilotAllowListed(IReadOnlyList<string> allowList, string deviceId)
    {
        foreach (var entry in allowList)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                continue;
            }

            var token = entry.Trim();
            if (string.Equals(token, deviceId, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (deviceId.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsRawPhysicalDevice(string? deviceId)
        => !string.IsNullOrWhiteSpace(deviceId) &&
           (deviceId.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
            deviceId.StartsWith(@"\\?\PhysicalDrive", StringComparison.OrdinalIgnoreCase));
}
