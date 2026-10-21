namespace ApfsAccess.Ipc;

public static class FusionControlEndpoint
{
    private const string InstanceSeparator = ".fusion.";

    public static string ForPrivateInstance(Guid instanceId)
    {
        if (instanceId == Guid.Empty)
            throw new ArgumentException("A private Fusion instance identity is required.", nameof(instanceId));
        return ApfsPipeConstants.PipeName + InstanceSeparator + instanceId.ToString("N");
    }

    public static bool IsPrivateInstance(string pipeName)
    {
        var prefix = ApfsPipeConstants.PipeName + InstanceSeparator;
        return pipeName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            && pipeName.Length == prefix.Length + 32
            && Guid.TryParseExact(pipeName.AsSpan(prefix.Length), "N", out var id)
            && id != Guid.Empty;
    }
}
