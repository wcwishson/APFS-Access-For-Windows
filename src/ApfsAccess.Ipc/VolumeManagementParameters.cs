using ApfsAccess.Core;
using System.Text.Json.Serialization;

namespace ApfsAccess.Ipc;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record VolumeManagementParameters(string Kind, string? Name = null, string? QuotaBytes = null,
    string? ReserveBytes = null, bool? CaseSensitive = null, string? Token = null, string? TargetBytes = null)
{
    public static bool IsCommand(string command) => command is ApfsControlCommands.VolumeCreatePlan or
        ApfsControlCommands.VolumeDeletePlan or ApfsControlCommands.VolumeManagementApply or
        ApfsControlCommands.VolumeManagementCancel or ApfsControlCommands.VolumeManagementRecover or
        ApfsControlCommands.VolumeResizePlan or ApfsControlCommands.VolumeFormatPlan;

    public static bool IsPlan(string command) => command is ApfsControlCommands.VolumeCreatePlan or ApfsControlCommands.VolumeDeletePlan or
        ApfsControlCommands.VolumeResizePlan or ApfsControlCommands.VolumeFormatPlan;
    public static bool IsImageKind(string kind) => kind is "grow" or "shrink" or "format" or "erase";

    public static bool Valid(string command, VolumeManagementParameters? p)
    {
        if (!IsCommand(command)) return p is null;
        if (p is null || p.Kind is not ("create" or "delete" or "grow" or "shrink" or "format" or "erase")) return false;
        if (command == ApfsControlCommands.VolumeCreatePlan && p.Kind != "create" ||
            command == ApfsControlCommands.VolumeDeletePlan && p.Kind != "delete" ||
            command == ApfsControlCommands.VolumeResizePlan && p.Kind is not ("grow" or "shrink") ||
            command == ApfsControlCommands.VolumeFormatPlan && p.Kind is not ("format" or "erase")) return false;
        var planning = IsPlan(command);
        if (planning ? p.Token is not null : p.Token is not { Length: 64 } || !p.Token.All(char.IsAsciiHexDigitLower)) return false;
        if (p.Kind is "grow" or "shrink")
            return p.Name is null && p.CaseSensitive is null && p.QuotaBytes is null && p.ReserveBytes is null &&
                VolumeTopologyProfile.Number(p.TargetBytes, false) && ulong.Parse(p.TargetBytes!, System.Globalization.CultureInfo.InvariantCulture) is >= 1048576 and <= VolumeTopologyProfile.MaximumStreamedImageBytes &&
                ulong.Parse(p.TargetBytes!, System.Globalization.CultureInfo.InvariantCulture) % 4096 == 0;
        if (p.Kind is "format" or "erase")
            return p.TargetBytes is null && p.QuotaBytes is null && p.ReserveBytes is null && p.CaseSensitive is not null &&
                !string.IsNullOrWhiteSpace(p.Name) && p.Name.Length <= 255 && !p.Name.Any(c => c is '\0' or '\r' or '\n');
        if (p.TargetBytes is not null) return false;
        return p.Kind == "delete"
            ? p.Name is null && p.QuotaBytes is null && p.ReserveBytes is null && p.CaseSensitive is null
            : !string.IsNullOrWhiteSpace(p.Name) && p.Name.Length <= 255 && !p.Name.Any(c => c is '\0' or '\r' or '\n') &&
                VolumeTopologyProfile.Number(p.QuotaBytes) && VolumeTopologyProfile.Number(p.ReserveBytes) && p.CaseSensitive is not null;
    }
}
