using System.Globalization;
using ApfsAccess.Core;

namespace ApfsAccess.Service;

public sealed partial class AgentControlCommandExecutor
{
    internal static string KeyManagementFailureDiagnostic(ImageKeyManagementAction action, Exception failure)
    {
        const string message = "Key management did not finish. Refresh the image and inspect its recovery state.";
        if (action != ImageKeyManagementAction.Observe || failure is not IOException ||
            failure.Data["NativeExitCode"] is not int exit || exit == 0)
            return message;

        var diagnostic = message + " NativeExitCode=" + exit.ToString(CultureInfo.InvariantCulture) + ".";
        // The backend accepts this field only from the exact retired Observe owner.
        if (failure.Data["NativeObservationRefusal"] is string { Length: > 0 and <= 4096 } refusal &&
            !refusal.Any(char.IsControl))
            diagnostic += " NativeObservationRefusal=" + refusal;
        return diagnostic;
    }
}
