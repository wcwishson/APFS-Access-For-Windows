using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

namespace ApfsAccess.Tray;

internal static class UpdateReceiptPublisher
{
    internal const string TokenEnvironmentKey = "APFSACCESS_UPDATE_TOKEN";
    internal const string VersionEnvironmentKey = "APFSACCESS_UPDATE_EXPECTED_VERSION";
    internal const string ReceiptPathEnvironmentKey = "APFSACCESS_UPDATE_RECEIPT_PATH";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    internal static bool TryWriteCurrentProcessPhase(string phase)
    {
        var token = Environment.GetEnvironmentVariable(TokenEnvironmentKey);
        var expectedVersion = Environment.GetEnvironmentVariable(VersionEnvironmentKey);
        var receiptPath = Environment.GetEnvironmentVariable(ReceiptPathEnvironmentKey);
        if (!IsToken(token) ||
            !IsExpectedVersion(expectedVersion) ||
            string.IsNullOrWhiteSpace(receiptPath) ||
            !Path.IsPathFullyQualified(receiptPath) ||
            (phase != "launched" && phase != "ready"))
        {
            return false;
        }

        try
        {
            var fullReceiptPath = Path.GetFullPath(receiptPath);
            using var process = Process.GetCurrentProcess();
            var receipt = new UpdateReceipt(
                token!,
                expectedVersion!,
                phase,
                process.Id,
                process.StartTime.ToUniversalTime().Ticks);
            var temporaryPath = fullReceiptPath + $".{Guid.NewGuid():N}.tmp";
            try
            {
                File.WriteAllText(temporaryPath, JsonSerializer.Serialize(receipt, JsonOptions));
                File.Move(temporaryPath, fullReceiptPath, overwrite: true);
            }
            finally
            {
                File.Delete(temporaryPath);
            }

            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    private static bool IsToken(string? value)
        => value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static bool IsExpectedVersion(string? value)
    {
        var current = Assembly.GetExecutingAssembly().GetName().Version;
        return current is not null &&
               string.Equals(value, current.ToString(3), StringComparison.Ordinal);
    }

    private sealed record UpdateReceipt(
        string Token,
        string ExpectedVersion,
        string Phase,
        int ProcessId,
        long ProcessStartTimeUtcTicks);
}
