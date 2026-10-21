using ApfsAccess.Cli;
using System.Globalization;

if (args.Length != 2 || args[0] != "--frame-child" ||
    !int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out var count) ||
    count is not (1 or 2)) return 2;

using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
try
{
    using var input = Console.OpenStandardInput();
    using var credentials = await SupervisedCredentialSet.ReceiveAsync(input, count, timeout.Token);
    return credentials.Count == count ? 0 : 5;
}
catch (Exception ex) when (ex is IOException or OperationCanceledException)
{
    return 5;
}
