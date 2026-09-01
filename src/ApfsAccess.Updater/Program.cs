namespace ApfsAccess.Updater;

internal static class Program
{
    [STAThread]
    private static async Task<int> Main(string[] args)
        => await RunAsync(args, CancellationToken.None);

    internal static Task<int> RunAsync(string[] args, CancellationToken token)
    {
        if (args.Length != 2 ||
            !string.Equals(args[0], "--apply", StringComparison.Ordinal))
        {
            return Task.FromResult(UpdateExitCode.InvalidArguments);
        }

        return new UpdateReplacementEngine().ApplyAsync(args[1], token);
    }
}
