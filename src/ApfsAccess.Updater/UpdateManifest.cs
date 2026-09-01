namespace ApfsAccess.Updater;

public sealed record UpdateManifest(
    int OldTrayProcessId,
    long OldTrayStartTimeUtcTicks,
    string LauncherPath,
    string ReadyPath,
    string BackupPath,
    string ReceiptPath,
    string CurrentSha256,
    string ExpectedSha256,
    string ExpectedVersion,
    string Token);
