using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class BackupImageMountCommandTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "backup-cli-" + Guid.NewGuid().ToString("N"));
    public BackupImageMountCommandTests() { Directory.CreateDirectory(directory); File.WriteAllBytes(Path.Combine(directory, "image"), new byte[4096]); }
    public void Dispose() => Directory.Delete(directory, true);
    private string[] Args => ["mount", "--image", Path.Combine(directory, "image"), "--container-id", "apfs-container:" + new string('a', 32),
        "--volume-oid", "101", "--journal-dir", Path.Combine(directory, "journal"), "--session-dir", Path.Combine(directory, "session")];
    [Fact] public void NestedPersistentEvidenceAndTransientSessionRefuse()
    {
        var args = Args; args[^1] = Path.Combine(directory, "journal", "session"); Assert.Throws<ArgumentException>(() => BackupImageMountCommand.Parse(args));
    }
    [Theory]
    [InlineData("--allow-raw-physical-write")]
    [InlineData("--container-manifest")]
    [InlineData("--enable-image-snapshots")]
    [InlineData("--journal-dir")]
    public void ForeignModeOrDuplicateAuthorityRefuses(string flag)
        => Assert.Throws<ArgumentException>(() => BackupImageMountCommand.Parse([..Args, flag, "value"]));
}
