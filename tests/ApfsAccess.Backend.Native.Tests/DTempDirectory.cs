namespace ApfsAccess.Backend.Native.Tests;

// D:-rooted temp directories. The machine %TEMP% lives on C: while this task
// is D:-only, and repo-rooted temp dirs would pollute the observer-path
// ancestor walk, so all new Task-1 tests stage files here.
internal sealed class DTempDirectory : IDisposable
{
    private DTempDirectory(string path) => Path = path;

    public string Path { get; }

    public static DTempDirectory Create(string? prefix = null)
    {
        var root = System.IO.Path.Combine("D:\\Temp", "ApfsAccessTests");
        Directory.CreateDirectory(root);
        var path = System.IO.Path.Combine(
            root, (prefix ?? "case") + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return new DTempDirectory(path);
    }

    public void Dispose()
    {
        if (Directory.Exists(Path))
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}
