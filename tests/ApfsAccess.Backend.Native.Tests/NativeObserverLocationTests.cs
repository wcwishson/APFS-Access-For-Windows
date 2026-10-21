using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

[CollectionDefinition("ObserverPathEnv", DisableParallelization = true)]
public sealed class ObserverPathEnvCollection
{
}

public sealed class NativeObserverLocationTests
{
    [Fact]
    public void ProductionBuildAndPublish_IncludePackagedObserver()
    {
        var repoRoot = FindRepositoryRoot();
        var nativeBuild = File.ReadAllText(Path.Combine(repoRoot, "scripts", "build_native_host.ps1"));
        var publish = File.ReadAllText(Path.Combine(repoRoot, "build", "publish.ps1"));

        Assert.Contains("ApfsObserver.exe", nativeBuild, StringComparison.Ordinal);
        Assert.Contains("$observerExe", nativeBuild, StringComparison.Ordinal);
        Assert.Contains("$nativeObserverExe", publish, StringComparison.Ordinal);
        Assert.Contains("foreach ($destination in @($serviceOut, $probeOut, $cliOut, $bundleOut))", publish, StringComparison.Ordinal);
        Assert.Contains("Copy-Item -LiteralPath $nativeObserverExe -Destination (Join-Path $destination \"ApfsObserver.exe\") -Force", publish, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingEverywhere_ReturnsNull()
    {
        using var temp = DTempDirectory.Create("observer-missing");
        var options = new ServiceHostOptions();
        var resolved = NativeApfsObserver.ResolveNativeObserverPath(
            options, Path.Combine(temp.Path, "empty-base"));
        Directory.CreateDirectory(Path.Combine(temp.Path, "empty-base"));

        Assert.Null(resolved);
    }

    [Fact]
    public void ConfiguredPath_WinsOverBaseDirectoryCandidates()
    {
        using var temp = DTempDirectory.Create("observer-configured");
        var baseDir = Path.Combine(temp.Path, "base");
        Directory.CreateDirectory(baseDir);
        var baseExe = Path.Combine(baseDir, "ApfsObserver.exe");
        File.WriteAllBytes(baseExe, [0x4D, 0x5A]);
        var configured = Path.Combine(temp.Path, "custom", "Observer.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(configured)!);
        File.WriteAllBytes(configured, [0x4D, 0x5A]);

        var options = new ServiceHostOptions { NativeObserverPath = configured };
        var resolved = NativeApfsObserver.ResolveNativeObserverPath(options, baseDir);

        Assert.Equal(Path.GetFullPath(configured), resolved);
    }

    [Fact]
    public void MissingConfiguredPath_FallsThroughToBaseDirectory()
    {
        using var temp = DTempDirectory.Create("observer-fallback");
        var baseDir = Path.Combine(temp.Path, "base");
        Directory.CreateDirectory(baseDir);
        var baseExe = Path.Combine(baseDir, "ApfsObserver.exe");
        File.WriteAllBytes(baseExe, [0x4D, 0x5A]);

        var options = new ServiceHostOptions
        {
            NativeObserverPath = Path.Combine(temp.Path, "does-not-exist.exe"),
        };
        var resolved = NativeApfsObserver.ResolveNativeObserverPath(options, baseDir);

        Assert.Equal(baseExe, resolved);
    }

    [Fact]
    public void BaseDirectoryExe_BeatsNativeSubdir()
    {
        using var temp = DTempDirectory.Create("observer-basedir");
        var baseDir = Path.Combine(temp.Path, "base");
        var nativeDir = Path.Combine(baseDir, "native");
        Directory.CreateDirectory(nativeDir);
        var baseExe = Path.Combine(baseDir, "ApfsObserver.exe");
        var nativeExe = Path.Combine(nativeDir, "ApfsObserver.exe");
        File.WriteAllBytes(baseExe, [0x4D, 0x5A]);
        File.WriteAllBytes(nativeExe, [0x4D, 0x5A]);

        var resolved = NativeApfsObserver.ResolveNativeObserverPath(new ServiceHostOptions(), baseDir);

        Assert.Equal(baseExe, resolved);
    }

    [Fact]
    public void NativeSubdir_BeatsRepoBuildOutput()
    {
        using var temp = DTempDirectory.Create("observer-native");
        var repo = Path.Combine(temp.Path, "repo");
        var baseDir = Path.Combine(repo, "bin");
        var nativeDir = Path.Combine(baseDir, "native");
        Directory.CreateDirectory(nativeDir);
        var nativeExe = Path.Combine(nativeDir, "ApfsObserver.exe");
        File.WriteAllBytes(nativeExe, [0x4D, 0x5A]);
        var buildExe = Path.Combine(repo, "build", "ApfsAccess.ApfsRwEngine", "Release", "ApfsObserver.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(buildExe)!);
        File.WriteAllBytes(buildExe, [0x4D, 0x5A]);

        var resolved = NativeApfsObserver.ResolveNativeObserverPath(new ServiceHostOptions(), baseDir);

        Assert.Equal(nativeExe, resolved);
    }

    [Fact]
    public void RepoBuildOutput_BeatsArtifactsReleaseAndDebug()
    {
        using var temp = DTempDirectory.Create("observer-build");
        var repo = Path.Combine(temp.Path, "repo");
        var baseDir = Path.Combine(repo, "bin");
        Directory.CreateDirectory(baseDir);
        var buildExe = Path.Combine(repo, "build", "ApfsAccess.ApfsRwEngine", "Release", "ApfsObserver.exe");
        var releaseExe = Path.Combine(repo, "artifacts", "native", "Release", "ApfsObserver.exe");
        var debugExe = Path.Combine(repo, "artifacts", "native", "Debug", "ApfsObserver.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(buildExe)!);
        Directory.CreateDirectory(Path.GetDirectoryName(releaseExe)!);
        Directory.CreateDirectory(Path.GetDirectoryName(debugExe)!);
        File.WriteAllBytes(buildExe, [0x4D, 0x5A]);
        File.WriteAllBytes(releaseExe, [0x4D, 0x5A]);
        File.WriteAllBytes(debugExe, [0x4D, 0x5A]);

        var resolved = NativeApfsObserver.ResolveNativeObserverPath(new ServiceHostOptions(), baseDir);

        Assert.Equal(buildExe, resolved);
    }

    [Fact]
    public void ArtifactsRelease_BeatsArtifactsDebug()
    {
        using var temp = DTempDirectory.Create("observer-artifacts");
        var repo = Path.Combine(temp.Path, "repo");
        var baseDir = Path.Combine(repo, "bin");
        Directory.CreateDirectory(baseDir);
        var releaseExe = Path.Combine(repo, "artifacts", "native", "Release", "ApfsObserver.exe");
        var debugExe = Path.Combine(repo, "artifacts", "native", "Debug", "ApfsObserver.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(releaseExe)!);
        Directory.CreateDirectory(Path.GetDirectoryName(debugExe)!);
        File.WriteAllBytes(releaseExe, [0x4D, 0x5A]);
        File.WriteAllBytes(debugExe, [0x4D, 0x5A]);

        var resolved = NativeApfsObserver.ResolveNativeObserverPath(new ServiceHostOptions(), baseDir);

        Assert.Equal(releaseExe, resolved);
    }

    [Fact]
    public void NestedBaseDirectory_StillFindsRepoBuildOutputByAncestorWalk()
    {
        using var temp = DTempDirectory.Create("observer-walk");
        var repo = Path.Combine(temp.Path, "repo");
        var baseDir = Path.Combine(repo, "tests", "Some.Tests", "bin", "Debug", "net9.0");
        Directory.CreateDirectory(baseDir);
        var buildExe = Path.Combine(repo, "build", "ApfsAccess.ApfsRwEngine", "Release", "ApfsObserver.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(buildExe)!);
        File.WriteAllBytes(buildExe, [0x4D, 0x5A]);

        var resolved = NativeApfsObserver.ResolveNativeObserverPath(new ServiceHostOptions(), baseDir);

        Assert.Equal(buildExe, resolved);
    }

    private static string FindRepositoryRoot(
        [System.Runtime.CompilerServices.CallerFilePath] string sourceFile = "")
    {
        foreach (var start in new[]
                 {
                     Path.GetDirectoryName(sourceFile) ?? string.Empty,
                     Directory.GetCurrentDirectory(),
                     AppContext.BaseDirectory,
                 })
        {
            if (string.IsNullOrWhiteSpace(start))
            {
                continue;
            }

            var directory = new DirectoryInfo(start);
            while (directory is not null)
            {
                if (File.Exists(Path.Combine(directory.FullName, "APFSAccess.sln")))
                {
                    return directory.FullName;
                }

                directory = directory.Parent;
            }
        }

        throw new DirectoryNotFoundException("Could not locate the APFS Access repository root.");
    }
}

[Collection("ObserverPathEnv")]
public sealed class NativeObserverEnvOverrideTests
{
    [Fact]
    public void EnvOverride_WinsOverConfiguredPath()
    {
        using var temp = DTempDirectory.Create("observer-env");
        var baseDir = Path.Combine(temp.Path, "base");
        Directory.CreateDirectory(baseDir);
        var envExe = Path.Combine(temp.Path, "env", "ApfsObserver.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(envExe)!);
        File.WriteAllBytes(envExe, [0x4D, 0x5A]);
        var configured = Path.Combine(temp.Path, "configured.exe");
        File.WriteAllBytes(configured, [0x4D, 0x5A]);

        var previous = Environment.GetEnvironmentVariable(NativeApfsObserver.PathOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(NativeApfsObserver.PathOverrideVariable, envExe);
            var options = new ServiceHostOptions { NativeObserverPath = configured };
            var resolved = NativeApfsObserver.ResolveNativeObserverPath(options, baseDir);

            Assert.Equal(Path.GetFullPath(envExe), resolved);
        }
        finally
        {
            Environment.SetEnvironmentVariable(NativeApfsObserver.PathOverrideVariable, previous);
        }
    }

    [Fact]
    public void MissingEnvOverride_FallsThroughToConfiguredPath()
    {
        using var temp = DTempDirectory.Create("observer-env-missing");
        var baseDir = Path.Combine(temp.Path, "base");
        Directory.CreateDirectory(baseDir);
        var configured = Path.Combine(temp.Path, "configured.exe");
        File.WriteAllBytes(configured, [0x4D, 0x5A]);

        var previous = Environment.GetEnvironmentVariable(NativeApfsObserver.PathOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(
                NativeApfsObserver.PathOverrideVariable,
                Path.Combine(temp.Path, "no-such-file.exe"));
            var options = new ServiceHostOptions { NativeObserverPath = configured };
            var resolved = NativeApfsObserver.ResolveNativeObserverPath(options, baseDir);

            Assert.Equal(Path.GetFullPath(configured), resolved);
        }
        finally
        {
            Environment.SetEnvironmentVariable(NativeApfsObserver.PathOverrideVariable, previous);
        }
    }
}
