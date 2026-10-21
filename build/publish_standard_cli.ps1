param(
    [Parameter(Mandatory)][string]$SMBLibrarySourceRoot,
    [Parameter(Mandatory)][string]$NativeDirectory,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$Configuration = 'Release',
    [string]$ArtifactsDirectory,
    [string]$RepositoryDirectory,
    [switch]$NoBuild,
    [switch]$NoRestore
)
$ErrorActionPreference = 'Stop'
$repo = if ($RepositoryDirectory) { [IO.Path]::GetFullPath($RepositoryDirectory) } else { Split-Path $PSScriptRoot }
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'Use a new output directory for the explicit standard-share package.' }
$native = [IO.Path]::GetFullPath($NativeDirectory)
$required = @('ApfsAccess.FsHost.exe', 'ApfsObserver.exe', 'VolumeKeeperInspect.exe')
foreach ($name in $required) {
    if (!(Test-Path -LiteralPath (Join-Path $native $name) -PathType Leaf)) { throw "Missing native component: $name" }
}
New-Item -ItemType Directory -Path $output | Out-Null
$arguments = @('publish', (Join-Path $repo 'src/ApfsAccess.Cli/ApfsAccess.Cli.csproj'), '-c', $Configuration,
    '--self-contained', 'false', ('-p:SMBLibrarySourceRoot=' + $SMBLibrarySourceRoot), '-p:PublishReadyToRun=false', '-o', $output)
if ($ArtifactsDirectory) {
    $arguments += @('-p:UseArtifactsOutput=true', ('-p:ArtifactsPath=' + [IO.Path]::GetFullPath($ArtifactsDirectory)))
}
if ($NoBuild) { $arguments += '--no-build' }
elseif ($NoRestore) { $arguments += '--no-restore' }
& dotnet @arguments
if ($LASTEXITCODE -ne 0) { throw "Standard-share CLI publish failed: $LASTEXITCODE" }
$destination = Join-Path $output 'native'
New-Item -ItemType Directory -Path $destination | Out-Null
foreach ($file in @($required | ForEach-Object { Get-Item -LiteralPath (Join-Path $native $_) }) +
    @(Get-ChildItem -LiteralPath $native -File -Filter '*.dll')) {
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $destination $file.Name)
}
& (Join-Path $repo 'build/copy_package_notices.ps1') -OutputDirectory $output `
    -RepositoryDirectory $repo -SMBLibrarySourceRoot $SMBLibrarySourceRoot
Write-Output "Explicit standard-share CLI package: $output"
