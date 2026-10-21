param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$RepositoryDirectory = (Split-Path $PSScriptRoot),
    [string]$SMBLibrarySourceRoot = $env:SMBLibrarySourceRoot,
    [string]$Runtime = 'win-x64',
    [string[]]$AssetsFiles = @(),
    [string]$NuGetPackagesDirectory = $env:NUGET_PACKAGES
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath($RepositoryDirectory)
$output = (Get-Item -LiteralPath $OutputDirectory -ErrorAction Stop).FullName
if ($output -eq $repo) { throw 'A separate package output directory is required.' }

function Copy-NoticeFile([string]$Source, [string]$Relative) {
    if (!(Test-Path -LiteralPath $Source -PathType Leaf)) { throw "Required package notice/source is missing: $Source" }
    $destination = Join-Path $output $Relative
    New-Item -ItemType Directory -Path (Split-Path $destination) -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $destination -Force
}

Copy-NoticeFile (Join-Path $repo 'THIRD_PARTY_NOTICES.md') 'THIRD_PARTY_NOTICES.md'
foreach ($relative in @('third_party/utf8proc/LICENSE.md', 'third_party/lzfse/LICENSE',
    'third_party/zlib/LICENSE', 'third_party/lzbitmap/LZBITMAP-LICENSE.txt')) {
    Copy-NoticeFile (Join-Path $repo $relative) $relative
}

if (Test-Path -LiteralPath (Join-Path $output 'SMBLibrary.dll') -PathType Leaf) {
    if ([string]::IsNullOrWhiteSpace($SMBLibrarySourceRoot)) { throw 'SMBLibrary.dll requires its pinned SMBLibrarySourceRoot for source and notices.' }
    $library = Join-Path $repo 'third_party/SMBLibrary'
    $noticeRoot = Join-Path $output 'third_party/SMBLibrary'
    $upstream = Join-Path $noticeRoot 'upstream'
    if (Test-Path -LiteralPath $upstream) { throw 'SMBLibrary source destination must be fresh.' }
    # Reuse the production source/hash/patch validator before distributing source.
    & (Join-Path $library 'PrepareSource.ps1') -SourceRoot $SMBLibrarySourceRoot -Destination (Join-Path $noticeRoot 'modified')
    if ((Get-FileHash -LiteralPath (Join-Path $SMBLibrarySourceRoot 'License.txt')).Hash -cne
        (Get-FileHash -LiteralPath (Join-Path $library 'LICENSE.txt')).Hash) { throw 'SMBLibrary upstream license differs from the pinned license.' }
    foreach ($file in Get-ChildItem -LiteralPath $library -File) {
        Copy-NoticeFile $file.FullName ('third_party/SMBLibrary/' + $file.Name)
    }
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $library 'Extensions') -File) {
        Copy-NoticeFile $file.FullName ('third_party/SMBLibrary/Extensions/' + $file.Name)
    }
    $manifest = Get-Content -LiteralPath (Join-Path $library 'source-pins.json') -Raw | ConvertFrom-Json
    foreach ($file in $manifest.files) {
        Copy-NoticeFile (Join-Path $SMBLibrarySourceRoot $file.path) ('third_party/SMBLibrary/upstream/' + $file.path)
    }
    Copy-NoticeFile (Join-Path $SMBLibrarySourceRoot 'License.txt') 'third_party/SMBLibrary/upstream/License.txt'
}

$packageRoots = [Collections.Generic.List[string]]::new()
if ($NuGetPackagesDirectory) { $packageRoots.Add([IO.Path]::GetFullPath($NuGetPackagesDirectory)) }
foreach ($assets in $AssetsFiles) {
    $json = Get-Content -LiteralPath $assets -Raw | ConvertFrom-Json
    foreach ($folder in $json.packageFolders.PSObject.Properties.Name) {
        if (!$packageRoots.Contains($folder)) { $packageRoots.Add($folder) }
    }
}
if (!$packageRoots.Count) { $packageRoots.Add((Join-Path ([Environment]::GetFolderPath('UserProfile')) '.nuget/packages')) }
function PackageDirectory([string]$Name, [string]$Version) {
    foreach ($root in $packageRoots) {
        $path = Join-Path $root ($Name.ToLowerInvariant() + '/' + $Version.ToLowerInvariant())
        if (Test-Path -LiteralPath $path -PathType Container) { return $path }
    }
    throw "Notice source for published package $Name/$Version was not found in the restored package folders."
}
function Copy-PackageLicense([string]$Name, [string]$Version, [string]$Relative) {
    $package = PackageDirectory $Name $Version
    $licenses = @(Get-ChildItem -LiteralPath $package -File | Where-Object { $_.Name -in 'LICENSE', 'LICENSE.TXT', 'LICENSE.MD' })
    if (!$licenses.Count) { throw "No license file found for published package $Name/$Version." }
    foreach ($file in @($licenses) + @(Get-ChildItem -LiteralPath $package -File | Where-Object { $_.Name -match '^THIRD[-.]?PARTY[-.]?NOTICES?(\.TXT)?$' })) {
        Copy-NoticeFile $file.FullName ($Relative + '/' + $file.Name)
    }
}

$packages = @{}
foreach ($file in Get-ChildItem -LiteralPath $output -Filter '*.deps.json' -File) {
    $deps = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    foreach ($entry in $deps.libraries.PSObject.Properties) {
        if ($entry.Value.type -eq 'package' -and !$entry.Name.StartsWith('runtimepack.', [StringComparison]::OrdinalIgnoreCase)) {
            $parts = $entry.Name.Split('/')
            if ($parts.Count -ne 2) { throw "Invalid published package identity: $($entry.Name)" }
            $packages[$entry.Name.ToLowerInvariant()] = $parts
        }
    }
}
foreach ($parts in $packages.Values) {
    Copy-PackageLicense $parts[0] $parts[1] ('licenses/dotnet-packages/' + $parts[0].ToLowerInvariant() + '/' + $parts[1])
}
$frameworks = @{}
foreach ($file in Get-ChildItem -LiteralPath $output -Filter '*.runtimeconfig.json' -File) {
    $config = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    foreach ($framework in $config.runtimeOptions.includedFrameworks) {
        $frameworks[$framework.name + '/' + $framework.version] = $framework
    }
}
foreach ($framework in $frameworks.Values) {
    $family = switch ($framework.name) {
        'Microsoft.NETCore.App' { 'dotnet-runtime' }
        'Microsoft.WindowsDesktop.App' { 'windowsdesktop' }
        default { throw "No notice mapping for included framework $($framework.name)." }
    }
    Copy-PackageLicense ($framework.name + '.Runtime.' + $Runtime) $framework.version ('licenses/' + $family + '/' + $framework.version)
}
if ((Test-Path -LiteralPath (Join-Path $output 'coreclr.dll')) -and !$frameworks.Count) {
    throw 'Self-contained runtime files have no included framework version for notice selection.'
}
Write-Output "Package notices copied: $output"
