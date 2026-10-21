param(
    [string]$Configuration = "Debug",
    [string]$SMBLibrarySourceRoot = $env:SMBLibrarySourceRoot
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
Set-Location -LiteralPath $repoRoot
if ([string]::IsNullOrWhiteSpace($SMBLibrarySourceRoot)) {
    throw 'Supply -SMBLibrarySourceRoot with the pinned source described in third_party/SMBLibrary/BUILD.md.'
}
$SMBLibrarySourceRoot = (Resolve-Path -LiteralPath $SMBLibrarySourceRoot).Path
foreach ($name in @('SMBLibrary', 'Utilities')) {
    if (!(Test-Path -LiteralPath (Join-Path $SMBLibrarySourceRoot $name) -PathType Container)) {
        throw 'SMBLibrarySourceRoot must contain the pinned SMBLibrary and Utilities source directories.'
    }
}

Write-Host "[build] generating tray icons..."
pwsh -NoProfile -File (Join-Path $repoRoot "scripts/create_tray_icons.ps1")

Write-Host "[build] building native fs host (best-effort)..."
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path -LiteralPath $vcvars)) {
    $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (Test-Path -LiteralPath $vcvars) {
    $cmd = '"' + $vcvars + '" >nul && cd /d "' + $repoRoot + '" && pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration ' + $Configuration + ' -Generator "NMake Makefiles" -SkipIfUnavailable'
    cmd /c $cmd

    Write-Host "[build] building native RW engine scaffold (best-effort)..."
    $cmdRw = '"' + $vcvars + '" >nul && cd /d "' + $repoRoot + '" && pwsh -NoProfile -File .\scripts\build_rw_engine.ps1 -Configuration ' + $Configuration + ' -Generator "NMake Makefiles" -SkipIfUnavailable'
    cmd /c $cmdRw
} else {
    pwsh -NoProfile -File (Join-Path $repoRoot "scripts/build_native_host.ps1") -Configuration $Configuration -SkipIfUnavailable
    pwsh -NoProfile -File (Join-Path $repoRoot "scripts/build_rw_engine.ps1") -Configuration $Configuration -SkipIfUnavailable
}

Write-Host "[build] restoring and building solution..."
dotnet build .\APFSAccess.sln -c $Configuration "-p:SMBLibrarySourceRoot=$SMBLibrarySourceRoot"
if ($LASTEXITCODE -ne 0) { throw "Managed solution build failed with exit code $LASTEXITCODE." }
