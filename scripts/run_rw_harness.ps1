param(
    [ValidateSet("basic", "fault-injection")]
    [string]$Scenario = "basic",

    [string]$OutputDir = "",

    [switch]$IncludeNative
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "artifacts\rw-harness"
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $OutputDir $timestamp
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

$operations = @(
    "mount_rw_or_fallback",
    "create_file",
    "append_file",
    "truncate_file",
    "rename_file",
    "delete_file",
    "unmount",
    "remount_verify"
)

if ($Scenario -eq "fault-injection") {
    $operations += @(
        "inject_failure_before_commit",
        "inject_failure_after_metadata_stage",
        "recover_and_verify"
    )
}

$manifest = [pscustomobject]@{
    scenario = $Scenario
    generatedUtc = (Get-Date).ToUniversalTime().ToString("o")
    operations = $operations
    notes = @(
        "Phase-A scaffold: this harness generates a deterministic test manifest and runs managed tests.",
        "Native rw-engine persistence tests can be enabled with -IncludeNative."
    )
}

$manifestPath = Join-Path $runDir "manifest.json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8

$coreTestsOut = Join-Path $runDir "core-tests.log"
$ipcTestsOut = Join-Path $runDir "ipc-tests.log"
$nativeTestsOut = Join-Path $runDir "native-rw-tests.log"

Push-Location $repoRoot
try {
    dotnet test .\tests\ApfsAccess.Core.Tests\ApfsAccess.Core.Tests.csproj -c Release *>&1 | Tee-Object -FilePath $coreTestsOut
    dotnet test .\tests\ApfsAccess.Ipc.Tests\ApfsAccess.Ipc.Tests.csproj -c Release *>&1 | Tee-Object -FilePath $ipcTestsOut
    if ($IncludeNative) {
        pwsh -NoProfile -File .\scripts\build_rw_engine.ps1 -Configuration Release -RunTests *>&1 | Tee-Object -FilePath $nativeTestsOut
    }
}
finally {
    Pop-Location
}

Write-Host "[rw-harness] run directory: $runDir"
Write-Host "[rw-harness] manifest     : $manifestPath"
