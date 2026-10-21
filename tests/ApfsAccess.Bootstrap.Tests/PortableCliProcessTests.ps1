param(
    [Parameter(Mandatory)][string]$BootstrapPath,
    [Parameter(Mandatory)][string]$PayloadCliPath,
    [Parameter(Mandatory)][string]$PackagePinsPath,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$ExistingPortableRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($OutputDirectory -notmatch '^[Dd]:[\\/]' -or (Test-Path -LiteralPath $OutputDirectory)) { throw 'Use a fresh absolute D test directory.' }
if ((Get-PSDrive D).Free -lt 150MB) { throw 'D test reserve unavailable.' }
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$environment = [ordered]@{}
foreach ($key in @('TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'DOTNET_CLI_HOME', 'DOTNET_BUNDLE_EXTRACT_BASE_DIR', 'APFSACCESS_PORTABLE_ROOT', 'APFSACCESS_RUNTIME_ROOT')) {
    $environment[$key] = Join-Path $OutputDirectory $key
    [void][IO.Directory]::CreateDirectory($environment[$key])
}
if ($ExistingPortableRoot) {
    if ($ExistingPortableRoot -notmatch '^[Dd]:[\\/]' -or !(Test-Path -LiteralPath $ExistingPortableRoot -PathType Container)) { throw 'Existing portable root must be a D test directory.' }
    $environment.APFSACCESS_PORTABLE_ROOT = [IO.Path]::GetFullPath($ExistingPortableRoot)
}
$pipe = 'APFSAccess-Bootstrap-Test-' + [Guid]::NewGuid().ToString('N')
$operation = [Guid]::NewGuid().ToString('D')
$connection = @('--pipe-name', $pipe, '--no-start-service', '--operation-id', $operation)
$cases = @(
    @{ name = 'help'; arguments = @('--help') + $connection; exit = 0 },
    @{ name = 'version'; arguments = @('--version') + $connection; exit = 0 },
    @{ name = 'quoted-failed-command'; arguments = @('portable bad command "quoted" trailing\') + $connection; exit = 2 },
    @{ name = 'stderr-invalid-key-command'; arguments = @('image-keys', 'not-an-action'); exit = 2 }
)
$runs = [Collections.Generic.List[object]]::new()
function RunProcess($executable, $arguments, $name) {
    $start = [Diagnostics.ProcessStartInfo]::new($executable)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WorkingDirectory = $OutputDirectory
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($key in @($start.Environment.Keys)) {
        if ($key -match '^(APFSACCESS_|CORECLR_|COR_|DOTNET_STARTUP_HOOKS$)') { [void]$start.Environment.Remove($key) }
    }
    foreach ($key in $environment.Keys) { $start.Environment[$key] = $environment[$key] }
    foreach ($argument in $arguments) { $start.ArgumentList.Add($argument) }
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $start
    $stdout = [IO.MemoryStream]::new()
    $stderr = [IO.MemoryStream]::new()
    try {
        if (!$child.Start()) { throw 'Child did not start.' }
        [void]$child.SafeHandle
        $ownedPid = $child.Id
        $readOut = $child.StandardOutput.BaseStream.CopyToAsync($stdout)
        $readErr = $child.StandardError.BaseStream.CopyToAsync($stderr)
        $child.StandardInput.Close()
        if (!$child.WaitForExit(30000)) { throw "Owned process $ownedPid exceeded deadline; inspect before cleanup." }
        [void]$readOut.GetAwaiter().GetResult()
        [void]$readErr.GetAwaiter().GetResult()
        $outBytes = $stdout.ToArray()
        $errBytes = $stderr.ToArray()
        [IO.File]::WriteAllBytes((Join-Path $OutputDirectory "$name.stdout"), $outBytes)
        [IO.File]::WriteAllBytes((Join-Path $OutputDirectory "$name.stderr"), $errBytes)
        $run = [ordered]@{ name = $name; executable = $executable; arguments = $arguments; pid = $ownedPid; exited = $child.HasExited; exitCode = $child.ExitCode; stdoutBytes = $outBytes.Length; stderrBytes = $errBytes.Length; stdoutSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($outBytes)); stderrSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($errBytes)) }
        $runs.Add($run)
        [IO.File]::WriteAllText((Join-Path $OutputDirectory "$name.process.json"), ($run | ConvertTo-Json -Depth 6))
        return [pscustomobject]$run
    } finally { $child.Dispose(); $stdout.Dispose(); $stderr.Dispose() }
}
foreach ($case in $cases) {
    $direct = RunProcess $PayloadCliPath $case.arguments ($case.name + '-direct')
    $portable = RunProcess $BootstrapPath (@('--cli') + $case.arguments) ($case.name + '-portable')
    if ($direct.exitCode -ne $case.exit -or $portable.exitCode -ne $direct.exitCode -or $portable.stdoutSha256 -cne $direct.stdoutSha256 -or $portable.stderrSha256 -cne $direct.stderrSha256) { throw "CLI forwarding differs: $($case.name)" }
    if ($case.name -eq 'version') {
        $version = Get-Content -LiteralPath (Join-Path $OutputDirectory 'version-portable.stdout') -Raw | ConvertFrom-Json
        if (!$version.success -or $version.version -cne '1.0.6.0') { throw 'Unexpected actual CLI version.' }
    }
    if ($case.name -eq 'stderr-invalid-key-command' -and ($portable.stderrBytes -eq 0 -or $portable.stdoutBytes -ne 0)) { throw 'Real stderr refusal was not exercised.' }
}
$payloads = @(Get-ChildItem -LiteralPath $environment.APFSACCESS_PORTABLE_ROOT -Directory)
if ($payloads.Count -ne 1 -or $payloads[0].Name -cne 'payload-7ABDFF5C73FB3C63') { throw 'Real embedded payload extraction did not produce the expected cache.' }
$payload = $payloads[0].FullName
$marker = Join-Path $payload '.payload.sha256'
if ((Get-Content -LiteralPath $marker -Raw).Trim() -cne '7ABDFF5C73FB3C63') { throw 'Extracted payload marker differs.' }
$pins = @(Get-Content -LiteralPath $PackagePinsPath -Raw | ConvertFrom-Json)
$verified = 0
foreach ($pin in $pins) {
    if (!$pin.relativePath.StartsWith('click-run\')) { continue }
    $relative = $pin.relativePath.Substring(10)
    $file = Join-Path $payload $relative
    if ((Get-Item -LiteralPath $file).Length -ne $pin.bytes -or (Get-FileHash -LiteralPath $file).Hash -cne $pin.sha256) { throw "Real extracted member differs: $relative" }
    $verified++
}
if ($verified -ne 1032 -or @(Get-ChildItem -LiteralPath $payload -Recurse -File).Count -ne $verified + 1) { throw 'Actual extraction is incomplete or has extra files.' }
$result = [ordered]@{
    status = 'Passed'; timestamp = [DateTimeOffset]::Now.ToString('o'); cases = $cases.Count; realProcesses = $runs.Count; runs = @($runs.ToArray())
    portableSha256 = (Get-FileHash -LiteralPath $BootstrapPath).Hash; expectedCliSha256 = (Get-FileHash -LiteralPath $PayloadCliPath).Hash
    extractedPayload = $payload; verifiedPayloadFiles = $verified; byteExactStdoutAndStderr = $true; serviceAutoStartRequested = $false
    environment = $environment; uniquePipe = $pipe; dFreeAfter = (Get-PSDrive D).Free
}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'result.json'), ($result | ConvertTo-Json -Depth 12))
[pscustomobject]$result | Select-Object status, cases, realProcesses, verifiedPayloadFiles, byteExactStdoutAndStderr, dFreeAfter | ConvertTo-Json
