param(
    [switch]$ForDeveloperBuild
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-WinFspInstalled {
    $service = Get-Service -Name "WinFsp.Launcher" -ErrorAction SilentlyContinue
    return $null -ne $service
}

function Test-CMakeInstalled {
    if ($null -ne (Get-Command cmake -ErrorAction SilentlyContinue)) {
        return $true
    }

    return (Test-Path -LiteralPath "C:\Program Files\CMake\bin\cmake.exe")
}

function Test-MsvcClInstalled {
    if ($null -ne (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        return $true
    }

    return (Test-Path -LiteralPath "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC")
}

function Test-VcRuntime {
    $key = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" -ErrorAction SilentlyContinue
    if ($null -eq $key) {
        return $false
    }

    return ($key.Installed -eq 1)
}

$checks = [System.Collections.Generic.List[object]]::new()

$checks.Add([pscustomobject]@{
    Name = "Admin session"
    Required = $false
    Passed = (Test-IsAdmin)
    Notes = "Recommended when installing prerequisites; not required after setup."
})

$checks.Add([pscustomobject]@{
    Name = "WinFsp runtime"
    Required = $true
    Passed = (Test-WinFspInstalled)
    Notes = "Install from https://winfsp.dev/ if missing."
})

$checks.Add([pscustomobject]@{
    Name = "VC++ x64 runtime"
    Required = $true
    Passed = (Test-VcRuntime)
    Notes = "Install Microsoft Visual C++ Redistributable x64 if missing."
})

if ($ForDeveloperBuild) {
    $checks.Add([pscustomobject]@{
        Name = "CMake"
        Required = $true
        Passed = (Test-CMakeInstalled)
        Notes = "Needed to build src-native/ApfsAccess.FsHost."
    })

    $checks.Add([pscustomobject]@{
        Name = "MSVC cl.exe"
        Required = $true
        Passed = (Test-MsvcClInstalled)
        Notes = "Install Visual Studio Build Tools (C++ workload) if missing."
    })
}

Write-Host ""
Write-Host "APFS Access prerequisite check"
$checks | Select-Object Name, Required, Passed, Notes | Format-Table -AutoSize

$failedRequired = $checks | Where-Object { $_.Required -and -not $_.Passed }
if ($failedRequired.Count -gt 0) {
    Write-Warning "Required prerequisites are missing."
    exit 1
}

Write-Host "All required prerequisites are present."
