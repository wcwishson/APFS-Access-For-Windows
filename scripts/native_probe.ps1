param(
    [Parameter(Mandatory = $true)]
    [string]$ApfsUtilPath,

    [Parameter(Mandatory = $true)]
    [string]$DevicePath
)

$ErrorActionPreference = "Stop"

if (!(Test-Path -LiteralPath $ApfsUtilPath)) {
    throw "apfsutil.exe was not found at: $ApfsUtilPath"
}

Write-Host "[probe] enumroot $DevicePath"
& $ApfsUtilPath enumroot $DevicePath
Write-Host ""
Write-Host "[probe] listsubvolumes $DevicePath"
& $ApfsUtilPath listsubvolumes $DevicePath
