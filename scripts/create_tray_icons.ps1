Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$iconDir = Join-Path $repoRoot "assets/icons"
New-Item -ItemType Directory -Force -Path $iconDir | Out-Null

$sizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)

function New-IconBitmapBytes {
    param(
        [int]$Size,
        [System.Drawing.Color]$PrimaryColor
    )

    $bmp = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)

    try {
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.Clear([System.Drawing.Color]::FromArgb(0, 0, 0, 0))

        $pad = [Math]::Max(1, [int]($Size * 0.10))
        $diam = $Size - (2 * $pad)

        $fillBrush = New-Object System.Drawing.SolidBrush($PrimaryColor)
        $ringPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(235, 255, 255, 255), [Math]::Max(1, [int]($Size * 0.05)))
        $g.FillEllipse($fillBrush, $pad, $pad, $diam, $diam)
        $g.DrawEllipse($ringPen, $pad, $pad, $diam, $diam)

        $driveW = [int]($Size * 0.56)
        $driveH = [int]($Size * 0.26)
        $driveX = [int](($Size - $driveW) / 2)
        $driveY = [int]($Size * 0.40)

        $driveBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(245, 255, 255, 255))
        $drivePen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 40, 40, 40), [Math]::Max(1, [int]($Size * 0.03)))
        $g.FillRectangle($driveBrush, $driveX, $driveY, $driveW, $driveH)
        $g.DrawRectangle($drivePen, $driveX, $driveY, $driveW, $driveH)

        $dot = [int]($Size * 0.12)
        $dotBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(230, 255, 255, 255))
        $g.FillEllipse($dotBrush, [int]($Size * 0.66), [int]($Size * 0.46), $dot, $dot)

        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        return $ms.ToArray()
    }
    finally {
        $g.Dispose()
        $bmp.Dispose()
    }
}

function Write-Ico {
    param(
        [string]$Path,
        [System.Drawing.Color]$PrimaryColor
    )

    $frames = @()
    foreach ($s in $sizes) {
        $bytes = New-IconBitmapBytes -Size $s -PrimaryColor $PrimaryColor
        $frames += [PSCustomObject]@{ Size = $s; Bytes = $bytes }
    }

    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $bw = New-Object System.IO.BinaryWriter($fs)
    try {
        $bw.Write([UInt16]0)
        $bw.Write([UInt16]1)
        $bw.Write([UInt16]$frames.Count)

        $offset = [uint32](6 + (16 * $frames.Count))
        foreach ($f in $frames) {
            $sizeByte = if ($f.Size -eq 256) { [byte]0 } else { [byte]$f.Size }
            $bw.Write($sizeByte)
            $bw.Write($sizeByte)
            $bw.Write([byte]0)
            $bw.Write([byte]0)
            $bw.Write([UInt16]1)
            $bw.Write([UInt16]32)
            $length = [uint32]$f.Bytes.Length
            $bw.Write($length)
            $bw.Write($offset)
            $offset = [uint32]($offset + $length)
        }

        foreach ($f in $frames) {
            $bw.Write([byte[]]$f.Bytes)
        }
    }
    finally {
        $bw.Close()
        $fs.Close()
    }
}

Write-Ico -Path (Join-Path $iconDir "tray_idle.ico")       -PrimaryColor ([System.Drawing.Color]::FromArgb(255, 111, 122, 133))
Write-Ico -Path (Join-Path $iconDir "tray_mounted_rw.ico") -PrimaryColor ([System.Drawing.Color]::FromArgb(255, 33, 150, 83))
Write-Ico -Path (Join-Path $iconDir "tray_mounted_ro.ico") -PrimaryColor ([System.Drawing.Color]::FromArgb(255, 33, 150, 83))
Write-Ico -Path (Join-Path $iconDir "tray_error.ico")      -PrimaryColor ([System.Drawing.Color]::FromArgb(255, 192, 57, 43))

Write-Host "Created tray icons in $iconDir"

