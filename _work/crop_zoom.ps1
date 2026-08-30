param([string]$ImagePath, [int]$X0, [int]$Y0, [int]$W, [int]$H, [double]$Zoom = 4.0, [string]$OutPath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$src = New-Object System.Drawing.Bitmap((Resolve-Path $ImagePath).Path)
$dst = New-Object System.Drawing.Bitmap([int]($W * $Zoom), [int]($H * $Zoom))
$g = [System.Drawing.Graphics]::FromImage($dst)
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBilinear
$g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
$rect = New-Object System.Drawing.Rectangle(0, 0, $dst.Width, $dst.Height)
$g.DrawImage($src, $rect, (New-Object System.Drawing.Rectangle($X0, $Y0, $W, $H)), [System.Drawing.GraphicsUnit]::Pixel)
$g.Dispose()
$dst.Save((Join-Path (Get-Location) $OutPath), [System.Drawing.Imaging.ImageFormat]::Png)
$dst.Dispose()
Write-Output ("salvo: {0} ({1}x{2})" -f $OutPath, ([int]($W * $Zoom)), ([int]($H * $Zoom)))
