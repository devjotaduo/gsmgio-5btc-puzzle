param([string]$ImagePath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap((Resolve-Path $ImagePath).Path)
Write-Output ("imagem: {0}x{1}" -f $bmp.Width, $bmp.Height)

$hist = @{}   # cor -> count
$posm = @{}   # cor -> List das primeiras posicoes (max 10)
$redpx = New-Object System.Collections.Generic.List[string]
$purplepx = New-Object System.Collections.Generic.List[string]
for ($y = 0; $y -lt $bmp.Height; $y++) {
    for ($x = 0; $x -lt $bmp.Width; $x++) {
        $c = $bmp.GetPixel($x, $y)
        $key = "{0},{1},{2}" -f $c.R, $c.G, $c.B
        if ($hist.ContainsKey($key)) { $hist[$key] = $hist[$key] + 1 } else { $hist[$key] = 1; $posm[$key] = New-Object System.Collections.Generic.List[string] }
        if ($posm[$key].Count -lt 10) { $posm[$key].Add("$x,$y") }
        if ($c.R -gt 150 -and $c.G -lt 90 -and $c.B -lt 90) { $redpx.Add("$x,$y") }
        if ($c.R -gt 90 -and $c.B -gt 90 -and $c.G -lt 70 -and [Math]::Abs($c.R - $c.B) -lt 90) { $purplepx.Add("$x,$y rgb=$key") }
    }
}
Write-Output "=== TOP 25 CORES ==="
$hist.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 25 | ForEach-Object {
    Write-Output ("{0}: {1}" -f $_.Key, $_.Value)
}
Write-Output "=== CORES RARAS (count <= 8) ==="
$hist.GetEnumerator() | Where-Object { $_.Value -le 8 } | Sort-Object { $_.Value } | ForEach-Object {
    Write-Output ("{0} (x{1}): {2}" -f $_.Key, $_.Value, ($posm[$_.Key] -join " "))
}
Write-Output "=== VERMELHOS ==="
Write-Output ("total: {0}" -f $redpx.Count)
if ($redpx.Count -gt 0) {
    $xs = @($redpx | ForEach-Object { [int]$_.Split(",")[0] })
    $ys = @($redpx | ForEach-Object { [int]$_.Split(",")[1] })
    Write-Output ("bbox x {0}..{1} y {2}..{3}" -f ($xs | Measure-Object -Minimum).Minimum, ($xs | Measure-Object -Maximum).Maximum, ($ys | Measure-Object -Minimum).Minimum, ($ys | Measure-Object -Maximum).Maximum)
    Write-Output ("amostra: " + (($redpx | Select-Object -First 15) -join " "))
}
Write-Output "=== ROXOS ==="
Write-Output ("total: {0}" -f $purplepx.Count)
if ($purplepx.Count -gt 0 -and $purplepx.Count -le 50) { $purplepx | ForEach-Object { Write-Output $_ } }
