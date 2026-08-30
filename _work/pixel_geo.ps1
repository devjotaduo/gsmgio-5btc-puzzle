param([string]$ImagePath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap((Resolve-Path $ImagePath).Path)
Write-Output ("imagem: {0}x{1}" -f $bmp.Width, $bmp.Height)

$targets = @{
  "VERMELHO_ED1C24" = { param($c) ($c.R -eq 237 -and $c.G -eq 28 -and $c.B -eq 36) }
  "vermelho_generoso" = { param($c) ($c.R -gt 180 -and $c.G -lt 90 -and $c.B -lt 90) }
  "FEFEFE" = { param($c) ($c.R -eq 254 -and $c.G -eq 254 -and $c.B -eq 254) }
  "AZUL_3F48CC" = { param($c) ($c.R -eq 63 -and $c.G -eq 72 -and $c.B -eq 204) }
  "AMARELO_FFF200" = { param($c) ($c.R -eq 255 -and $c.G -eq 242 -and $c.B -eq 0) }
  "CINZA_F5F5F5" = { param($c) ($c.R -eq 245 -and $c.G -eq 245 -and $c.B -eq 245) }
  "ROXO" = { param($c) ($c.R -gt 80 -and $c.B -gt 80 -and $c.G -lt 80 -and [Math]::Abs($c.R - $c.B) -lt 120) }
}
foreach ($name in $targets.Keys) {
    $pred = $targets[$name]
    $xs = New-Object System.Collections.Generic.List[int]
    $ys = New-Object System.Collections.Generic.List[int]
    $rows = @{}
    for ($y = 0; $y -lt $bmp.Height; $y++) {
        for ($x = 0; $x -lt $bmp.Width; $x++) {
            $c = $bmp.GetPixel($x, $y)
            if (& $pred $c) {
                $xs.Add($x); $ys.Add($y)
                if ($rows.ContainsKey($y)) { $rows[$y]++ } else { $rows[$y] = 1 }
            }
        }
    }
    if ($xs.Count -eq 0) { Write-Output ("{0}: 0 px" -f $name); continue }
    $minx = ($xs | Measure-Object -Minimum).Minimum; $maxx = ($xs | Measure-Object -Maximum).Maximum
    $miny = ($ys | Measure-Object -Minimum).Minimum; $maxy = ($ys | Measure-Object -Maximum).Maximum
    Write-Output ("{0}: {1} px | bbox x {2}..{3} y {4}..{5}" -f $name, $xs.Count, $minx, $maxx, $miny, $maxy)
    if ($name -like "VERM*") {
        Write-Output "  linhas com mais vermelho (y: count):"
        $rows.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 12 | ForEach-Object {
            Write-Output ("    y={0}: {1}" -f $_.Key, $_.Value)
        }
    }
}
