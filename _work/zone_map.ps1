param([string]$ImagePath, [int]$Y0 = 1062, [int]$Y1 = 1556, [int]$Step = 8)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap((Resolve-Path $ImagePath).Path)
Write-Output ("zona y {0}..{1}, celula {2}px" -f $Y0, $Y1, $Step)

function Classify($c) {
    if ($c.R -eq 245 -and $c.G -eq 245 -and $c.B -eq 245) { return '.' }
    if ($c.R -eq 255 -and $c.G -eq 255 -and $c.B -eq 255) { return ' ' }
    if ($c.R -lt 90 -and $c.G -lt 90 -and $c.B -lt 90) { return '#' }
    if ($c.B -gt $c.R + 40) { return 'B' }
    if ($c.R -gt $c.B + 40 -and $c.G -gt 120) { return 'O' }
    if ($c.R -gt $c.B + 40) { return 'R' }
    if ($c.R -gt 200 -and $c.G -gt 200) { return 'y' }
    return '?'
}

for ($y = $Y0; $y -lt $Y1; $y += $Step) {
    $line = New-Object System.Text.StringBuilder
    for ($x = 0; $x -lt $bmp.Width; $x += $Step) {
        $classes = @{}
        for ($dy = 0; $dy -lt $Step; $dy++) {
            for ($dx = 0; $dx -lt $Step; $dx++) {
                $yy = $y + $dy; $xx = $x + $dx
                if ($yy -ge $bmp.Height -or $xx -ge $bmp.Width) { continue }
                $k = Classify $bmp.GetPixel($xx, $yy)
                if ($classes.ContainsKey($k)) { $classes[$k]++ } else { $classes[$k] = 1 }
            }
        }
        # classe dominante nao-cinza se houver minoria significativa
        $n = ($classes.Values | Measure-Object -Sum).Sum
        $best = '.'; $bestc = 0
        foreach ($k in $classes.Keys) {
            if ($k -eq '.' -or $k -eq ' ') { continue }
            if ($classes[$k] -gt $bestc) { $bestc = $classes[$k]; $best = $k }
        }
        if ($bestc -ge 8) { [void]$line.Append($best) }               # maioria nao-cinza
        elseif ($bestc -ge 2) { [void]$line.Append([char]::ToLower($best)) } # minoria
        else { [void]$line.Append('.') }
    }
    Write-Output ("{0,4} {1}" -f $y, $line.ToString())
}

