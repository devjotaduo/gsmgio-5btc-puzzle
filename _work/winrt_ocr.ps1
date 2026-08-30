param([string]$ImagePath, [string]$Lang = "")
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Media.Ocr.OcrEngine, Windows.Media.Ocr, ContentType = WindowsRuntime]
$null = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
$null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
$null = [Windows.Globalization.Language, Windows.Globalization, ContentType = WindowsRuntime]

function Await($WinRtTask, $ResultType) {
    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}

Write-Output "=== idiomas OCR disponiveis ==="
[Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages | ForEach-Object { Write-Output $_.LanguageTag }

$engine = $null
if ($Lang -ne "") {
    try {
        $langObj = [Windows.Globalization.Language]::new($Lang)
        $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($langObj)
    } catch { Write-Output "falha ao criar engine para $Lang : $_" }
}
if ($null -eq $engine) {
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
}
if ($null -eq $engine) { Write-Output "SEM ENGINE OCR"; exit 1 }
Write-Output "engine pronto"

$path = (Resolve-Path $ImagePath).Path
$file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($path)) ([Windows.Storage.StorageFile])
$stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$bitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])

$bitmapFinal = $bitmap
try {
    $result = Await ($engine.RecognizeAsync($bitmapFinal)) ([Windows.Media.Ocr.OcrResult])
} catch {
    Write-Output "recognize falhou com bitmap original, convertendo p/ Bgra8..."
    $null = [Windows.Graphics.Imaging.SoftwareBitmap, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    $bitmapFinal = [Windows.Graphics.Imaging.SoftwareBitmap]::Convert($bitmap, [Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8)
    $result = Await ($engine.RecognizeAsync($bitmapFinal)) ([Windows.Media.Ocr.OcrResult])
}

Write-Output "=== TEXTO OCR (por linha) ==="
foreach ($line in $result.Lines) { Write-Output $line.Text }
Write-Output "=== fim ==="
