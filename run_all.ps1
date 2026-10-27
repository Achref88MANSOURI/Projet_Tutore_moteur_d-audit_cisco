$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $pythonExe = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $pythonExe)) { throw 'Run setup.ps1 first.' }
    & $pythonExe tools\evaluate_twenty.py --pilot
    if ($LASTEXITCODE -ne 0) { throw 'Pilot evaluation failed.' }
    & $pythonExe tools\evaluate_twenty.py
    if ($LASTEXITCODE -ne 0) { throw 'Corpus evaluation failed.' }
    & $pythonExe -m pytest tests -q -p no:cacheprovider --junitxml=outputs/tests.xml
    if ($LASTEXITCODE -ne 0) { throw 'Behavioral tests failed.' }
    & $pythonExe tools\build_report.py
    if ($LASTEXITCODE -ne 0) { throw 'Report generation failed.' }
} finally { Pop-Location }
