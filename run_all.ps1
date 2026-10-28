$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $pythonExe = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $pythonExe)) { throw 'Run setup.ps1 first.' }
    & $pythonExe -B tools\validate_normalized.py
    if ($LASTEXITCODE -ne 0) { throw 'Corpus evaluation failed.' }
    $testTemp = Join-Path 'outputs' ('pytest_' + [guid]::NewGuid().ToString('N').Substring(0,12))
    & $pythonExe -B -m pytest tests -q -p no:cacheprovider --basetemp=$testTemp --junitxml=outputs/tests.xml
    if ($LASTEXITCODE -ne 0) { throw 'Behavioral tests failed.' }
} finally { Pop-Location }
