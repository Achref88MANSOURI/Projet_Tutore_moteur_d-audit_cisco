param([string]$Python = "")
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
if (-not $Python) {
    $bundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    if (Test-Path -LiteralPath $bundledPython) { $Python = $bundledPython }
    else { $Python = (Get-Command python -ErrorAction Stop).Source }
}
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    & $Python -m venv --copies (Join-Path $projectRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
}
& $venvPython -m pip install --no-index --find-links (Join-Path $projectRoot 'wheelhouse') -r (Join-Path $projectRoot 'requirements.lock')
if ($LASTEXITCODE -ne 0) { throw 'Offline install failed. The included binary wheels target Windows x64 / Python 3.12.' }
Write-Output 'Environment ready. Run .\.venv\Scripts\python.exe webapp.py'
