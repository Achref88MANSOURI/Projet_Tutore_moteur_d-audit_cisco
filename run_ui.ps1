$ErrorActionPreference = 'Stop'
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Environnement Python absent. Lancez setup.ps1 avant de démarrer l’interface.'
}
& $pythonPath (Join-Path $PSScriptRoot 'webapp.py') @args
exit $LASTEXITCODE

