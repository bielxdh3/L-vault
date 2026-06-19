$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path $Root ".venv"
python -m venv $Venv
& (Join-Path $Venv "Scripts\python.exe") -m pip install --upgrade pip
& (Join-Path $Venv "Scripts\pip.exe") install -e "$Root[test]"
& (Join-Path $Venv "Scripts\localvault.exe") init --root "$Root"
Write-Host "Installed. Start viewer with .\run_viewer.ps1"
