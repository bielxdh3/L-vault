$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$LocalVault = Join-Path $Root ".venv\Scripts\localvault.exe"
if (Test-Path $LocalVault) { & $LocalVault serve --root "$Root" } else { python -m localvault serve --root "$Root" }
