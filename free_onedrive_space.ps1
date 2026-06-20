$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$PSCommandPath`""
  )
  exit 0
}

$LogDir = Join-Path $Root "logs\manual"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogDir "$Stamp`_free_onedrive_space.log"
$LocalVault = Join-Path $Root ".venv\Scripts\localvault.exe"

if (Test-Path $LocalVault) {
  $Exe = $LocalVault
  $Args = @("onedrive-backup-cleanup", "--root", $Root)
} else {
  $Exe = "python"
  $Args = @("-m", "localvault", "onedrive-backup-cleanup", "--root", $Root)
}

"[$(Get-Date -Format o)] Starting verified OneDrive cleanup" | Tee-Object -FilePath $LogFile
& $Exe @Args 2>&1 | Tee-Object -FilePath $LogFile -Append
$Code = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
"[$(Get-Date -Format o)] Finished with exit code $Code" | Tee-Object -FilePath $LogFile -Append
Read-Host "Pressione Enter para fechar"
exit $Code
