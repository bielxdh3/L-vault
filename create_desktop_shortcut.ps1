$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ShortcutPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "Abrir LocalVault.lnk"
$Target = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$Script = Join-Path $Root "start_viewer_hidden.ps1"

$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $Target
$Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script`""
$Shortcut.WorkingDirectory = $Root
$Shortcut.Description = "Abrir painel local do LocalVault"
$Shortcut.IconLocation = "$env:SystemRoot\System32\shell32.dll,13"
$Shortcut.Save()

Write-Host "Atalho criado: $ShortcutPath"
