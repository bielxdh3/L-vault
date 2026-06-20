from __future__ import annotations

import subprocess
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import DEFAULT_CONFIG, VaultPaths, load_config


@dataclass(frozen=True)
class GeneratedScheduleFiles:
    runner: Path
    install: Path
    remove: Path
    list_tasks: Path


def automation_defaults() -> dict[str, Any]:
    return deepcopy(DEFAULT_CONFIG["automation"])


def merge_automation_config(override: dict[str, Any]) -> dict[str, Any]:
    base = automation_defaults()
    base.setdefault("tasks", {})
    for key, value in override.items():
        if key == "tasks" and isinstance(value, dict):
            for task_key, task_value in value.items():
                base["tasks"].setdefault(task_key, {}).update(task_value)
        else:
            base[key] = value
    return base


def generate_schedule_files(p: VaultPaths) -> GeneratedScheduleFiles:
    automation = merge_automation_config(load_config(p.root).get("automation", {}))
    runner = p.root / "run_scheduled_task.ps1"
    install = p.root / "schedule_tasks.ps1"
    remove = p.root / "unschedule_tasks.ps1"
    list_tasks = p.root / "list_scheduled_tasks.ps1"
    runner.write_text(_runner_script(p), encoding="utf-8")
    install.write_text(_install_script(p, automation), encoding="utf-8")
    remove.write_text(_remove_script(automation), encoding="utf-8")
    list_tasks.write_text(_list_script(automation), encoding="utf-8")
    return GeneratedScheduleFiles(runner, install, remove, list_tasks)


def list_windows_tasks(prefix: str) -> subprocess.CompletedProcess[str]:
    command = f"Get-ScheduledTask | Where-Object {{$_.TaskName -like '{prefix} *'}} | Select-Object TaskName,State,TaskPath | Format-Table -AutoSize"
    return subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], text=True, capture_output=True, check=False)


def run_powershell_script(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)], text=True, check=False)


def _runner_script(p: VaultPaths) -> str:
    return f"""param([Parameter(Mandatory=$true)][string]$TaskName,[Parameter(Mandatory=$true)][string]$CommandArgs)
$ErrorActionPreference = "Stop"
$VaultRoot = "{p.root}"
$LogDir = Join-Path $VaultRoot "logs\\scheduled"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$SafeTaskName = $TaskName -replace "[^A-Za-z0-9_-]", "_"
$LogFile = Join-Path $LogDir "$Stamp`_$SafeTaskName.log"
$LocalVaultExe = Join-Path $VaultRoot ".venv\\Scripts\\localvault.exe"
if (Test-Path $LocalVaultExe) {{ $Exe = $LocalVaultExe; $BaseArgs = @() }} else {{ $Exe = "python"; $BaseArgs = @("-m","localvault") }}
$AllArgs = $BaseArgs + ($CommandArgs -split " ") + @("--root",$VaultRoot)
"[$(Get-Date -Format o)] Starting $TaskName" | Out-File -FilePath $LogFile -Encoding utf8
"& $Exe $($AllArgs -join ' ')" | Out-File -FilePath $LogFile -Encoding utf8 -Append
try {{
  & $Exe @AllArgs 2>&1 | ForEach-Object {{ $_ | Out-File -FilePath $LogFile -Encoding utf8 -Append }}
  $ExitCode = if ($null -eq $LASTEXITCODE) {{ 0 }} else {{ $LASTEXITCODE }}
  "[$(Get-Date -Format o)] Finished with exit code $ExitCode" | Out-File -FilePath $LogFile -Encoding utf8 -Append
  exit $ExitCode
}} catch {{
  "[$(Get-Date -Format o)] Failed: $($_.Exception.Message)" | Out-File -FilePath $LogFile -Encoding utf8 -Append
  exit 1
}}
"""


def _install_script(p: VaultPaths, automation: dict[str, Any]) -> str:
    return f"""$ErrorActionPreference = "Stop"
$VaultRoot = "{p.root}"
$Runner = Join-Path $VaultRoot "run_scheduled_task.ps1"
$ExecutionTimeLimit = New-TimeSpan -Hours {int(automation.get("execution_time_limit_hours", 8))}
$Tasks = @(
{_powershell_tasks(automation)}
)
function New-LocalVaultTrigger($Task) {{
  if ($Task.Frequency -eq "Daily") {{ return New-ScheduledTaskTrigger -Daily -At $Task.Time }}
  if ($Task.Frequency -eq "Weekly") {{ return New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Task.Days -At $Task.Time }}
  throw "Unsupported frequency: $($Task.Frequency)"
}}
Write-Host "This will register LocalVault scheduled tasks for $VaultRoot"
$confirm = Read-Host "Type YES to continue"
if ($confirm -ne "YES") {{ Write-Host "Cancelled."; exit 0 }}
foreach ($Task in $Tasks) {{
  if (-not $Task.Enabled) {{ Write-Host "Skipping disabled task: $($Task.Name)"; continue }}
  $ActionArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$Runner`" -TaskName `"$($Task.FullName)`" -CommandArgs `"$($Task.Command)`""
  $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $ActionArgs
  $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit $ExecutionTimeLimit
  $Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
  Register-ScheduledTask -TaskName $Task.FullName -Action $Action -Trigger (New-LocalVaultTrigger $Task) -Settings $Settings -Principal $Principal -Description "LocalVault Backup Manager: $($Task.Command)" -Force | Out-Null
  Write-Host "Registered: $($Task.FullName)"
}}
"""


def _remove_script(automation: dict[str, Any]) -> str:
    prefix = automation.get("task_prefix", "LocalVault")
    return f"""$TaskPrefix = "{prefix}"
$Tasks = Get-ScheduledTask | Where-Object {{ $_.TaskName -like "$TaskPrefix *" }}
if (-not $Tasks) {{ Write-Host "No LocalVault scheduled tasks found."; exit 0 }}
$Tasks | Select-Object TaskName,State,TaskPath | Format-Table -AutoSize
$confirm = Read-Host "Type REMOVE to unregister these tasks"
if ($confirm -ne "REMOVE") {{ Write-Host "Cancelled."; exit 0 }}
$Tasks | ForEach-Object {{ Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false; Write-Host "Removed: $($_.TaskName)" }}
"""


def _list_script(automation: dict[str, Any]) -> str:
    prefix = automation.get("task_prefix", "LocalVault")
    return f"""$TaskPrefix = "{prefix}"
Get-ScheduledTask | Where-Object {{ $_.TaskName -like "$TaskPrefix *" }} | Select-Object TaskName,State,TaskPath | Format-Table -AutoSize
"""


def _powershell_tasks(automation: dict[str, Any]) -> str:
    lines = []
    prefix = automation.get("task_prefix", "LocalVault")
    for key, task in automation.get("tasks", {}).items():
        enabled = "$true" if task.get("enabled", True) else "$false"
        name = str(task.get("name", key)).replace('"', '`"')
        full = f"{prefix} {name}".replace('"', '`"')
        cmd = str(task.get("command", "")).replace('"', '`"')
        freq = str(task.get("frequency", "daily")).capitalize()
        time = str(task.get("time", "03:00"))
        days = ", ".join(f'"{d}"' for d in (task.get("days") or []))
        lines.append(f'  @{{ Key="{key}"; FullName="{full}"; Name="{name}"; Command="{cmd}"; Frequency="{freq}"; Time="{time}"; Days=@({days}); Enabled={enabled} }}')
    return ",\n".join(lines)
