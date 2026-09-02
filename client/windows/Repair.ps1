[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repairLogDirectory = "$env:ProgramData\OperationCrackdown"
$repairLog = Join-Path $repairLogDirectory 'repair-error.log'
trap {
    New-Item -ItemType Directory -Path $repairLogDirectory -Force | Out-Null
    $message = "[$([DateTime]::UtcNow.ToString('o'))] $($_.Exception.ToString())`r`n$($_.InvocationInfo.PositionMessage)`r`n$($_.ScriptStackTrace)"
    Set-Content -LiteralPath $repairLog -Value $message -Encoding UTF8
    exit 1
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this repair from an elevated PowerShell window (Run as administrator).'
}

$installDirectory = "$env:ProgramData\OperationCrackdown"
$configPath = Join-Path $installDirectory 'config.json'
$agentSource = Join-Path $PSScriptRoot 'OperationCrackdown.ps1'
$agentPath = Join-Path $installDirectory 'OperationCrackdown.ps1'
$extensionSource = Join-Path (Split-Path $PSScriptRoot -Parent) 'browser-extension'
$extensionPath = Join-Path $installDirectory 'browser-extension'

if (-not (Test-Path -LiteralPath $configPath)) {
    throw 'This PC is not enrolled. Run Install.ps1 with a fresh enrollment code instead.'
}
if (-not (Test-Path -LiteralPath $agentSource)) {
    throw "Client source is missing: $agentSource"
}

$listener = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
foreach ($connection in @($listener)) {
    Stop-Process -Id $connection.OwningProcess -Force -ErrorAction SilentlyContinue
}
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    if (-not (Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 250
}
if (Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue) {
    throw 'The previous client process did not release local port 8765.'
}

Copy-Item -LiteralPath $agentSource -Destination $agentPath -Force
if (Test-Path -LiteralPath $extensionSource) {
    Copy-Item -LiteralPath $extensionSource -Destination $installDirectory -Recurse -Force
}
$startupLog = Join-Path $installDirectory 'startup-error.log'
Remove-Item -LiteralPath $startupLog -Force -ErrorAction SilentlyContinue

$taskName = 'Operation Crackdown Client'
$taskCommand = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agentPath`" -Mode Run"
schtasks.exe /Create /TN $taskName /SC ONLOGON /RL HIGHEST /TR $taskCommand /F | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to create the elevated Operation Crackdown scheduled task.' }
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Set-ScheduledTask -TaskName $taskName -Settings $taskSettings | Out-Null

schtasks.exe /Run /TN $taskName | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'The scheduled task was created but could not be started.' }

Start-Sleep -Seconds 8
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if ($task.State -ne 'Running') {
    $detail = if (Test-Path -LiteralPath $startupLog) { Get-Content -LiteralPath $startupLog -Raw } else { 'No startup error log was written.' }
    throw "The repaired task is not running (state: $($task.State)). $detail"
}

Write-Host 'Operation Crackdown repaired. Existing enrollment was preserved and the elevated client is running.'
if (Test-Path -LiteralPath $extensionPath) {
    Write-Host "For website auditing, load this unpacked extension in Edge or Chrome: $extensionPath"
}
Remove-Item -LiteralPath $repairLog -Force -ErrorAction SilentlyContinue
