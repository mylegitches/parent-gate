[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [Parameter(Mandatory = $true)][string]$EnrollmentCode,
    [string]$DeviceName = $env:COMPUTERNAME
)

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell window (Run as administrator).'
}

$installDirectory = "$env:ProgramData\ParentGate"
$agentSource = Join-Path $PSScriptRoot 'ParentGate.ps1'
$agentPath = Join-Path $installDirectory 'ParentGate.ps1'
$noticeSource = Join-Path $PSScriptRoot 'ShowInternetNotice.ps1'
$noticePath = Join-Path $installDirectory 'ShowInternetNotice.ps1'
$updaterSource = Join-Path $PSScriptRoot 'ApplyUpdate.ps1'
$updaterPath = Join-Path $installDirectory 'ApplyUpdate.ps1'
$extensionSource = Join-Path (Split-Path $PSScriptRoot -Parent) 'browser-extension'
$extensionPath = Join-Path $installDirectory 'browser-extension'
New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
Copy-Item -LiteralPath $agentSource -Destination $agentPath -Force
if (Test-Path -LiteralPath $noticeSource) { Copy-Item -LiteralPath $noticeSource -Destination $noticePath -Force }
if (Test-Path -LiteralPath $updaterSource) { Copy-Item -LiteralPath $updaterSource -Destination $updaterPath -Force }
if (Test-Path -LiteralPath $extensionSource) {
    Copy-Item -LiteralPath $extensionSource -Destination $installDirectory -Recurse -Force
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $agentPath -Mode Enroll -ServerUrl $ServerUrl -EnrollmentCode $EnrollmentCode -DeviceName $DeviceName
if ($LASTEXITCODE -ne 0) { throw 'Device enrollment failed.' }

$listener = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
foreach ($connection in @($listener)) {
    Stop-Process -Id $connection.OwningProcess -Force -ErrorAction SilentlyContinue
}
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    if (-not (Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 250
}

$taskName = 'ParentGate Client'
$taskCommand = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agentPath`" -Mode Run"
schtasks.exe /Create /TN $taskName /SC ONLOGON /RL HIGHEST /TR $taskCommand /F | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to create the elevated ParentGate scheduled task.' }
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)
Set-ScheduledTask -TaskName $taskName -Settings $taskSettings | Out-Null

$desktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
$shortcutPath = Join-Path $desktop 'ParentGate Parent Override.url'
@"
[InternetShortcut]
URL=http://127.0.0.1:8765/
IconFile=$env:SystemRoot\System32\shell32.dll
IconIndex=47
"@ | Set-Content -LiteralPath $shortcutPath -Encoding ASCII

schtasks.exe /Run /TN $taskName | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'ParentGate was installed, but the scheduled task could not be started.' }
Write-Host 'ParentGate is installed. The local parent override shortcut is on the desktop.'
if (Test-Path -LiteralPath $extensionPath) {
    Write-Host "For website auditing, load this unpacked extension in Edge or Chrome: $extensionPath"
}
