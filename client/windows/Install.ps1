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

$installDirectory = "$env:ProgramData\OperationCrackdown"
$agentSource = Join-Path $PSScriptRoot 'OperationCrackdown.ps1'
$agentPath = Join-Path $installDirectory 'OperationCrackdown.ps1'
New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
Copy-Item -LiteralPath $agentSource -Destination $agentPath -Force

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $agentPath -Mode Enroll -ServerUrl $ServerUrl -EnrollmentCode $EnrollmentCode -DeviceName $DeviceName
if ($LASTEXITCODE -ne 0) { throw 'Device enrollment failed.' }

$taskName = 'Operation Crackdown Client'
$taskCommand = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agentPath`" -Mode Run"
schtasks.exe /Create /TN $taskName /SC ONLOGON /RL HIGHEST /TR $taskCommand /F | Out-Null

$desktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
$shortcutPath = Join-Path $desktop 'Operation Crackdown Parent Override.url'
@"
[InternetShortcut]
URL=http://127.0.0.1:8765/
IconFile=$env:SystemRoot\System32\shell32.dll
IconIndex=47
"@ | Set-Content -LiteralPath $shortcutPath -Encoding ASCII

schtasks.exe /Run /TN $taskName | Out-Null
Write-Host 'Operation Crackdown is installed. The local parent override shortcut is on the desktop.'

