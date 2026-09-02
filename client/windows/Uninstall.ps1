[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this uninstaller from an elevated PowerShell window (Run as administrator).'
}

$taskName = 'Operation Crackdown Client'
schtasks.exe /End /TN $taskName 2>$null | Out-Null
schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null

$installDirectory = "$env:ProgramData\OperationCrackdown"
$firewallStatePath = Join-Path $installDirectory 'internet-firewall-backup.json'
$firewallState = if (Test-Path -LiteralPath $firewallStatePath) { Get-Content -LiteralPath $firewallStatePath -Raw | ConvertFrom-Json } else { $null }
if ($firewallState) {
    foreach ($name in @($firewallState.disabledAllowRules)) {
        Set-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -Enabled True -ErrorAction Continue
    }
    foreach ($profile in @($firewallState.profiles)) {
        $saved = [string]$profile.defaultOutboundAction
        $action = if ($saved -eq 'Block') { 'Block' } elseif ($saved -eq 'Allow') { 'Allow' } else { 'NotConfigured' }
        Set-NetFirewallProfile -Name ([string]$profile.name) -DefaultOutboundAction $action
    }
}
Get-NetFirewallRule -Group 'Operation Crackdown Control Channel' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if (Test-Path -LiteralPath $hostsPath) {
    $content = Get-Content -LiteralPath $hostsPath -Raw
    $pattern = '(?ms)^# BEGIN OPERATION CRACKDOWN.*?^# END OPERATION CRACKDOWN\s*'
    $clean = [regex]::Replace($content, $pattern, '').TrimEnd()
    Set-Content -LiteralPath $hostsPath -Value $clean -Encoding ASCII
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

$shortcutPath = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Operation Crackdown Parent Override.url'
if (Test-Path -LiteralPath $shortcutPath) { Remove-Item -LiteralPath $shortcutPath -Force }
$recoveryShortcutPath = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Operation Crackdown Emergency Restore.cmd'
if (Test-Path -LiteralPath $recoveryShortcutPath) { Remove-Item -LiteralPath $recoveryShortcutPath -Force }

if (Test-Path -LiteralPath $installDirectory) { Remove-Item -LiteralPath $installDirectory -Recurse -Force }
Write-Host 'Operation Crackdown was removed. Its managed hosts entries were cleared.'
