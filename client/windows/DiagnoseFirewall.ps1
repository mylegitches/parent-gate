[CmdletBinding()]
param(
    [string]$OutputPath = "$env:ProgramData\OperationCrackdown\firewall-diagnostic.json"
)

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this diagnostic as Administrator.'
}

$report = [pscustomobject]@{
    capturedAt = [DateTime]::UtcNow.ToString('o')
    profiles = @(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
    connections = @(Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity)
    enabledOutboundAllowRuleCount = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue).Count
    controlRules = @(Get-NetFirewallRule -Group 'Operation Crackdown Control Channel' -ErrorAction SilentlyContinue | Select-Object Name, Enabled, Direction, Action, PrimaryStatus)
    firewallService = Get-Service MpsSvc | Select-Object Status, StartType
}

$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
