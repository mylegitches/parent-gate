[CmdletBinding()]
param(
    [string]$StagingDirectory,
    [string]$ExpectedVersion,
    [int]$ParentProcessId,
    [string]$InstallDirectory = "$env:ProgramData\ParentGate",
    [switch]$EmergencyRestore
)

$ErrorActionPreference = 'Stop'
$taskName = 'ParentGate Client'
$statusPath = Join-Path $InstallDirectory 'status.json'
$logPath = Join-Path $InstallDirectory 'update-error.log'
$backupDirectory = Join-Path $InstallDirectory 'update-backup'
$files = @('ParentGate.ps1', 'ShowInternetNotice.ps1', 'ApplyUpdate.ps1')

function Start-ClientTask {
    Stop-ClientListener
    Start-Sleep -Milliseconds 400
    schtasks.exe /Run /TN $taskName | Out-Null
    if ($LASTEXITCODE -eq 0) { return }
    $agentPath = Join-Path $InstallDirectory 'ParentGate.ps1'
    Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agentPath`" -Mode Run" -WindowStyle Hidden | Out-Null
}

function Stop-ClientListener {
    foreach ($connection in @(Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $connection.OwningProcess -Force -ErrorAction SilentlyContinue
    }
}

function Restore-InternetState {
    $firewallStatePath = Join-Path $InstallDirectory 'internet-firewall-backup.json'
    $firewallState = if (Test-Path -LiteralPath $firewallStatePath) { Get-Content -LiteralPath $firewallStatePath -Raw | ConvertFrom-Json } else { $null }
    if ($firewallState) {
        $restoreErrors = New-Object Collections.Generic.List[string]
        foreach ($profile in @($firewallState.profiles)) {
            try {
                $saved = [string]$profile.defaultOutboundAction
                $action = if ($saved -eq 'Block') { 'Block' } elseif ($saved -eq 'Allow') { 'Allow' } else { 'NotConfigured' }
                Set-NetFirewallProfile -Name ([string]$profile.name) -DefaultOutboundAction $action -ErrorAction Stop
                if ($null -ne $profile.enabled) {
                    $savedEnabled = [string]$profile.enabled
                    $enabled = if ($savedEnabled -eq 'True') { 'True' } elseif ($savedEnabled -eq 'False') { 'False' } else { 'NotConfigured' }
                    Set-NetFirewallProfile -Name ([string]$profile.name) -Enabled $enabled -ErrorAction Stop
                }
            }
            catch { $restoreErrors.Add("Firewall profile $($profile.name): $($_.Exception.Message)") }
        }
        $ruleNames = @($firewallState.disabledAllowRules | Where-Object { $_ })
        if ($ruleNames.Count -gt 0) {
            try { Set-NetFirewallRule -PolicyStore PersistentStore -Name $ruleNames -Enabled True -ErrorAction Stop }
            catch {
                foreach ($name in $ruleNames) {
                    try { Set-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -Enabled True -ErrorAction Stop }
                    catch { $restoreErrors.Add("Firewall rule $name`: $($_.Exception.Message)") }
                }
            }
        }
        if ($restoreErrors.Count -gt 0) { throw "Emergency firewall restore was incomplete: $($restoreErrors -join '; ')" }
        Remove-Item -LiteralPath $firewallStatePath -Force
    }
    Get-NetFirewallRule -Group 'ParentGate Control Channel' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hostsPath) {
        $content = Get-Content -LiteralPath $hostsPath -Raw
        $clean = [regex]::Replace($content, '(?ms)^# BEGIN PARENTGATE.*?^# END PARENTGATE\s*', '').TrimEnd()
        $clean = [regex]::Replace($clean, '(?ms)^# BEGIN PG-DASHBOARD-PIN.*?^# END PG-DASHBOARD-PIN\s*', '').TrimEnd()
        Set-Content -LiteralPath $hostsPath -Value $clean -Encoding ASCII
        Clear-DnsClientCache -ErrorAction SilentlyContinue
    }
}

if ($EmergencyRestore) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Emergency restore requires administrator permission.'
    }
    schtasks.exe /Change /TN $taskName /Disable | Out-Null
    Stop-ClientListener
    Restore-InternetState
    Write-Host 'ParentGate enforcement is disabled and its firewall and hosts-file changes were restored.'
    Write-Host 'After restoring access in the dashboard, run Repair.ps1 as Administrator to re-enable the client.'
    exit 0
}

if ([string]::IsNullOrWhiteSpace($StagingDirectory) -or [string]::IsNullOrWhiteSpace($ExpectedVersion) -or $ParentProcessId -le 0) {
    throw 'StagingDirectory, ExpectedVersion, and ParentProcessId are required for a client update.'
}

try {
    Wait-Process -Id $ParentProcessId -Timeout 60 -ErrorAction SilentlyContinue
    if (Get-Process -Id $ParentProcessId -ErrorAction SilentlyContinue) {
        throw 'The previous client process did not stop for the update.'
    }

    New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
    foreach ($name in $files) {
        $source = Join-Path $StagingDirectory $name
        if (-not (Test-Path -LiteralPath $source)) { throw "The staged update is missing $name." }
        $installed = Join-Path $InstallDirectory $name
        if (Test-Path -LiteralPath $installed) {
            Copy-Item -LiteralPath $installed -Destination (Join-Path $backupDirectory $name) -Force
        }
        Copy-Item -LiteralPath $source -Destination $installed -Force
    }

    Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
    Start-ClientTask
    $healthy = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Seconds 1
        if (Test-Path -LiteralPath $statusPath) {
            try {
                $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
                if ([string]$status.clientVersion -eq $ExpectedVersion -and [string]$status.state -in @('applied', 'degraded')) {
                    $healthy = $true
                    break
                }
            }
            catch { }
        }
    }
    if (-not $healthy) { throw "Client $ExpectedVersion did not report healthy after the update." }
    Remove-Item -LiteralPath $StagingDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
catch {
    $failure = $_.Exception.ToString()
    Stop-ClientListener
    foreach ($name in $files) {
        $backup = Join-Path $backupDirectory $name
        if (Test-Path -LiteralPath $backup) {
            Copy-Item -LiteralPath $backup -Destination (Join-Path $InstallDirectory $name) -Force
        }
    }
    try { Start-ClientTask } catch { $failure += "`r`nRollback restart failed: $($_.Exception.Message)" }
    Set-Content -LiteralPath $logPath -Value "[$([DateTime]::UtcNow.ToString('o'))] $failure" -Encoding UTF8
    exit 1
}
