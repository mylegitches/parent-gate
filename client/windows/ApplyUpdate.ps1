[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StagingDirectory,
    [Parameter(Mandatory = $true)][string]$ExpectedVersion,
    [Parameter(Mandatory = $true)][int]$ParentProcessId,
    [string]$InstallDirectory = "$env:ProgramData\OperationCrackdown"
)

$ErrorActionPreference = 'Stop'
$taskName = 'Operation Crackdown Client'
$statusPath = Join-Path $InstallDirectory 'status.json'
$logPath = Join-Path $InstallDirectory 'update-error.log'
$backupDirectory = Join-Path $InstallDirectory 'update-backup'
$files = @('OperationCrackdown.ps1', 'ShowInternetNotice.ps1', 'ApplyUpdate.ps1')

function Start-ClientTask {
    $agentPath = Join-Path $InstallDirectory 'OperationCrackdown.ps1'
    Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agentPath`" -Mode Run" -WindowStyle Hidden | Out-Null
}

function Stop-ClientListener {
    foreach ($connection in @(Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $connection.OwningProcess -Force -ErrorAction SilentlyContinue
    }
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
