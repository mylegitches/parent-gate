[CmdletBinding()]
param(
    [ValidateSet('Run', 'Enroll')]
    [string]$Mode = 'Run',
    [string]$ServerUrl,
    [string]$EnrollmentCode,
    [string]$DeviceName = $env:COMPUTERNAME,
    [string]$DataDirectory = "$env:ProgramData\ParentGate",
    [string]$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
)

$ErrorActionPreference = 'Stop'
$script:ClientVersion = '0.3.11'
$script:ConfigPath = Join-Path $DataDirectory 'config.json'
$script:PolicyPath = Join-Path $DataDirectory 'policy.json'
$script:StatusPath = Join-Path $DataDirectory 'status.json'
$script:PendingPath = Join-Path $DataDirectory 'pending-operations.json'
$script:ApplicationEventsPath = Join-Path $DataDirectory 'pending-application-events.json'
$script:WebsiteEventsPath = Join-Path $DataDirectory 'pending-website-events.json'
$script:FirewallStatePath = Join-Path $DataDirectory 'internet-firewall-backup.json'
$script:InternetStatePath = Join-Path $DataDirectory 'internet-pause-state.json'
$script:NoticeMarkerPath = Join-Path $DataDirectory 'last-internet-notice.txt'
$script:NoticeScriptPath = Join-Path $DataDirectory 'ShowInternetNotice.ps1'
$script:UpdaterScriptPath = Join-Path $DataDirectory 'ApplyUpdate.ps1'
$script:FirewallRuleGroup = 'ParentGate Control Channel'
$script:LocalPort = 8765
$script:LatestPolicy = $null
$script:Credential = $null
$script:Config = $null
$script:LastError = $null
$script:NextEnforcement = [DateTime]::MinValue
$script:NextInternetEnforcement = [DateTime]::MinValue
$script:InternetPauseKnownDisabled = $false
$script:ObservedApplications = @{}
$script:ApplicationMonitorInitialized = $false
$script:UpdateStatus = 'current'
$script:LastScreenshotRequestId = $null

function Test-IsAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-PlainText {
    param([Security.SecureString]$SecureString)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Protect-Secret {
    param([string]$Value)
    return ConvertFrom-SecureString (ConvertTo-SecureString $Value -AsPlainText -Force)
}

function Unprotect-Secret {
    param([string]$Value)
    return ConvertTo-PlainText (ConvertTo-SecureString $Value)
}

function ConvertFrom-Base64Url {
    param([string]$Value)
    $normalized = $Value.Replace('-', '+').Replace('_', '/')
    switch ($normalized.Length % 4) {
        2 { $normalized += '==' }
        3 { $normalized += '=' }
    }
    return [Convert]::FromBase64String($normalized)
}

function Test-ConstantTimeEqual {
    param([byte[]]$Left, [byte[]]$Right)
    if ($Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ($Left[$index] -bxor $Right[$index])
    }
    return $difference -eq 0
}

function ConvertFrom-Hex {
    param([string]$Value)
    if ($Value.Length % 2 -ne 0) { throw 'Invalid hexadecimal value.' }
    $bytes = New-Object byte[] ($Value.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Value.Substring($index * 2, 2), 16)
    }
    return $bytes
}

function Test-UpdateManifestSignature {
    param($Manifest)
    if ([string]$Manifest.signatureAlgorithm -ne 'device-hmac-sha256') { return $false }
    $lines = New-Object Collections.Generic.List[string]
    $lines.Add([string]$Manifest.version)
    foreach ($file in @($Manifest.files)) {
        $lines.Add("$([string]$file.name)|$([string]$file.sha256)|$([string]$file.url)")
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $key = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($script:Credential)) }
    finally { $sha.Dispose() }
    $hmac = New-Object Security.Cryptography.HMACSHA256 (,$key)
    try { $actual = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))) }
    finally { $hmac.Dispose() }
    try { $expected = ConvertFrom-Hex ([string]$Manifest.signature) }
    catch { return $false }
    return Test-ConstantTimeEqual $actual $expected
}

function Start-ClientUpdate {
    $manifest = Invoke-ClientApi -Method GET -Path '/api/client/v1/update' -TimeoutSec 20
    if ($null -eq $manifest) {
        $script:UpdateStatus = 'current'
        return $false
    }
    try {
        $available = [version]([string]$manifest.version)
        $installed = [version]$script:ClientVersion
    }
    catch { throw 'The dashboard returned an invalid client update version.' }
    if ($available -le $installed) {
        $script:UpdateStatus = 'current'
        return $false
    }
    if (-not (Test-UpdateManifestSignature $manifest)) { throw 'Client update signature verification failed.' }
    if (-not (Test-Path -LiteralPath $script:UpdaterScriptPath)) { throw 'The installed update helper is missing.' }

    $stagingDirectory = Join-Path $DataDirectory "update-staging-$($manifest.version)"
    New-Item -ItemType Directory -Path $stagingDirectory -Force | Out-Null
    $headers = @{ Authorization = "Bearer $script:Credential" }
    foreach ($file in @($manifest.files)) {
        $name = [string]$file.name
        if ($name -notmatch '^[A-Za-z0-9.-]+$') { throw "Invalid update filename: $name" }
        $destination = Join-Path $stagingDirectory $name
        $uri = "$($script:Config.serverUrl.TrimEnd('/'))$([string]$file.url)"
        Invoke-WebRequest -Uri $uri -Method GET -Headers $headers -UseBasicParsing -TimeoutSec 30 -OutFile $destination
        $actualHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne ([string]$file.sha256).ToLowerInvariant()) { throw "Update file verification failed: $name" }
    }

    $script:UpdateStatus = "installing-$($manifest.version)"
    $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script:UpdaterScriptPath`" -StagingDirectory `"$stagingDirectory`" -ExpectedVersion `"$($manifest.version)`" -ParentProcessId $PID"
    Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -WindowStyle Hidden | Out-Null
    return $true
}

function Test-PinVerifier {
    param([string]$Pin, [string]$Verifier)
    try {
        $parts = $Verifier.Split('$')
        if ($parts.Length -ne 4 -or $parts[0] -ne 'pbkdf2-sha256') { return $false }
        $iterations = [int]$parts[1]
        $salt = ConvertFrom-Base64Url $parts[2]
        $expected = ConvertFrom-Base64Url $parts[3]
        $derive = [Security.Cryptography.Rfc2898DeriveBytes]::new(
            $Pin,
            $salt,
            $iterations,
            [Security.Cryptography.HashAlgorithmName]::SHA256
        )
        try { $actual = $derive.GetBytes($expected.Length) }
        finally { $derive.Dispose() }
        return Test-ConstantTimeEqual $actual $expected
    }
    catch { return $false }
}

function Save-JsonFile {
    param([string]$Path, $Value)
    $temporary = "$Path.tmp"
    ConvertTo-Json -InputObject $Value -Depth 100 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Read-JsonFile {
    param([string]$Path, $Fallback)
    if (-not (Test-Path -LiteralPath $Path)) { return $Fallback }
    try { return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
    catch { return $Fallback }
}

function Invoke-ClientApi {
    param(
        [ValidateSet('GET', 'POST')][string]$Method,
        [string]$Path,
        $Body = $null,
        [int]$TimeoutSec = 15,
        [switch]$AllowConflict
    )
    $headers = @{ Authorization = "Bearer $script:Credential" }
    $parameters = @{
        Uri = "$($script:Config.serverUrl.TrimEnd('/'))$Path"
        Method = $Method
        Headers = $headers
        UseBasicParsing = $true
        TimeoutSec = $TimeoutSec
    }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 100
    }
    try {
        $response = Invoke-WebRequest @parameters
        if ([string]::IsNullOrWhiteSpace($response.Content)) { return $null }
        return $response.Content | ConvertFrom-Json
    }
    catch {
        if ($AllowConflict -and $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 409) {
            $reader = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
            try { return @{ Conflict = $true; Body = ($reader.ReadToEnd() | ConvertFrom-Json) } }
            finally { $reader.Dispose() }
        }
        throw
    }
}

function Invoke-Enrollment {
    if ([string]::IsNullOrWhiteSpace($ServerUrl) -or [string]::IsNullOrWhiteSpace($EnrollmentCode)) {
        throw 'ServerUrl and EnrollmentCode are required for enrollment.'
    }
    New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
    $body = @{
        enrollmentCode = $EnrollmentCode.ToUpperInvariant()
        name = $DeviceName
        platform = 'windows'
        osVersion = [Environment]::OSVersion.VersionString
        clientVersion = $script:ClientVersion
        capabilities = @('process-enforcement', 'hosts-enforcement', 'target-scan', 'local-pin', 'internet-pause-message', 'self-update', 'desktop-screenshot')
    }
    $response = Invoke-RestMethod -Uri "$($ServerUrl.TrimEnd('/'))/api/client/v1/enroll" -Method Post -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 5) -TimeoutSec 20
    $config = @{
        serverUrl = $response.serverUrl.TrimEnd('/')
        deviceId = $response.deviceId
        credentialProtected = Protect-Secret $response.credential
        localPort = $script:LocalPort
    }
    Save-JsonFile $script:ConfigPath $config
    Write-Host "Enrolled $DeviceName as $($response.deviceId)."
}

function Get-PendingOperations {
    $value = Read-JsonFile $script:PendingPath @()
    if ($null -eq $value) { return @() }
    return @($value)
}

function Save-PendingOperations {
    param([array]$Operations)
    Save-JsonFile $script:PendingPath @($Operations)
}

function Sync-PendingOperations {
    $pending = @(Get-PendingOperations)
    if ($pending.Count -eq 0) { return $true }
    $remaining = New-Object Collections.Generic.List[object]
    foreach ($operation in $pending) {
        try {
            $result = Invoke-ClientApi -Method POST -Path '/api/client/v1/local-operations' -Body $operation -AllowConflict
            if ($result.Conflict) {
                $script:LatestPolicy = $result.Body.policy
                Save-JsonFile $script:PolicyPath $script:LatestPolicy
                $script:LastError = 'A newer dashboard change replaced a queued local override.'
            }
            elseif ($result.policy) {
                $script:LatestPolicy = $result.policy
                Save-JsonFile $script:PolicyPath $script:LatestPolicy
            }
        }
        catch {
            $remaining.Add($operation)
            $script:LastError = "Local override waiting to sync: $($_.Exception.Message)"
        }
    }
    Save-PendingOperations $remaining.ToArray()
    return $remaining.Count -eq 0
}

function Copy-Policy {
    param($Policy)
    return ($Policy | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
}

function Apply-OperationLocally {
    param($Policy, $Operation)
    $local = Copy-Policy $Policy
    $beforeOverride = Copy-Policy $Policy
    if ($Operation.targetType -eq 'master') {
        $local.masterEnabled = $Operation.action -eq 'enable'
        foreach ($service in @($local.services)) { $service.blocked = $local.masterEnabled -and $service.configuredBlocked }
        foreach ($target in @($local.customTargets)) { $target.blocked = $local.masterEnabled -and $target.configuredBlocked }
        foreach ($website in @($local.customWebsites)) { $website.blocked = $local.masterEnabled -and $website.configuredBlocked }
    }
    elseif ($Operation.targetType -eq 'internet') {
        $local.internetBlocked = $Operation.action -eq 'block'
        $local.internetMessage = if ($local.internetBlocked) { [string]$Operation.message } else { $null }
        $local.internetNoticeId = if ($local.internetBlocked) { [string]$Operation.operationId } else { $null }
    }
    elseif ($Operation.targetType -eq 'service') {
        foreach ($service in $local.services) {
            if ($service.id -eq $Operation.targetId) {
                $service.configuredBlocked = $Operation.action -eq 'block'
                $service.blocked = $local.masterEnabled -and $service.configuredBlocked
            }
        }
    }
    elseif ($Operation.targetType -eq 'target') {
        foreach ($target in @($local.customTargets)) {
            if ($target.key -eq $Operation.targetId) {
                $target.configuredBlocked = $Operation.action -eq 'block'
                $target.blocked = $local.masterEnabled -and $target.configuredBlocked
            }
        }
    }
    elseif ($Operation.targetType -eq 'website') {
        foreach ($website in @($local.customWebsites)) {
            if ($website.id -eq $Operation.targetId) {
                $website.configuredBlocked = $Operation.action -eq 'block'
                $website.blocked = $local.masterEnabled -and $website.configuredBlocked
            }
        }
    }
    $local.effectiveUntil = $Operation.effectiveUntil
    if ($Operation.effectiveUntil) {
        $local.nextExpiry = $Operation.effectiveUntil
        $local | Add-Member -NotePropertyName afterExpiry -NotePropertyValue $beforeOverride -Force
    }
    return $local
}

function Advance-ExpiredPolicy {
    param($Policy)
    $current = $Policy
    for ($index = 0; $index -lt 20; $index++) {
        if (-not $current.nextExpiry -or -not $current.afterExpiry) { break }
        $expires = [DateTime]::Parse([string]$current.nextExpiry).ToUniversalTime()
        if ($expires -gt [DateTime]::UtcNow) { break }
        $current = $current.afterExpiry
    }
    return $current
}

function Get-BlockedExecutables {
    param($Policy)
    $names = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $paths = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($service in @($Policy.services)) {
        if ($service.blocked) {
            foreach ($name in @($service.windows.processes)) { [void]$names.Add([IO.Path]::GetFileNameWithoutExtension([string]$name)) }
        }
    }
    foreach ($target in @($Policy.customTargets)) {
        if (-not $target.blocked -or -not $target.mapping) { continue }
        foreach ($name in @($target.mapping.processes)) { [void]$names.Add([IO.Path]::GetFileNameWithoutExtension([string]$name)) }
        foreach ($path in @($target.mapping.paths)) {
            $clean = [string]$path
            if (-not [string]::IsNullOrWhiteSpace($clean)) { [void]$paths.Add($clean) }
        }
    }
    return @{ Names = @($names); Paths = @($paths) }
}

function Test-ProtectedProcess {
    param($Process)
    $protectedNames = @('csrss', 'smss', 'wininit', 'services', 'lsass', 'svchost', 'explorer', 'powershell', 'pwsh', 'conhost', 'parentgate')
    if ($Process.Id -eq $PID) { return $true }
    if ($Process.ProcessName -in $protectedNames) { return $true }
    try {
        $path = [string]$Process.Path
        if ($path -and ($path -match '(?i)\\ParentGate\\|\\Windows\\System32\\|\\Windows\\SysWOW64\\')) { return $true }
        $command = [string]$Process.CommandLine
        if ($command -and $command -match '(?i)ParentGate\.ps1') { return $true }
    }
    catch { }
    return $false
}

function Stop-BlockedExecutables {
    param($Policy)
    $blocked = Get-BlockedExecutables $Policy
    $errors = New-Object Collections.Generic.List[string]
    $nameSet = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($blocked.Names)) { [void]$nameSet.Add($name) }
    $pathSet = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in @($blocked.Paths)) { [void]$pathSet.Add($path) }
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
        if (Test-ProtectedProcess $process) { continue }
        $path = $null
        try { $path = [string]$process.Path } catch { $path = $null }
        $matchName = $nameSet.Contains($process.ProcessName)
        $matchPath = $path -and $pathSet.Contains($path)
        if (-not $matchName -and -not $matchPath) { continue }
        try { Stop-Process -Id $process.Id -Force -ErrorAction Stop }
        catch { $errors.Add("Unable to close $($process.ProcessName)") }
    }
    if ($pathSet.Count -gt 0) {
        foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
            if ([int]$process.ProcessId -eq $PID) { continue }
            $executable = [string]$process.ExecutablePath
            $command = [string]$process.CommandLine
            if ($command -match '(?i)ParentGate\.ps1') { continue }
            if (-not $executable -or -not $pathSet.Contains($executable)) { continue }
            try { Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction Stop }
            catch { $errors.Add("Unable to close $executable") }
        }
    }
    return $errors
}

function Get-BlockedDomains {
    param($Policy)
    $domains = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $controlHost = ([Uri]$script:Config.serverUrl).DnsSafeHost
    foreach ($service in @($Policy.services)) {
        if (-not $service.blocked) { continue }
        foreach ($domain in @($service.windows.domains)) {
            $clean = ([string]$domain).Trim().TrimStart('.').ToLowerInvariant()
            if (-not $clean) { continue }
            if ($clean -eq $controlHost -or $controlHost.EndsWith(".$clean")) { continue }
            [void]$domains.Add($clean)
        }
    }
    foreach ($website in @($Policy.customWebsites)) {
        if (-not $website.blocked) { continue }
        $clean = ([string]$website.domain).Trim().TrimStart('.').ToLowerInvariant()
        if (-not $clean) { continue }
        if ($clean -eq $controlHost -or $controlHost.EndsWith(".$clean")) { continue }
        [void]$domains.Add($clean)
    }
    return @($domains | Sort-Object)
}

function Set-ManagedHosts {
    param([string[]]$Domains)
    $hostsPath = $HostsPath
    $begin = '# BEGIN PARENTGATE'
    $end = '# END PARENTGATE'
    $content = if (Test-Path -LiteralPath $hostsPath) { Get-Content -LiteralPath $hostsPath -Raw } else { '' }
    # Get-Content -Raw returns $null for an existing empty file. Regex.Replace
    # requires a string, so normalize empty hosts files before removing our block.
    if ($null -eq $content) { $content = '' }
    $pattern = '(?ms)^' + [regex]::Escape($begin) + '.*?^' + [regex]::Escape($end) + '\s*'
    $clean = [regex]::Replace($content, $pattern, '').TrimEnd()
    $lines = New-Object Collections.Generic.List[string]
    $lines.Add($clean)
    if ($Domains.Count -gt 0) {
        $lines.Add('')
        $lines.Add($begin)
        foreach ($domain in $Domains) {
            $lines.Add("0.0.0.0 $domain")
            $lines.Add(":: $domain")
        }
        $lines.Add($end)
    }
    $desired = $lines -join [Environment]::NewLine
    if ($content -eq $desired) { return }

    $lastWriteError = $null
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            [IO.File]::WriteAllText($hostsPath, $desired, [Text.Encoding]::ASCII)
            $lastWriteError = $null
            break
        }
        catch [IO.IOException] {
            $lastWriteError = $_
            Start-Sleep -Milliseconds 200
        }
    }
    if ($lastWriteError) { throw $lastWriteError }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

function Get-ControlChannelPrograms {
    $programs = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    [void]$programs.Add((Join-Path $PSHOME 'powershell.exe'))
    $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if ($pwsh -and $pwsh.Source) { [void]$programs.Add([string]$pwsh.Source) }
    try {
        $self = [string](Get-Process -Id $PID -ErrorAction Stop).Path
        if ($self) { [void]$programs.Add($self) }
    }
    catch { }
    return @($programs)
}

function Get-ControlEndpoint {
    param(
        [string[]]$FallbackAddresses = @(),
        [int]$FallbackPort = 0
    )
    $uri = [Uri]$script:Config.serverUrl
    $port = if (-not $uri.IsDefaultPort) { $uri.Port } elseif ($uri.Scheme -eq 'https') { 443 } else { 80 }
    $addresses = New-Object Collections.Generic.List[string]
    try {
        if ($uri.HostNameType -eq [UriHostNameType]::IPv4 -or $uri.HostNameType -eq [UriHostNameType]::IPv6) {
            $addresses.Add($uri.Host)
        }
        else {
            foreach ($address in [Net.Dns]::GetHostAddresses($uri.Host)) { $addresses.Add($address.IPAddressToString) }
        }
    }
    catch {
        foreach ($address in @($FallbackAddresses)) {
            if (-not [string]::IsNullOrWhiteSpace($address)) { $addresses.Add($address) }
        }
        if ($addresses.Count -eq 0) { throw }
        if ($FallbackPort -gt 0) { $port = $FallbackPort }
    }
    if ($addresses.Count -eq 0) { throw "Unable to resolve dashboard host $($uri.Host)." }
    $unique = @($addresses | Sort-Object -Unique)
    $ordered = @($unique | Where-Object { $_ -notmatch ':' }) + @($unique | Where-Object { $_ -match ':' })
    return @{ Port = $port; Addresses = $ordered; Host = $uri.DnsSafeHost; HostIsName = -not ($uri.HostNameType -eq [UriHostNameType]::IPv4 -or $uri.HostNameType -eq [UriHostNameType]::IPv6) }
}

function Remove-ControlFirewallRules {
    Get-NetFirewallRule -Group $script:FirewallRuleGroup -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

function Get-RestoredOutboundAction {
    param([string]$Value)
    if ($Value -eq 'Block') { return 'Block' }
    if ($Value -eq 'Allow') { return 'Allow' }
    return 'NotConfigured'
}

function Get-RestoredProfileEnabled {
    param([string]$Value)
    if ($Value -eq 'True') { return 'True' }
    if ($Value -eq 'False') { return 'False' }
    return 'NotConfigured'
}

function Set-HostsSection {
    param([string]$Begin, [string]$End, [string[]]$Lines)
    $hostsPath = $HostsPath
    $content = if (Test-Path -LiteralPath $hostsPath) { Get-Content -LiteralPath $hostsPath -Raw } else { '' }
    if ($null -eq $content) { $content = '' }
    $pattern = '(?ms)^' + [regex]::Escape($Begin) + '.*?^' + [regex]::Escape($End) + '\s*'
    $clean = [regex]::Replace($content, $pattern, '').TrimEnd()
    $output = New-Object Collections.Generic.List[string]
    $output.Add($clean)
    if ($Lines.Count -gt 0) {
        $output.Add('')
        $output.Add($Begin)
        foreach ($line in $Lines) { $output.Add($line) }
        $output.Add($End)
    }
    $desired = $output -join [Environment]::NewLine
    if ($content -eq $desired) { return }
    [IO.File]::WriteAllText($hostsPath, $desired, [Text.Encoding]::ASCII)
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

function Set-ControlDashboardPin {
    param($Endpoint)
    $begin = '# BEGIN PG-DASHBOARD-PIN'
    $end = '# END PG-DASHBOARD-PIN'
    if (-not $Endpoint.HostIsName) {
        Set-HostsSection -Begin $begin -End $end -Lines @()
        return
    }
    $ip = @($Endpoint.Addresses | Where-Object { $_ -notmatch ':' }) | Select-Object -First 1
    if (-not $ip) { $ip = @($Endpoint.Addresses) | Select-Object -First 1 }
    if (-not $ip) { return }
    Set-HostsSection -Begin $begin -End $end -Lines @("$ip $($Endpoint.Host)")
}

function Clear-ControlDashboardPin {
    Set-HostsSection -Begin '# BEGIN PG-DASHBOARD-PIN' -End '# END PG-DASHBOARD-PIN' -Lines @()
}

function Test-ControlChannel {
    param([int]$TimeoutSec = 15)
    $base = $script:Config.serverUrl.TrimEnd('/')
    Invoke-WebRequest -Uri "$base/healthz" -UseBasicParsing -TimeoutSec $TimeoutSec | Out-Null
    if ($script:Credential) {
        Invoke-ClientApi -Method GET -Path '/api/client/v1/policy' -TimeoutSec $TimeoutSec | Out-Null
    }
}
function Restore-FirewallProfilesFromState {
    param($State, $ErrorList)
    foreach ($profile in @($State.profiles)) {
        try {
            $action = Get-RestoredOutboundAction ([string]$profile.defaultOutboundAction)
            Set-NetFirewallProfile -Name ([string]$profile.name) -DefaultOutboundAction $action -ErrorAction Stop
            if ($null -ne $profile.enabled) {
                $enabled = Get-RestoredProfileEnabled ([string]$profile.enabled)
                Set-NetFirewallProfile -Name ([string]$profile.name) -Enabled $enabled -ErrorAction Stop
            }
        }
        catch { $ErrorList.Add("Firewall profile $($profile.name): $($_.Exception.Message)") }
    }
}

function Restore-DisabledAllowRules {
    param($Names, $ErrorList)
    $ruleNames = @($Names | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    if ($ruleNames.Count -eq 0) { return }
    try {
        Set-NetFirewallRule -PolicyStore PersistentStore -Name $ruleNames -Enabled True -ErrorAction Stop
    }
    catch {
        foreach ($name in $ruleNames) {
            try { Set-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -Enabled True -ErrorAction Stop }
            catch { $ErrorList.Add("Firewall rule $name`: $($_.Exception.Message)") }
        }
    }
}

function Enable-InternetPause {
    if (-not (Test-IsAdministrator)) { throw 'Internet pause requires an elevated client.' }
    $refreshing = Test-Path -LiteralPath $script:FirewallStatePath
    $state = Read-JsonFile $script:FirewallStatePath $null
    if (-not $state) {
        $profiles = @(Get-NetFirewallProfile | ForEach-Object {
            @{ name = [string]$_.Name; enabled = [string]$_.Enabled; defaultOutboundAction = [string]$_.DefaultOutboundAction }
        })
        $state = @{ profiles = $profiles; controlAddresses = @(); controlPort = 0; disabledAllowRules = @() }
        Save-JsonFile $script:FirewallStatePath $state
    }
    try {
        $endpoint = Get-ControlEndpoint -FallbackAddresses @($state.controlAddresses) -FallbackPort ([int]$state.controlPort)
        Set-ControlDashboardPin $endpoint
        $addressKey = (@($endpoint.Addresses) -join ',')
        $existingKey = (@($state.controlAddresses) -join ',')
        $ruleCount = @(Get-NetFirewallRule -Group $script:FirewallRuleGroup -ErrorAction SilentlyContinue).Count
        if ($addressKey -ne $existingKey -or [int]$state.controlPort -ne [int]$endpoint.Port -or $ruleCount -eq 0) {
            Remove-ControlFirewallRules
            $sharedProxyPort = [int]$endpoint.Port -in @(80, 443)
            if (-not $sharedProxyPort) {
                New-NetFirewallRule -DisplayName 'ParentGate dashboard destination' -Group $script:FirewallRuleGroup -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $endpoint.Addresses -RemotePort $endpoint.Port -Profile Any | Out-Null
            }
            $index = 0
            foreach ($program in @(Get-ControlChannelPrograms)) {
                $index += 1
                New-NetFirewallRule -DisplayName "ParentGate dashboard access $index" -Group $script:FirewallRuleGroup -Direction Outbound -Action Allow -Program $program -Protocol TCP -RemoteAddress $endpoint.Addresses -RemotePort $endpoint.Port -Profile Any | Out-Null
            }
            New-NetFirewallRule -DisplayName 'ParentGate DNS (UDP)' -Group $script:FirewallRuleGroup -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName 'ParentGate DNS (TCP)' -Group $script:FirewallRuleGroup -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53 -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName 'ParentGate DHCP (IPv4)' -Group $script:FirewallRuleGroup -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName 'ParentGate DHCP (IPv6)' -Group $script:FirewallRuleGroup -Direction Outbound -Action Allow -Protocol UDP -LocalPort 546 -RemotePort 547 -Profile Any | Out-Null
            $state.controlAddresses = @($endpoint.Addresses)
            $state.controlPort = [int]$endpoint.Port
            Save-JsonFile $script:FirewallStatePath $state
        }

        $alreadyDisabled = @($state.disabledAllowRules)
        if (-not $refreshing) {
            $enabledAllowRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow -Enabled True -ErrorAction Stop |
                Where-Object { $_.Group -ne $script:FirewallRuleGroup })
            $newRuleNames = @($enabledAllowRules.Name | Where-Object { $_ -notin $alreadyDisabled } | Sort-Object -Unique)
            if ($newRuleNames.Count -gt 0) {
                $state.disabledAllowRules = @($alreadyDisabled + $newRuleNames | Sort-Object -Unique)
                Save-JsonFile $script:FirewallStatePath $state
            }
        }
        else {
            $newRuleNames = @()
        }

        foreach ($profile in Get-NetFirewallProfile) {
            if ([string]$profile.Enabled -ne 'True' -or [string]$profile.DefaultOutboundAction -ne 'Block') {
                Set-NetFirewallProfile -Name $profile.Name -Enabled True -DefaultOutboundAction Block -ErrorAction Stop
            }
        }
        if ($newRuleNames.Count -gt 0) {
            Set-NetFirewallRule -PolicyStore PersistentStore -Name $newRuleNames -Enabled False -ErrorAction Stop
        }

        Test-ControlChannel -TimeoutSec 8
    }
    catch {
        $pauseError = $_.Exception.Message
        if ($refreshing) {
            throw "Internet pause remains active, but the control channel needs another try: $pauseError"
        }
        try { Disable-InternetPause }
        catch { throw "Internet pause failed ($pauseError) and rollback was incomplete: $($_.Exception.Message)" }
        throw "Internet pause was safely rolled back: $pauseError"
    }
    $script:InternetPauseKnownDisabled = $false
}

function Disable-InternetPause {
    $state = Read-JsonFile $script:FirewallStatePath $null
    if ($state) {
        $restoreErrors = New-Object Collections.Generic.List[string]
        Restore-FirewallProfilesFromState $state $restoreErrors
        Remove-ControlFirewallRules
        try { Clear-ControlDashboardPin } catch { $restoreErrors.Add("Dashboard host pin: $($_.Exception.Message)") }
        Restore-DisabledAllowRules @($state.disabledAllowRules) $restoreErrors
        if ($restoreErrors.Count -gt 0) { throw "Internet restore was incomplete: $($restoreErrors -join '; ')" }
        Remove-Item -LiteralPath $script:FirewallStatePath -Force -ErrorAction SilentlyContinue
    }
    elseif (-not $script:InternetPauseKnownDisabled) {
        Remove-ControlFirewallRules
        Clear-ControlDashboardPin
    }
    $script:InternetPauseKnownDisabled = $true
}

function Ensure-EmergencyRestoreShortcut {
    $desktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
    if ([string]::IsNullOrWhiteSpace($desktop)) { return }
    $shortcutPath = Join-Path $desktop 'ParentGate Emergency Restore.cmd'
    $command = '@echo off' + "`r`n" + 'powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList ''-NoProfile -NoExit -ExecutionPolicy Bypass -File ""C:\ProgramData\ParentGate\ApplyUpdate.ps1"" -EmergencyRestore''"'
    if (-not (Test-Path -LiteralPath $shortcutPath) -or (Get-Content -LiteralPath $shortcutPath -Raw) -ne $command) {
        Set-Content -LiteralPath $shortcutPath -Value $command -Encoding ASCII -NoNewline
    }
}

function Update-InternetNotice {
    param($Policy)
    $blocked = [bool]$Policy.internetBlocked
    $noticeId = if ($blocked) { [string]$Policy.internetNoticeId } else { '' }
    $message = if ($blocked -and -not [string]::IsNullOrWhiteSpace([string]$Policy.internetMessage)) { [string]$Policy.internetMessage } else { 'Internet access is paused.' }
    $desired = @{ internetBlocked = $blocked; noticeId = $noticeId; message = $message }
    $current = Read-JsonFile $script:InternetStatePath $null
    if (-not $current -or [bool]$current.internetBlocked -ne $blocked -or [string]$current.noticeId -ne $noticeId -or [string]$current.message -ne $message) {
        Save-JsonFile $script:InternetStatePath $desired
    }
    if (-not $blocked) { return }
    $lastNotice = if (Test-Path -LiteralPath $script:NoticeMarkerPath) { (Get-Content -LiteralPath $script:NoticeMarkerPath -Raw).Trim() } else { '' }
    if ($lastNotice -eq $noticeId) { return }
    Set-Content -LiteralPath $script:NoticeMarkerPath -Value $noticeId -Encoding ASCII
    if (Test-Path -LiteralPath $script:NoticeScriptPath) {
        $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script:NoticeScriptPath`" -StatePath `"$script:InternetStatePath`" -NoticeId `"$noticeId`""
        Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -WindowStyle Hidden | Out-Null
    }
    else {
        Start-Process -FilePath 'msg.exe' -ArgumentList @('*', '/TIME:120', "Internet paused: $message") -WindowStyle Hidden | Out-Null
    }
}

function Apply-Policy {
    param($Policy)
    $errors = New-Object Collections.Generic.List[string]
    $blocked = Get-BlockedExecutables $Policy
    foreach ($errorMessage in @(Stop-BlockedExecutables $Policy)) { $errors.Add($errorMessage) }
    try { Set-ManagedHosts @(Get-BlockedDomains $Policy) }
    catch { $errors.Add("Website enforcement failed: $($_.Exception.Message)") }
    try { Update-InternetNotice $Policy }
    catch { $errors.Add("Internet pause message failed: $($_.Exception.Message)") }
    try {
        if ($Policy.internetBlocked) {
            if ([DateTime]::UtcNow -ge $script:NextInternetEnforcement) {
                Enable-InternetPause
                $script:NextInternetEnforcement = [DateTime]::UtcNow.AddMinutes(1)
            }
        }
        else {
            Disable-InternetPause
            $script:NextInternetEnforcement = [DateTime]::MinValue
        }
    }
    catch { $errors.Add("Internet pause enforcement failed: $($_.Exception.Message)") }
    $script:NextEnforcement = [DateTime]::UtcNow.AddSeconds(2)
    $status = @{
        state = if ($errors.Count -eq 0) { 'applied' } else { 'degraded' }
        profile = $Policy.profile
        blockedProcesses = @($blocked.Names)
        blockedPaths = @($blocked.Paths)
        errors = $errors.ToArray()
        elevated = Test-IsAdministrator
        localPort = $script:LocalPort
        pendingLocalOperations = @(Get-PendingOperations).Count
        pendingApplicationEvents = @(Get-PendingApplicationEvents).Count
        pendingWebsiteEvents = @(Get-PendingWebsiteEvents).Count
        internetBlocked = [bool]$Policy.internetBlocked
        clientVersion = $script:ClientVersion
        updateStatus = $script:UpdateStatus
    }
    Save-JsonFile $script:StatusPath $status
    return $status
}

function Capture-DesktopJpeg {
    param([string]$Path)
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $bounds = [Windows.Forms.SystemInformation]::VirtualScreen
    if ($bounds.Width -lt 1 -or $bounds.Height -lt 1) { throw 'The desktop size could not be read.' }
    $bitmap = New-Object Drawing.Bitmap $bounds.Width, $bounds.Height
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.Size)
    }
    finally { $graphics.Dispose() }
    $output = $bitmap
    $maxWidth = 1920
    if ($bitmap.Width -gt $maxWidth) {
        $height = [Math]::Max(1, [int]($bitmap.Height * ($maxWidth / $bitmap.Width)))
        $output = New-Object Drawing.Bitmap $maxWidth, $height
        $scale = [Drawing.Graphics]::FromImage($output)
        try {
            $scale.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $scale.DrawImage($bitmap, 0, 0, $maxWidth, $height)
        }
        finally { $scale.Dispose() }
        $bitmap.Dispose()
    }
    try {
        $codec = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
        $parameters = New-Object Drawing.Imaging.EncoderParameters 1
        $parameters.Param[0] = New-Object Drawing.Imaging.EncoderParameter ([Drawing.Imaging.Encoder]::Quality, [long]70)
        $output.Save($Path, $codec, $parameters)
    }
    finally { $output.Dispose() }
}

function Send-ScreenshotResult {
    param(
        [string]$RequestId,
        [string]$Path = $null,
        [string]$ErrorMessage = $null
    )
    $headers = @{
        Authorization = "Bearer $script:Credential"
        'X-Screenshot-Request-Id' = $RequestId
    }
    $parameters = @{
        Uri = "$($script:Config.serverUrl.TrimEnd('/'))/api/client/v1/screenshot"
        Method = 'POST'
        Headers = $headers
        UseBasicParsing = $true
        TimeoutSec = 30
    }
    if ($ErrorMessage) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = (@{ requestId = $RequestId; error = $ErrorMessage } | ConvertTo-Json -Compress)
    }
    else {
        $parameters.ContentType = 'image/jpeg'
        $parameters.InFile = $Path
    }
    Invoke-WebRequest @parameters | Out-Null
}

function Sync-DesktopScreenshot {
    param($Policy)
    $requestId = [string]$Policy.screenshotRequestId
    if ([string]::IsNullOrWhiteSpace($requestId) -or $requestId -eq $script:LastScreenshotRequestId) { return }
    $path = Join-Path $DataDirectory 'latest-screenshot.jpg'
    try {
        Capture-DesktopJpeg -Path $path
        Send-ScreenshotResult -RequestId $requestId -Path $path
        $script:LastScreenshotRequestId = $requestId
    }
    catch {
        $message = $_.Exception.Message
        try { Send-ScreenshotResult -RequestId $requestId -ErrorMessage $message } catch { }
        $script:LastScreenshotRequestId = $requestId
        $script:LastError = "Screenshot upload failed: $message"
    }
    finally {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function Send-Status {
    param($Policy, $Status)
    try {
        Invoke-ClientApi -Method POST -Path '/api/client/v1/status' -Body @{
            appliedRevision = [int]$Policy.revision
            clientVersion = $script:ClientVersion
            osVersion = [Environment]::OSVersion.VersionString
            capabilities = @('process-enforcement', 'hosts-enforcement', 'target-scan', 'local-pin', 'internet-pause-message', 'self-update', 'desktop-screenshot')
            status = $Status
        } | Out-Null
    }
    catch { $script:LastError = "Status update failed: $($_.Exception.Message)" }
}

function Get-VisibleApplications {
    $excluded = @('explorer', 'taskmgr', 'powershell', 'pwsh', 'conhost', 'textinputhost', 'searchhost', 'shellexperiencehost', 'systemsettings', 'parentgate')
    $communicationPattern = '(?i)discord|slack|teams|zoom|skype|telegram|signal|whatsapp|messenger|webex|wechat|line'
    $streamingPattern = '(?i)netflix|hulu|paramount|discovery|youtube|twitch|spotify|plex|primevideo|disney'
    $gamingPattern = '(?i)roblox|minecraft|fortnite|steam|epicgames|riotclient|league of legends|valorant'
    $applications = New-Object Collections.Generic.List[object]
    foreach ($process in Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.ProcessName -notin $excluded }) {
        $displayName = $process.ProcessName
        try {
            if ($process.MainModule.FileVersionInfo.ProductName) { $displayName = $process.MainModule.FileVersionInfo.ProductName }
        }
        catch { }
        $combined = "$($process.ProcessName) $displayName"
        $category = if ($combined -match $communicationPattern) { 'communication' } elseif ($combined -match $streamingPattern) { 'streaming' } elseif ($combined -match $gamingPattern) { 'gaming' } else { 'unknown' }
        $processFile = "$($process.ProcessName).exe"
        $startedAt = try { $process.StartTime.ToUniversalTime().ToString('o') } catch { [DateTime]::UtcNow.ToString('o') }
        $applications.Add(@{
            key = "process:$($processFile.ToLowerInvariant())"
            displayName = $displayName
            categoryGuess = $category
            processFile = $processFile
            startedAt = $startedAt
        })
    }
    return $applications.ToArray()
}

function Get-ApplicationTargets {
    $targets = foreach ($application in @(Get-VisibleApplications)) {
        @{
            key = $application.key
            displayName = $application.displayName
            kind = 'application'
            categoryGuess = $application.categoryGuess
            source = 'windows-running-scan'
            currentlyRunning = $true
            mapping = @{ processes = @($application.processFile) }
        }
    }
    return @($targets | Sort-Object key -Unique)
}

function Send-Targets {
    try { Invoke-ClientApi -Method POST -Path '/api/client/v1/targets' -Body @{ targets = @(Get-ApplicationTargets) } | Out-Null }
    catch { $script:LastError = "Application scan upload failed: $($_.Exception.Message)" }
}

function Get-PendingApplicationEvents {
    $value = Read-JsonFile $script:ApplicationEventsPath @()
    if ($null -eq $value) { return @() }
    return @($value)
}

function Save-PendingApplicationEvents {
    param([array]$Events)
    Save-JsonFile $script:ApplicationEventsPath @($Events | Select-Object -Last 10000)
}

function Add-ApplicationEvent {
    param($Application, [ValidateSet('started', 'stopped')][string]$EventType, [string]$OccurredAt)
    $pending = @(Get-PendingApplicationEvents)
    $pending += @{
        id = [Guid]::NewGuid().ToString()
        targetKey = $Application.key
        displayName = $Application.displayName
        categoryGuess = $Application.categoryGuess
        eventType = $EventType
        occurredAt = $OccurredAt
    }
    Save-PendingApplicationEvents $pending
}

function Update-ApplicationActivity {
    $current = @{}
    foreach ($application in @(Get-VisibleApplications)) {
        if (-not $current.ContainsKey($application.key)) {
            $current[$application.key] = $application
            continue
        }
        if ([DateTime]::Parse([string]$application.startedAt) -lt [DateTime]::Parse([string]$current[$application.key].startedAt)) {
            $current[$application.key] = $application
        }
    }

    foreach ($key in $current.Keys) {
        if (-not $script:ObservedApplications.ContainsKey($key)) {
            Add-ApplicationEvent $current[$key] 'started' $current[$key].startedAt
        }
    }
    if ($script:ApplicationMonitorInitialized) {
        foreach ($key in $script:ObservedApplications.Keys) {
            if (-not $current.ContainsKey($key)) {
                Add-ApplicationEvent $script:ObservedApplications[$key] 'stopped' ([DateTime]::UtcNow.ToString('o'))
            }
        }
    }
    $script:ObservedApplications = $current
    $script:ApplicationMonitorInitialized = $true
}

function Sync-ApplicationEvents {
    $pending = @(Get-PendingApplicationEvents)
    if ($pending.Count -eq 0) { return }
    $batch = @($pending | Select-Object -First 500)
    try {
        Invoke-ClientApi -Method POST -Path '/api/client/v1/application-events' -Body @{ events = $batch } -TimeoutSec 5 | Out-Null
        Save-PendingApplicationEvents @($pending | Select-Object -Skip $batch.Count)
    }
    catch { $script:LastError = "Application activity waiting to sync: $($_.Exception.Message)" }
}

function Get-PendingWebsiteEvents {
    $value = Read-JsonFile $script:WebsiteEventsPath @()
    if ($null -eq $value) { return @() }
    return @($value)
}

function Save-PendingWebsiteEvents {
    param([array]$Events)
    Save-JsonFile $script:WebsiteEventsPath @($Events | Select-Object -Last 10000)
}

function Add-WebsiteEvent {
    param([string]$Id, [string]$Domain, [string]$Browser, [string]$OccurredAt)
    $clean = $Domain.Trim().TrimStart('.').ToLowerInvariant()
    if (-not $clean -or $clean.Length -gt 253 -or $clean -notmatch '^[a-z0-9.-]+$' -or -not $clean.Contains('.')) {
        throw 'Invalid website hostname.'
    }
    $timestamp = [DateTime]::Parse($OccurredAt).ToUniversalTime().ToString('o')
    $pending = @(Get-PendingWebsiteEvents)
    $eventId = if ($Id -match '^[0-9a-f-]{36}$') { $Id } else { [Guid]::NewGuid().ToString() }
    if ($pending | Where-Object { $_.id -eq $eventId }) { return }
    $pending += @{
        id = $eventId
        domain = $clean
        browser = if ([string]::IsNullOrWhiteSpace($Browser)) { 'browser' } else { $Browser.Substring(0, [Math]::Min(40, $Browser.Length)) }
        occurredAt = $timestamp
    }
    Save-PendingWebsiteEvents $pending
}

function Sync-WebsiteEvents {
    $pending = @(Get-PendingWebsiteEvents)
    if ($pending.Count -eq 0) { return }
    $batch = @($pending | Select-Object -First 500)
    try {
        Invoke-ClientApi -Method POST -Path '/api/client/v1/website-events' -Body @{ events = $batch } -TimeoutSec 5 | Out-Null
        Save-PendingWebsiteEvents @($pending | Select-Object -Skip $batch.Count)
    }
    catch { $script:LastError = "Website activity waiting to sync: $($_.Exception.Message)" }
}

function HtmlEncode {
    param([string]$Value)
    Add-Type -AssemblyName System.Web
    return [Web.HttpUtility]::HtmlEncode($Value)
}

function Get-LocalPage {
    $policy = $script:LatestPolicy
    $masterState = if ($policy -and $policy.masterEnabled) { 'On' } elseif ($policy) { 'Off' } else { 'Unavailable' }
    $controls = "<option value='master|blocking|enable'>Turn master blocking on</option><option value='master|blocking|disable'>Turn master blocking off</option>"
    if ($policy -and $policy.internetBlocked) { $controls = "<option value='internet|access|allow'>Restore internet access</option>$controls" }
    if ($policy) {
        foreach ($service in @($policy.services)) {
            $state = if ($service.configuredBlocked) { 'Selected to block' } else { 'Allowed' }
            $serviceId = HtmlEncode ([string]$service.id)
            $name = HtmlEncode ([string]$service.displayName)
            $controls += "<option value='service|$serviceId'>$name ($state)</option>"
        }
        foreach ($website in @($policy.customWebsites)) {
            $state = if ($website.configuredBlocked) { 'Selected to block' } else { 'Allowed' }
            $websiteId = HtmlEncode ([string]$website.id)
            $name = HtmlEncode ([string]$website.displayName)
            $controls += "<option value='website|$websiteId'>$name ($state)</option>"
        }
        foreach ($target in @($policy.customTargets)) {
            $state = if ($target.configuredBlocked) { 'Selected to block' } else { 'Allowed' }
            $targetId = HtmlEncode ([string]$target.key)
            $name = HtmlEncode ([string]$target.displayName)
            $controls += "<option value='target|$targetId'>$name ($state)</option>"
        }
    }
    $message = if ($script:LastError) { "<p class='warning'>$(HtmlEncode $script:LastError)</p>" } else { '' }
    return @"
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Parent Override</title><style>
body{font-family:Segoe UI,sans-serif;background:#f3f5f9;color:#172033;margin:0;padding:24px}.card{max-width:540px;margin:5vh auto;background:white;border:1px solid #d9dfeb;border-radius:18px;padding:28px;box-shadow:0 16px 45px #1f2a4414}h1{margin-top:0}label{display:grid;gap:6px;font-weight:650;margin:14px 0}input,select,button{font:inherit;padding:11px;border-radius:9px;border:1px solid #cbd2df}button{background:#3157d5;color:white;border:0;font-weight:750;cursor:pointer;width:100%;margin-top:12px}.muted{color:#667085}.warning{color:#b54708;background:#fff5e8;padding:10px;border-radius:9px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}@media(max-width:520px){.grid{grid-template-columns:1fr}}</style></head>
<body><main class="card"><h1>Parent Override</h1><p class="muted">Master blocking: <strong>$(HtmlEncode $masterState)</strong></p>$(if ($policy -and $policy.internetBlocked) { "<p class='warning'><strong>Internet paused:</strong> $(HtmlEncode ([string]$policy.internetMessage))</p>" })$message
<form method="post" action="/override"><label>Parent PIN<input name="pin" type="password" inputmode="numeric" required></label>
<label>Control<select name="selection">$controls</select></label>
<div class="grid"><label>Item action<select name="serviceAction"><option value="block">Block</option><option value="allow">Allow</option></select></label>
<label>Duration<select name="duration"><option value="0">Until changed</option><option value="30">30 minutes</option><option value="60">1 hour</option><option value="120">2 hours</option></select></label></div>
<button type="submit">Apply on this device</button></form></main></body></html>
"@
}

function New-LocalResult {
    param([int]$Status, [string]$Html)
    return @{ Status = $Status; Html = $Html }
}

function Process-LocalRequest {
    param([string]$Method, [string]$Path, [string]$Body)
    try {
        if ($Method -eq 'GET' -and $Path -eq '/') {
            return New-LocalResult 200 (Get-LocalPage)
        }
        if ($Method -eq 'OPTIONS' -and $Path -eq '/browser-event') {
            return New-LocalResult 204 ''
        }
        if ($Method -eq 'POST' -and $Path -eq '/browser-event') {
            $event = $Body | ConvertFrom-Json
            Add-WebsiteEvent ([string]$event.id) ([string]$event.domain) ([string]$event.browser) ([string]$event.occurredAt)
            return New-LocalResult 204 ''
        }
        if ($Method -ne 'POST' -or $Path -ne '/override') {
            return New-LocalResult 404 '<h1>Not found</h1>'
        }
        if (-not $script:LatestPolicy) { return New-LocalResult 503 '<h1>No policy is available yet.</h1>' }
        Add-Type -AssemblyName System.Web
        $form = [Web.HttpUtility]::ParseQueryString($Body)
        $pin = [string]$form['pin']
        $matchedParent = $null
        foreach ($parent in @($script:LatestPolicy.pinVerifiers)) {
            if (Test-PinVerifier $pin $parent.verifier) { $matchedParent = $parent; break }
        }
        if (-not $matchedParent) {
            Start-Sleep -Milliseconds 800
            return New-LocalResult 403 '<h1>Incorrect parent PIN.</h1><p><a href="/">Try again</a></p>'
        }
        $selection = [string]$form['selection']
        $parts = $selection.Split('|')
        $targetType = $parts[0]
        $targetId = $parts[1]
        $action = if ($targetType -in @('master', 'internet')) { $parts[2] } else { [string]$form['serviceAction'] }
        $duration = [int]$form['duration']
        $effectiveUntil = if ($duration -gt 0) { [DateTime]::UtcNow.AddMinutes($duration).ToString('o') } else { $null }
        $operation = @{
            operationId = [Guid]::NewGuid().ToString()
            deviceId = $script:Config.deviceId
            baseRevision = [int]$script:LatestPolicy.revision
            source = 'local-parent'
            parentKeyId = $matchedParent.parentKeyId
            targetType = $targetType
            targetId = $targetId
            action = $action
            effectiveUntil = $effectiveUntil
            createdAt = [DateTime]::UtcNow.ToString('o')
        }
        $pending = @(Get-PendingOperations)
        $pending += $operation
        Save-PendingOperations $pending
        $script:LatestPolicy = Apply-OperationLocally $script:LatestPolicy $operation
        Save-JsonFile $script:PolicyPath $script:LatestPolicy
        Apply-Policy $script:LatestPolicy | Out-Null
        [void](Sync-PendingOperations)
        return New-LocalResult 200 '<h1>Override applied.</h1><p>The dashboard will reflect this change after synchronization.</p><p><a href="/">Back to controls</a></p>'
    }
    catch {
        $script:LastError = $_.Exception.Message
        return New-LocalResult 500 "<h1>Unable to apply override.</h1><p>$(HtmlEncode $_.Exception.Message)</p><p><a href='/'>Back</a></p>"
    }
}

function Handle-LocalTcpClient {
    param([Net.Sockets.TcpClient]$Client)
    try {
        $stream = $Client.GetStream()
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::ASCII, $false, 4096, $true)
        $requestLine = $reader.ReadLine()
        if ([string]::IsNullOrWhiteSpace($requestLine)) { return }
        $requestParts = $requestLine.Split(' ')
        $method = $requestParts[0].ToUpperInvariant()
        $path = ([Uri]::new("http://127.0.0.1$($requestParts[1])")).AbsolutePath
        $contentLength = 0
        while ($true) {
            $line = $reader.ReadLine()
            if ([string]::IsNullOrEmpty($line)) { break }
            if ($line.StartsWith('Content-Length:', [StringComparison]::OrdinalIgnoreCase)) {
                $contentLength = [int]$line.Substring($line.IndexOf(':') + 1).Trim()
            }
        }
        $body = ''
        if ($contentLength -gt 0) {
            $buffer = New-Object char[] $contentLength
            $read = 0
            while ($read -lt $contentLength) {
                $count = $reader.Read($buffer, $read, $contentLength - $read)
                if ($count -le 0) { break }
                $read += $count
            }
            $body = -join $buffer[0..([Math]::Max(0, $read - 1))]
        }
        $result = Process-LocalRequest $method $path $body
        $statusText = switch ([int]$result.Status) { 200 { 'OK' } 204 { 'No Content' } 403 { 'Forbidden' } 404 { 'Not Found' } 503 { 'Service Unavailable' } default { 'Error' } }
        $htmlBytes = [Text.Encoding]::UTF8.GetBytes([string]$result.Html)
        $corsHeaders = if ($path -eq '/browser-event') { "Access-Control-Allow-Origin: *`r`nAccess-Control-Allow-Methods: POST, OPTIONS`r`nAccess-Control-Allow-Headers: Content-Type`r`n" } else { '' }
        $headers = "HTTP/1.1 $($result.Status) $statusText`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($htmlBytes.Length)`r`nCache-Control: no-store`r`n${corsHeaders}Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`r`nConnection: close`r`n`r`n"
        $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)
        $stream.Write($headerBytes, 0, $headerBytes.Length)
        $stream.Write($htmlBytes, 0, $htmlBytes.Length)
        $stream.Flush()
        $reader.Dispose()
    }
    catch {
        # Browsers and extension workers may cancel a request before the response
        # is fully written. A disconnected local caller must not stop the agent.
    }
    finally { $Client.Dispose() }
}

function Stop-ForeignClientListeners {
    param([int]$Port = $script:LocalPort)
    foreach ($connection in @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)) {
        if ([int]$connection.OwningProcess -eq $PID) { continue }
        Stop-Process -Id $connection.OwningProcess -Force -ErrorAction SilentlyContinue
    }
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        $busy = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
            Where-Object { [int]$_.OwningProcess -ne $PID })
        if ($busy.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "Local port $Port is still in use by another process."
}

function Start-Agent {
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) { throw "Client is not enrolled. Missing $script:ConfigPath" }
    $script:Config = Read-JsonFile $script:ConfigPath $null
    $script:Credential = Unprotect-Secret $script:Config.credentialProtected
    $script:LocalPort = if ($script:Config.localPort) { [int]$script:Config.localPort } else { 8765 }
    $script:LatestPolicy = Read-JsonFile $script:PolicyPath $null
    Ensure-EmergencyRestoreShortcut
    Stop-ForeignClientListeners
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $script:LocalPort)
    $started = $false
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            $listener.Start()
            $started = $true
            break
        }
        catch {
            Stop-ForeignClientListeners
            Start-Sleep -Milliseconds (200 * $attempt)
        }
    }
    if (-not $started) { throw "Unable to listen on local port $($script:LocalPort)." }
    $clientTask = $listener.AcceptTcpClientAsync()
    $nextPoll = [DateTime]::MinValue
    $nextScan = [DateTime]::MinValue
    $nextApplicationCheck = [DateTime]::MinValue
    $nextApplicationSync = [DateTime]::MinValue
    $nextUpdateCheck = [DateTime]::MinValue
    try {
        while ($true) {
            $now = [DateTime]::UtcNow
            if ($clientTask.IsCompleted) {
                Handle-LocalTcpClient $clientTask.Result
                $clientTask = $listener.AcceptTcpClientAsync()
            }
            if ($now -ge $nextPoll) {
                try {
                    $synced = $false
                    try { [void](Sync-PendingOperations) } catch { $script:LastError = "Local override waiting to sync: $($_.Exception.Message)" }
                    try {
                        $policy = Invoke-ClientApi -Method GET -Path '/api/client/v1/policy' -TimeoutSec 15
                        $script:LatestPolicy = $policy
                        Save-JsonFile $script:PolicyPath $policy
                        $synced = $true
                    }
                    catch {
                        $script:LastError = "Dashboard sync failed: $($_.Exception.Message)"
                    }
                    if ($script:LatestPolicy) {
                        $status = Apply-Policy $script:LatestPolicy
                        Send-Status $script:LatestPolicy $status
                    }
                    if ($synced) { $script:LastError = $null }
                    if ($synced -and $script:LatestPolicy) {
                        try { Sync-DesktopScreenshot $script:LatestPolicy } catch { $script:LastError = "Screenshot capture failed: $($_.Exception.Message)" }
                    }
                }
                catch { $script:LastError = "Dashboard sync failed: $($_.Exception.Message)" }
                $pollSeconds = if ($script:LatestPolicy -and [bool]$script:LatestPolicy.internetBlocked) { 2 } else { 8 }
                $nextPoll = [DateTime]::UtcNow.AddSeconds($pollSeconds)
                if ($clientTask.IsCompleted) {
                    Handle-LocalTcpClient $clientTask.Result
                    $clientTask = $listener.AcceptTcpClientAsync()
                }
            }
            if ($script:LatestPolicy) {
                $advanced = Advance-ExpiredPolicy $script:LatestPolicy
                if (-not [object]::ReferenceEquals($advanced, $script:LatestPolicy)) {
                    $script:LatestPolicy = $advanced
                    Save-JsonFile $script:PolicyPath $script:LatestPolicy
                    Apply-Policy $script:LatestPolicy | Out-Null
                }
            }
            if ($now -ge $nextUpdateCheck) {
                try {
                    if (Start-ClientUpdate) { return }
                }
                catch {
                    $script:UpdateStatus = 'failed'
                    $script:LastError = "Client update check failed: $($_.Exception.Message)"
                }
                $nextUpdateCheck = $now.AddMinutes(5)
            }
            if ($now -ge $nextScan) {
                if (-not ($script:LatestPolicy -and $script:LatestPolicy.internetBlocked)) {
                    Send-Targets
                }
                $nextScan = $now.AddMinutes(2)
                if ($clientTask.IsCompleted) {
                    Handle-LocalTcpClient $clientTask.Result
                    $clientTask = $listener.AcceptTcpClientAsync()
                }
            }
            if ($now -ge $nextApplicationCheck) {
                Update-ApplicationActivity
                $nextApplicationCheck = $now.AddSeconds(2)
            }
            if ($now -ge $nextApplicationSync) {
                Sync-ApplicationEvents
                if ($clientTask.IsCompleted) {
                    Handle-LocalTcpClient $clientTask.Result
                    $clientTask = $listener.AcceptTcpClientAsync()
                }
                Sync-WebsiteEvents
                $nextApplicationSync = [DateTime]::UtcNow.AddSeconds(30)
            }
            if ($script:LatestPolicy -and $now -ge $script:NextEnforcement) { Apply-Policy $script:LatestPolicy | Out-Null }
            Start-Sleep -Milliseconds 250
        }
    }
    finally {
        $listener.Stop()
    }
}

try {
    if ($Mode -eq 'Enroll') { Invoke-Enrollment }
    else { Start-Agent }
}
catch {
    try {
        $message = "[$([DateTime]::UtcNow.ToString('o'))] Mode=$Mode $($_.Exception.ToString())`r`n$($_.InvocationInfo.PositionMessage)`r`n$($_.ScriptStackTrace)"
        Add-Content -LiteralPath (Join-Path $script:DataDirectory 'startup-error.log') -Value $message -Encoding UTF8
    }
    catch { }
    throw
}
