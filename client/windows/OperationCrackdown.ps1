[CmdletBinding()]
param(
    [ValidateSet('Run', 'Enroll')]
    [string]$Mode = 'Run',
    [string]$ServerUrl,
    [string]$EnrollmentCode,
    [string]$DeviceName = $env:COMPUTERNAME,
    [string]$DataDirectory = "$env:ProgramData\OperationCrackdown",
    [string]$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
)

$ErrorActionPreference = 'Stop'
$script:ClientVersion = '0.1.0'
$script:ConfigPath = Join-Path $DataDirectory 'config.json'
$script:PolicyPath = Join-Path $DataDirectory 'policy.json'
$script:StatusPath = Join-Path $DataDirectory 'status.json'
$script:PendingPath = Join-Path $DataDirectory 'pending-operations.json'
$script:ApplicationEventsPath = Join-Path $DataDirectory 'pending-application-events.json'
$script:WebsiteEventsPath = Join-Path $DataDirectory 'pending-website-events.json'
$script:LocalPort = 8765
$script:LatestPolicy = $null
$script:Credential = $null
$script:Config = $null
$script:LastError = $null
$script:NextEnforcement = [DateTime]::MinValue
$script:ObservedApplications = @{}
$script:ApplicationMonitorInitialized = $false

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
        [int]$TimeoutSec = 5,
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
        capabilities = @('process-enforcement', 'hosts-enforcement', 'target-scan', 'local-pin')
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

function Get-BlockedProcesses {
    param($Policy)
    $names = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($service in @($Policy.services)) {
        if ($service.blocked) {
            foreach ($name in @($service.windows.processes)) { [void]$names.Add([IO.Path]::GetFileNameWithoutExtension([string]$name)) }
        }
    }
    foreach ($target in @($Policy.customTargets)) {
        if ($target.blocked) {
            foreach ($name in @($target.mapping.processes)) { [void]$names.Add([IO.Path]::GetFileNameWithoutExtension([string]$name)) }
        }
    }
    return @($names)
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
    $begin = '# BEGIN OPERATION CRACKDOWN'
    $end = '# END OPERATION CRACKDOWN'
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

function Apply-Policy {
    param($Policy)
    $errors = New-Object Collections.Generic.List[string]
    $blockedProcesses = @(Get-BlockedProcesses $Policy)
    foreach ($name in $blockedProcesses) {
        try { Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Stop }
        catch { $errors.Add("Unable to close $name") }
    }
    try { Set-ManagedHosts @(Get-BlockedDomains $Policy) }
    catch { $errors.Add("Website enforcement failed: $($_.Exception.Message)") }
    $script:NextEnforcement = [DateTime]::UtcNow.AddSeconds(2)
    $status = @{
        state = if ($errors.Count -eq 0) { 'applied' } else { 'degraded' }
        profile = $Policy.profile
        blockedProcesses = $blockedProcesses
        errors = $errors.ToArray()
        elevated = Test-IsAdministrator
        localPort = $script:LocalPort
        pendingLocalOperations = @(Get-PendingOperations).Count
        pendingApplicationEvents = @(Get-PendingApplicationEvents).Count
        pendingWebsiteEvents = @(Get-PendingWebsiteEvents).Count
    }
    Save-JsonFile $script:StatusPath $status
    return $status
}

function Send-Status {
    param($Policy, $Status)
    try {
        Invoke-ClientApi -Method POST -Path '/api/client/v1/status' -Body @{
            appliedRevision = [int]$Policy.revision
            clientVersion = $script:ClientVersion
            osVersion = [Environment]::OSVersion.VersionString
            status = $Status
        } | Out-Null
    }
    catch { $script:LastError = "Status update failed: $($_.Exception.Message)" }
}

function Get-VisibleApplications {
    $excluded = @('explorer', 'taskmgr', 'powershell', 'pwsh', 'conhost', 'textinputhost', 'searchhost', 'shellexperiencehost', 'systemsettings', 'operationcrackdown')
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
<body><main class="card"><h1>Parent Override</h1><p class="muted">Master blocking: <strong>$(HtmlEncode $masterState)</strong></p>$message
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
        $action = if ($targetType -eq 'master') { $parts[2] } else { [string]$form['serviceAction'] }
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

function Start-Agent {
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) { throw "Client is not enrolled. Missing $script:ConfigPath" }
    $script:Config = Read-JsonFile $script:ConfigPath $null
    $script:Credential = Unprotect-Secret $script:Config.credentialProtected
    $script:LocalPort = if ($script:Config.localPort) { [int]$script:Config.localPort } else { 8765 }
    $script:LatestPolicy = Read-JsonFile $script:PolicyPath $null
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $script:LocalPort)
    $listener.Start()
    $clientTask = $listener.AcceptTcpClientAsync()
    $nextPoll = [DateTime]::MinValue
    $nextScan = [DateTime]::MinValue
    $nextApplicationCheck = [DateTime]::MinValue
    $nextApplicationSync = [DateTime]::MinValue
    try {
        while ($true) {
            $now = [DateTime]::UtcNow
            if ($clientTask.IsCompleted) {
                Handle-LocalTcpClient $clientTask.Result
                $clientTask = $listener.AcceptTcpClientAsync()
            }
            if ($now -ge $nextPoll) {
                try {
                    if (Sync-PendingOperations) {
                        $policy = Invoke-ClientApi -Method GET -Path '/api/client/v1/policy'
                        $script:LatestPolicy = $policy
                        Save-JsonFile $script:PolicyPath $policy
                    }
                    if ($script:LatestPolicy) {
                        $status = Apply-Policy $script:LatestPolicy
                        Send-Status $script:LatestPolicy $status
                    }
                    $script:LastError = $null
                }
                catch { $script:LastError = "Dashboard sync failed: $($_.Exception.Message)" }
                $nextPoll = $now.AddSeconds(8)
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
            if ($now -ge $nextScan) {
                Send-Targets
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
