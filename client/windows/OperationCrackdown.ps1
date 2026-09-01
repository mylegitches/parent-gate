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
$script:PendingPath = Join-Path $DataDirectory 'pending-operations.json'
$script:LocalPort = 8765
$script:LatestPolicy = $null
$script:Credential = $null
$script:Config = $null
$script:LastError = $null
$script:NextEnforcement = [DateTime]::MinValue

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
    ConvertTo-Json -InputObject $Value -Depth 20 | Set-Content -LiteralPath $temporary -Encoding UTF8
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
        [switch]$AllowConflict
    )
    $headers = @{ Authorization = "Bearer $script:Credential" }
    $parameters = @{
        Uri = "$($script:Config.serverUrl.TrimEnd('/'))$Path"
        Method = $Method
        Headers = $headers
        UseBasicParsing = $true
        TimeoutSec = 15
    }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 20
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
    return ($Policy | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
}

function Apply-OperationLocally {
    param($Policy, $Operation)
    $local = Copy-Policy $Policy
    $beforeOverride = Copy-Policy $Policy
    if ($Operation.targetType -eq 'profile') {
        $local.profile = $Operation.targetId
        foreach ($service in $local.services) {
            switch ($Operation.targetId) {
                'normal' { $service.blocked = $false }
                'homework' { $service.blocked = ($service.id -eq 'discord') }
                'deep-focus' { $service.blocked = ($service.category -in @('social', 'streaming')) }
            }
        }
        foreach ($target in @($local.customTargets)) {
            $target.blocked = @($target.profiles) -contains $Operation.targetId
        }
    }
    elseif ($Operation.targetType -eq 'category') {
        foreach ($service in $local.services) {
            if ($service.category -eq $Operation.targetId) { $service.blocked = $Operation.action -eq 'block' }
        }
    }
    elseif ($Operation.targetType -eq 'service') {
        foreach ($service in $local.services) {
            if ($service.id -eq $Operation.targetId) { $service.blocked = $Operation.action -eq 'block' }
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
    return @($domains | Sort-Object)
}

function Set-ManagedHosts {
    param([string[]]$Domains)
    $hostsPath = $HostsPath
    $begin = '# BEGIN OPERATION CRACKDOWN'
    $end = '# END OPERATION CRACKDOWN'
    $content = if (Test-Path -LiteralPath $hostsPath) { Get-Content -LiteralPath $hostsPath -Raw } else { '' }
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
    Set-Content -LiteralPath $hostsPath -Value ($lines -join [Environment]::NewLine) -Encoding ASCII
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
    return @{
        state = if ($errors.Count -eq 0) { 'applied' } else { 'degraded' }
        profile = $Policy.profile
        blockedProcesses = $blockedProcesses
        errors = $errors.ToArray()
        localPort = $script:LocalPort
        pendingLocalOperations = @(Get-PendingOperations).Count
    }
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

function Get-ApplicationTargets {
    $excluded = @('explorer', 'taskmgr', 'powershell', 'pwsh', 'conhost', 'textinputhost', 'searchhost', 'shellexperiencehost', 'systemsettings', 'operationcrackdown')
    $communicationPattern = '(?i)discord|slack|teams|zoom|skype|telegram|signal|whatsapp|messenger|webex|wechat|line'
    $streamingPattern = '(?i)netflix|hulu|paramount|discovery|youtube|twitch|spotify|plex|primevideo|disney'
    $targets = New-Object Collections.Generic.List[object]
    foreach ($process in Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.ProcessName -notin $excluded }) {
        $displayName = $process.ProcessName
        try {
            if ($process.MainModule.FileVersionInfo.ProductName) { $displayName = $process.MainModule.FileVersionInfo.ProductName }
        }
        catch { }
        $combined = "$($process.ProcessName) $displayName"
        $category = if ($combined -match $communicationPattern) { 'communication' } elseif ($combined -match $streamingPattern) { 'streaming' } else { 'unknown' }
        $processFile = "$($process.ProcessName).exe"
        $targets.Add(@{
            key = "process:$($processFile.ToLowerInvariant())"
            displayName = $displayName
            kind = 'application'
            categoryGuess = $category
            source = 'windows-running-scan'
            currentlyRunning = $true
            mapping = @{ processes = @($processFile) }
        })
    }
    return @($targets | Sort-Object key -Unique)
}

function Send-Targets {
    try { Invoke-ClientApi -Method POST -Path '/api/client/v1/targets' -Body @{ targets = @(Get-ApplicationTargets) } | Out-Null }
    catch { $script:LastError = "Application scan upload failed: $($_.Exception.Message)" }
}

function HtmlEncode {
    param([string]$Value)
    Add-Type -AssemblyName System.Web
    return [Web.HttpUtility]::HtmlEncode($Value)
}

function Get-LocalPage {
    $policy = $script:LatestPolicy
    $profile = if ($policy) { [string]$policy.profile } else { 'unavailable' }
    $services = ''
    if ($policy) {
        foreach ($service in @($policy.services)) {
            $state = if ($service.blocked) { 'Blocked' } else { 'Allowed' }
            $serviceId = HtmlEncode ([string]$service.id)
            $name = HtmlEncode ([string]$service.displayName)
            $services += "<option value='$serviceId'>$name ($state)</option>"
        }
    }
    $message = if ($script:LastError) { "<p class='warning'>$(HtmlEncode $script:LastError)</p>" } else { '' }
    return @"
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Parent Override</title><style>
body{font-family:Segoe UI,sans-serif;background:#f3f5f9;color:#172033;margin:0;padding:24px}.card{max-width:540px;margin:5vh auto;background:white;border:1px solid #d9dfeb;border-radius:18px;padding:28px;box-shadow:0 16px 45px #1f2a4414}h1{margin-top:0}label{display:grid;gap:6px;font-weight:650;margin:14px 0}input,select,button{font:inherit;padding:11px;border-radius:9px;border:1px solid #cbd2df}button{background:#3157d5;color:white;border:0;font-weight:750;cursor:pointer;width:100%;margin-top:12px}.muted{color:#667085}.warning{color:#b54708;background:#fff5e8;padding:10px;border-radius:9px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}@media(max-width:520px){.grid{grid-template-columns:1fr}}</style></head>
<body><main class="card"><h1>Parent Override</h1><p class="muted">Current profile: <strong>$(HtmlEncode $profile)</strong></p>$message
<form method="post" action="/override"><label>Parent PIN<input name="pin" type="password" inputmode="numeric" required></label>
<label>Control<select name="selection"><option value="profile:normal:set">Normal mode</option><option value="profile:homework:set">Homework mode</option><option value="profile:deep-focus:set">Deep Focus</option>$services</select></label>
<div class="grid"><label>Service action<select name="serviceAction"><option value="allow">Allow</option><option value="block">Block</option></select></label>
<label>Duration<select name="duration"><option value="30">30 minutes</option><option value="60">1 hour</option><option value="120">2 hours</option><option value="0">Until changed</option></select></label></div>
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
        $parts = $selection.Split(':')
        if ($parts[0] -eq 'profile') {
            $targetType = 'profile'; $targetId = $parts[1]; $action = 'set'
        }
        else {
            $targetType = 'service'; $targetId = $selection; $action = [string]$form['serviceAction']
        }
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
        $statusText = switch ([int]$result.Status) { 200 { 'OK' } 403 { 'Forbidden' } 404 { 'Not Found' } 503 { 'Service Unavailable' } default { 'Error' } }
        $htmlBytes = [Text.Encoding]::UTF8.GetBytes([string]$result.Html)
        $headers = "HTTP/1.1 $($result.Status) $statusText`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($htmlBytes.Length)`r`nCache-Control: no-store`r`nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`r`nConnection: close`r`n`r`n"
        $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)
        $stream.Write($headerBytes, 0, $headerBytes.Length)
        $stream.Write($htmlBytes, 0, $htmlBytes.Length)
        $stream.Flush()
        $reader.Dispose()
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
            }
            if ($script:LatestPolicy -and $now -ge $script:NextEnforcement) { Apply-Policy $script:LatestPolicy | Out-Null }
            Start-Sleep -Milliseconds 250
        }
    }
    finally {
        $listener.Stop()
    }
}

if ($Mode -eq 'Enroll') { Invoke-Enrollment }
else { Start-Agent }
