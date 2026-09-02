[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StatePath,
    [Parameter(Mandatory = $true)][string]$NoticeId
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Read-PauseState {
    try { return Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json }
    catch { return $null }
}

$state = Read-PauseState
if (-not $state -or -not $state.internetBlocked -or [string]$state.noticeId -ne $NoticeId) { exit 0 }

$form = New-Object Windows.Forms.Form
$form.Text = 'Operation Crackdown'
$form.Size = New-Object Drawing.Size(580, 310)
$form.StartPosition = 'CenterScreen'
$form.TopMost = $true
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.BackColor = [Drawing.Color]::FromArgb(246, 248, 252)

$title = New-Object Windows.Forms.Label
$title.Text = 'Internet access is paused'
$title.Font = New-Object Drawing.Font('Segoe UI', 18, [Drawing.FontStyle]::Bold)
$title.ForeColor = [Drawing.Color]::FromArgb(23, 32, 51)
$title.AutoSize = $true
$title.Location = New-Object Drawing.Point(28, 25)
$form.Controls.Add($title)

$message = New-Object Windows.Forms.Label
$message.Text = [string]$state.message
$message.Font = New-Object Drawing.Font('Segoe UI', 12)
$message.ForeColor = [Drawing.Color]::FromArgb(52, 64, 84)
$message.Location = New-Object Drawing.Point(31, 82)
$message.Size = New-Object Drawing.Size(510, 105)
$form.Controls.Add($message)

$hint = New-Object Windows.Forms.Label
$hint.Text = 'A parent can restore access from the household dashboard.'
$hint.Font = New-Object Drawing.Font('Segoe UI', 9)
$hint.ForeColor = [Drawing.Color]::FromArgb(102, 112, 133)
$hint.AutoSize = $true
$hint.Location = New-Object Drawing.Point(31, 194)
$form.Controls.Add($hint)

$button = New-Object Windows.Forms.Button
$button.Text = 'Got it'
$button.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)
$button.Size = New-Object Drawing.Size(120, 40)
$button.Location = New-Object Drawing.Point(421, 222)
$button.BackColor = [Drawing.Color]::FromArgb(49, 87, 213)
$button.ForeColor = [Drawing.Color]::White
$button.FlatStyle = 'Flat'
$button.Add_Click({ $form.Close() })
$form.Controls.Add($button)
$form.AcceptButton = $button

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 1500
$timer.Add_Tick({
    $current = Read-PauseState
    if (-not $current -or -not $current.internetBlocked -or [string]$current.noticeId -ne $NoticeId) { $form.Close() }
})
$timer.Start()
[Windows.Forms.Application]::Run($form)
$timer.Stop()
