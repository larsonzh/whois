<#
.SYNOPSIS
    Send a message to VS Code Chat via IPC (no UI automation required).

.DESCRIPTION
    Writes a command file that the vscode-chat-sender extension picks up,
    then waits for the result.  No pywinauto or AHK involved.

    Prerequisites:
      - VS Code >= 1.82 with GitHub Copilot
      - vscode-chat-sender extension installed
        (run tools/test/install_ipc_chat_extension.ps1 once)

.PARAMETER Message
    The message text to send.

.PARAMETER RequestId
    Optional identifier echoed back in the result.

.PARAMETER SubmitChord
    Submit chord hint: enter, ctrl-enter, or alt-enter.
    Defaults to enter.

.PARAMETER JsonOutput
    Print the result payload as JSON.

.EXAMPLE
    .\Send-IpcChatMessage.ps1 -Message "Hello from IPC"

.EXAMPLE
    .\Send-IpcChatMessage.ps1 -Message "test" -SubmitChord ctrl-enter -JsonOutput
#>

param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Message,

    [AllowEmptyString()]
    [string]$RequestId = '',

    [ValidateSet('enter', 'ctrl-enter', 'alt-enter')]
    [string]$SubmitChord = 'enter',

    [switch]$JsonOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- constants ----------------------------------------------------------
$cmdFile = Join-Path $env:TEMP 'vscode_chat_send_cmd.json'
$resFile = Join-Path $env:TEMP 'vscode_chat_send_result.json'
$pollTimeoutSec = 30
$pollIntervalSec = 0.2

# ---- helpers ------------------------------------------------------------
function Get-Deadline {
    return (Get-Date).AddSeconds($pollTimeoutSec)
}

function Test-DeadlinePassed {
    param([datetime]$Deadline)
    return (Get-Date) -gt $Deadline
}

function Write-ResultToFile {
    param([object]$Data)
    try {
        $Data | ConvertTo-Json -Compress -Depth 3 | Set-Content -LiteralPath $resFile -Encoding utf8 -NoNewline -Force
    } catch {
        # best-effort write, ignore failure
        $null = $null
    }
}

# ---- validate message ---------------------------------------------------
$messageText = [string]$Message
if ([string]::IsNullOrWhiteSpace($messageText)) {
    $payload = @{ success = $false; reason = 'empty_message' }
    if ($JsonOutput) { $payload | ConvertTo-Json -Compress | Write-Output }
    exit 3
}

# ---- write command file -------------------------------------------------
$cmdPayload = @{
    message      = $messageText
    request_id   = [string]$RequestId
    submit_chord = $SubmitChord
}
try {
    $jsonText = $cmdPayload | ConvertTo-Json -Compress -Depth 3
    [System.IO.File]::WriteAllText([string]$cmdFile, [string]$jsonText, [System.Text.UTF8Encoding]::new($false))
} catch {
    $payload = @{ success = $false; reason = "write_cmd_failed:$($_.Exception.Message)" }
    if ($JsonOutput) { $payload | ConvertTo-Json -Compress | Write-Output }
    exit 1
}

# ---- remove stale result ------------------------------------------------
if (Test-Path -LiteralPath $resFile) {
    try { Remove-Item -LiteralPath $resFile -Force } catch {
        # stale file already absent, ignore
        $null = $null
    }
}

# ---- poll for result ----------------------------------------------------
$deadline = Get-Deadline
$outcome = $null

while (-not (Test-DeadlinePassed -Deadline $deadline)) {
    if (Test-Path -LiteralPath $resFile) {
        try {
            $raw = Get-Content -LiteralPath $resFile -Raw -Encoding utf8
            $outcome = $raw | ConvertFrom-Json -ErrorAction Stop
            Remove-Item -LiteralPath $resFile -Force -ErrorAction SilentlyContinue
            break
        } catch {
            Start-Sleep -Milliseconds ([Math]::Max(50, [int]($pollIntervalSec * 1000)))
            continue
        }
    }
    Start-Sleep -Milliseconds ([Math]::Max(50, [int]($pollIntervalSec * 1000)))
}

if ($null -eq $outcome) {
    $outcome = @{ success = $false; reason = 'poll_timeout' }
    if (Test-Path -LiteralPath $cmdFile) {
        try { Remove-Item -LiteralPath $cmdFile -Force } catch {
            # best-effort cleanup, ignore
            $null = $null
        }
    }
}

if ($JsonOutput) {
    $outcome | ConvertTo-Json -Compress -Depth 3 | Write-Output
}

if ($outcome.success) {
    exit 0
}
exit 2
