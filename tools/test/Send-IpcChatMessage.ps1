<#
.SYNOPSIS
    Send a message to VS Code Chat via IPC (no UI automation required).

.DESCRIPTION
    Writes a command file that the vscode-chat-sender extension picks up,
    then waits for the result.  No pywinauto or AHK involved.

    Multi-instance routing:
      The script auto-detects the target VS Code instance PID from
      $env:VSCODE_PID (integrated terminal) or the first Code.exe process
      (external terminal).  Pass -TargetPid explicitly to target a specific
      instance when multiple VS Code windows are open.

    Prerequisites:
      - VS Code >= 1.82 with GitHub Copilot
      - vscode-chat-sender extension installed
        (run tools/test/install_ipc_chat_extension.ps1 once)

.PARAMETER Message
    The message text to send.

.PARAMETER RequestId
    Optional identifier echoed back in the result.

.PARAMETER Priority
    Send mode: normal (queue) or high (interrupt).
    normal → silently queues if AI is busy; picks up after current reply.
    high   → cancels current work, sends immediately.

.PARAMETER JsonOutput
    Print the result payload as JSON.

.PARAMETER KeepTempFiles
    Preserve the result file after reading (default: deleted on read).
    Useful for post-mortem diagnostics.

.PARAMETER TargetPid
    Target VS Code main-window PID.  0 = auto-detect.
    Auto-detect order:  $env:VSCODE_PID → first running Code.exe.

.EXAMPLE
    .\Send-IpcChatMessage.ps1 -Message "Hello from IPC"

.EXAMPLE
    .\Send-IpcChatMessage.ps1 -Message "状态报告" -Priority normal

.EXAMPLE
    # High-priority: cancels current AI work, sends immediately
    .\Send-IpcChatMessage.ps1 -Message "紧急事件" -Priority high

.EXAMPLE
    # JSON output for programmatic consumption
    .\Send-IpcChatMessage.ps1 -Message "test" -JsonOutput

.EXAMPLE
    # Target a specific VS Code instance by PID
    .\Send-IpcChatMessage.ps1 -Message "hi" -TargetPid 12345

.EXAMPLE
    # Keep temp files after send for diagnostics
    .\Send-IpcChatMessage.ps1 -Message "test" -KeepTempFiles

#>

param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Message,

    [AllowEmptyString()]
    [string]$RequestId = '',

    [switch]$JsonOutput,

    [switch]$KeepTempFiles,

    [ValidateRange(0, 99999)]
    [int]$TargetPid = 0,

    [ValidateSet('normal', 'high')]
    [string]$Priority = 'normal'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- constants ----------------------------------------------------------
$pollTimeoutSec = 30
$pollIntervalSec = 0.2

# ---- resolve target PID -------------------------------------------------
function Resolve-TargetPid {
    param([int]$PreferredPid)

    if ($PreferredPid -gt 0) {
        return $PreferredPid
    }

    # Try VS Code integrated terminal env var.
    $vscodePid = [string]$env:VSCODE_PID
    if (-not [string]::IsNullOrWhiteSpace($vscodePid)) {
        $parsed = 0
        if ([int]::TryParse($vscodePid, [ref]$parsed)) {
            if ($parsed -gt 0) {
                return $parsed
            }
        }
    }

    # Fallback: find the main VS Code window (the process with a non-empty
    # window title).  Child processes (extension host, watchers, etc.) share
    # the same image name but have no MainWindowTitle.
    try {
        $codeProc = Get-Process -Name 'Code' -ErrorAction SilentlyContinue |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.MainWindowTitle) } |
            Sort-Object StartTime -Descending |
            Select-Object -First 1
        if ($null -ne $codeProc) {
            return [int]$codeProc.Id
        }
    }
    catch {
        $null = $null
    }

    return 0
}

$targetPid = Resolve-TargetPid -PreferredPid $TargetPid

# ---- resolve file paths -------------------------------------------------
$cmdFile = ''
$resFile = ''

if ($targetPid -gt 0) {
    $cmdFile = Join-Path $env:TEMP ("vscode_chat_send_cmd_{0}.json" -f $targetPid)
    $resFile = Join-Path $env:TEMP ("vscode_chat_send_res_{0}.json" -f $targetPid)
}
else {
    # No PID available — fall back to legacy shared paths.
    $cmdFile = Join-Path $env:TEMP 'vscode_chat_send_cmd.json'
    $resFile = Join-Path $env:TEMP 'vscode_chat_send_result.json'
}

$resolvedTargetPid = $targetPid

# ---- helpers ------------------------------------------------------------
function Get-Deadline {
    return (Get-Date).AddSeconds($pollTimeoutSec)
}

function Test-DeadlinePassed {
    param([datetime]$Deadline)
    return (Get-Date) -gt $Deadline
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
    priority = $Priority
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
            if (-not $KeepTempFiles.IsPresent) {
                Remove-Item -LiteralPath $resFile -Force -ErrorAction SilentlyContinue
            }
            break
        } catch {
            Start-Sleep -Milliseconds ([Math]::Max(50, [int]($pollIntervalSec * 1000)))
            continue
        }
    }
    Start-Sleep -Milliseconds ([Math]::Max(50, [int]($pollIntervalSec * 1000)))
}

if ($null -eq $outcome) {
    $outcome = @{
        success      = $false
        reason       = 'poll_timeout'
        target_pid   = $resolvedTargetPid
        cmd_file     = $cmdFile
        res_file     = $resFile
    }
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
