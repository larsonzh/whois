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
    If omitted, the script auto-generates one and validates result binding.

.PARAMETER Priority
    Send mode: normal (queue) or high (interrupt).
    Both priorities clear the pending queue before sending to avoid
    VS Code's "保留/移除" confirmation dialog.
    normal → queues silently when AI is busy; sends directly when idle.
    high   → also cancels any active request before pasting + submitting.

.PARAMETER AutoEscalate
    When set with -Priority normal: if the initial send times out,
    automatically retry with -Priority high (cancel + submit).
    Acts as a safety net for unattended status polling.

.PARAMETER TimeoutSec
    Maximum seconds to wait for the extension to respond (1-300).
    Default: 30.

.PARAMETER PollIntervalMs
    Polling interval in milliseconds (50-2000).
    Default: 200.

.PARAMETER Mode
    Delivery mode:
      Visible = Clipboard paste only (appears in chat panel, same session).
                May pollute in-progress typing if the chat input is focused.
                This is the default.
      Silent  = LM API only (zero UI, captures AI response, no clipboard).
                Messages are invisible in the chat panel but do not
                interfere with manual typing.
      Auto    = Try LM API first, fall back to clipboard.

.PARAMETER Model
    Preferred model name or ID for LM API (Silent/Auto mode).
    Examples: "DeepSeek V4 Flash", "GPT-5.5", "gpt-4.1", "auto".
    Leave empty for default selection logic.

.PARAMETER ModelOptions
    Optional hashtable of model-specific options passed verbatim to the
    LM API as modelOptions.  Use to configure thinking mode, context size,
    etc.  Requires -Mode Silent or -Mode Auto.
    Example: @{ thinking_mode = "deep" }

.PARAMETER DiscoverModels
    List all available LM models with metadata (name, vendor, id, family,
    version, maxInputTokens).  No message is sent when this switch is set.
    Prints a table by default, or JSON when -JsonOutput is used.

.EXAMPLE
    # Auto-escalate: try normal first, escalate to high on timeout
    .\Send-IpcChatMessage.ps1 -Message "状态报告" -Priority normal -AutoEscalate

.PARAMETER JsonOutput
    Print the result payload as JSON.

.PARAMETER KeepTempFiles
    Preserve the result file after reading (default: deleted on read).
    Useful for post-mortem diagnostics.

.PARAMETER TargetPid
    Target VS Code main-window PID.  0 = auto-detect.
    Auto-detect order:  $env:VSCODE_PID → first running Code.exe.
    If the specified PID does not exist or is not a Code.exe process,
    falls back to auto-detect automatically.

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
    [Parameter(Mandatory = $true, ParameterSetName = 'Send')]
    [AllowEmptyString()]
    [string]$Message,

    [AllowEmptyString()]
    [string]$RequestId = '',

    [switch]$JsonOutput,

    [switch]$KeepTempFiles,

    [ValidateRange(0, 99999)]
    [int]$TargetPid = 0,

    [ValidateSet('normal', 'high')]
    [string]$Priority = 'normal',

    [switch]$AutoEscalate,

    [ValidateRange(1, 5400)]
    [int]$TimeoutSec = 30,

    [ValidateRange(50, 2000)]
    [int]$PollIntervalMs = 200,

    [ValidateSet('Silent', 'Visible', 'Auto')]
    [string]$Mode = 'Visible',

    [AllowEmptyString()]
    [string]$Model = '',

    [object]$ModelOptions = $null,

    [ValidateRange(1000, 3600000)]
    [int]$LmResponseTimeoutMs = 0,

    [Parameter(ParameterSetName = 'Discover')]
    [switch]$DiscoverModels
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'SEND-IPC-CHAT-MESSAGE'

# Keep compatibility parameters explicit even when currently unused.
$null = @(
    $KeepTempFiles,
    $TimeoutSec,
    $PollIntervalMs,
    $Mode,
    $Model,
    $ModelOptions,
    $LmResponseTimeoutMs
)

# ---- PID existence validation -------------------------------------------
if ($TargetPid -gt 0) {
    try {
        $proc = Get-Process -Id $TargetPid -ErrorAction SilentlyContinue
        if ($null -eq $proc -or $proc.Name -ne 'Code') {
            # Specified PID does not exist or is not a Code.exe process —
            # fall back to auto-detect.
            $TargetPid = 0
        }
    } catch {
        $TargetPid = 0
    }
}

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

function Get-RequestId {
    return ('auto-' + [Guid]::NewGuid().ToString('N'))
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

# ---- validate message ---------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Send') {
    $messageText = [string]$Message
    if ([string]::IsNullOrWhiteSpace($messageText)) {
        $payload = @{ success = $false; reason = 'empty_message' }
        if ($JsonOutput) { $payload | ConvertTo-Json -Compress | Write-Output }
        exit 3
    }
} else {
    # DiscoverModels mode: message is not required
    $messageText = ''
}

# ---- request id generation/binding --------------------------------------
$requestIdWasAutoGenerated = [string]::IsNullOrWhiteSpace([string]$RequestId)
$effectiveRequestId = if ($requestIdWasAutoGenerated) { Get-RequestId } else { [string]$RequestId }

# ---- send attempt function ----------------------------------------------
function Invoke-SendAttempt {
    param(
        [string]$AttemptPriority,
        [string]$CmdFile,
        [string]$ResFile
    )

    # Remove stale result before issuing a new command.
    # If deletion happens after command write, fast extension responses can be
    # accidentally deleted and appear as poll_timeout.
    if (Test-Path -LiteralPath $ResFile) {
        try { Remove-Item -LiteralPath $ResFile -Force } catch { $null = $null }
    }

    # Write command file.
    $cmdPayload = @{
        message    = $messageText
        request_id = $effectiveRequestId
        priority   = $AttemptPriority
        mode       = $Mode.ToLowerInvariant()
        model      = [string]$Model
        discover   = $DiscoverModels.IsPresent
    }
    # model_options: pass hashtable verbatim if provided.
    if ($null -ne $ModelOptions -and $ModelOptions -is [hashtable] -and $ModelOptions.Count -gt 0) {
        $cmdPayload.model_options = $ModelOptions
    }
    # lm_response_timeout_ms: per-request LM API timeout override (>0 only).
    if ($LmResponseTimeoutMs -gt 0) {
        $cmdPayload.lm_response_timeout_ms = $LmResponseTimeoutMs
    }
    try {
        $jsonText = $cmdPayload | ConvertTo-Json -Compress -Depth 3
        [System.IO.File]::WriteAllText([string]$CmdFile, [string]$jsonText, [System.Text.UTF8Encoding]::new($false))
    } catch {
        return @{ success = $false; reason = "write_cmd_failed:$($_.Exception.Message)"; request_id = $effectiveRequestId }
    }

    # Poll for result.
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -le $deadline) {
        if (Test-Path -LiteralPath $ResFile) {
            try {
                $raw = Get-Content -LiteralPath $ResFile -Raw -Encoding utf8
                $outcome = $raw | ConvertFrom-Json -ErrorAction Stop

                $resultRequestId = ''
                if ($null -ne $outcome.PSObject.Properties['request_id']) {
                    $resultRequestId = [string]$outcome.request_id
                }

                $reasonText = ''
                if ($null -ne $outcome.PSObject.Properties['reason']) {
                    $reasonText = [string]$outcome.reason
                }

                $requestIdMatches = ($resultRequestId -eq $effectiveRequestId)
                if (-not $requestIdMatches) {
                    # Compatibility: older extensions may not echo request_id
                    # for discovery responses.
                    $isLegacyDiscoverNoRequestId = (
                        $DiscoverModels.IsPresent -and
                        [string]::IsNullOrWhiteSpace($resultRequestId) -and
                        ($reasonText -eq 'discovery' -or $reasonText -eq 'discovery_failed')
                    )
                    if (-not $isLegacyDiscoverNoRequestId) {
                        Start-Sleep -Milliseconds 100
                        continue
                    }
                }

                if (-not $KeepTempFiles.IsPresent) {
                    Remove-Item -LiteralPath $ResFile -Force -ErrorAction SilentlyContinue
                }
                return $outcome
            } catch {
                Start-Sleep -Milliseconds 100
                continue
            }
        }
        Start-Sleep -Milliseconds $PollIntervalMs
    }

    # Timeout — clean up command file.
    if (Test-Path -LiteralPath $CmdFile) {
        try { Remove-Item -LiteralPath $CmdFile -Force } catch { $null = $null }
    }
    return $null  # timeout
}

# ---- initial attempt with configured priority ---------------------------
$outcome = Invoke-SendAttempt -AttemptPriority $Priority -CmdFile $cmdFile -ResFile $resFile

# ---- auto-escalate: normal timeout → retry with high --------------------
$escalated = $false
if ($null -eq $outcome -and $AutoEscalate.IsPresent -and $Priority -eq 'normal') {
    $outcome = Invoke-SendAttempt -AttemptPriority 'high' -CmdFile $cmdFile -ResFile $resFile
    if ($null -ne $outcome) {
        $escalated = $true
    }
}

# ---- final outcome ------------------------------------------------------
if ($null -eq $outcome) {
    $outcome = @{
        success      = $false
        reason       = 'poll_timeout'
        request_id   = $effectiveRequestId
        target_pid   = $resolvedTargetPid
        cmd_file     = $cmdFile
        res_file     = $resFile
    }
} elseif ($escalated) {
    # Add escalation info to the outcome.
    $outcome = $outcome.PSObject.Copy()
    Add-Member -InputObject $outcome -NotePropertyName 'escalated' -NotePropertyValue $true -Force
    Add-Member -InputObject $outcome -NotePropertyName 'escalated_reason' -NotePropertyValue 'normal_timeout_retry_with_high' -Force
}

# Attach resolved request-id metadata for diagnostics/output consistency.
if ($outcome -is [hashtable]) {
    if (-not $outcome.ContainsKey('request_id') -or [string]::IsNullOrWhiteSpace([string]$outcome['request_id'])) {
        $outcome['request_id'] = $effectiveRequestId
    }
    $outcome['request_id_auto_generated'] = $requestIdWasAutoGenerated
} else {
    if ($null -eq $outcome.PSObject.Properties['request_id'] -or
        [string]::IsNullOrWhiteSpace([string]$outcome.request_id)) {
        Add-Member -InputObject $outcome -NotePropertyName 'request_id' -NotePropertyValue $effectiveRequestId -Force
    }
    Add-Member -InputObject $outcome -NotePropertyName 'request_id_auto_generated' -NotePropertyValue $requestIdWasAutoGenerated -Force
}

if ($JsonOutput) {
    $outcome | ConvertTo-Json -Compress -Depth 3 | Write-Output
}
elseif ($DiscoverModels.IsPresent -and $outcome.success -and $null -ne $outcome.models) {
    # Pretty-printed table for DiscoverModels (without -JsonOutput)
    $models = $outcome.models | Sort-Object vendor, name

    Write-Output ""
    Write-Output " Available Models (grouped by vendor):"
    Write-Output ("-" * 100)

    $models | Group-Object vendor | ForEach-Object {
        Write-Output "`n [$($_.Name)]"

        $_.Group | Format-Table -Property @{L='Model Name';E={$_.name};Width=42},
                                         @{L='ID';E={$_.id};Width=30},
                                         @{L='Max Tokens';E={"{0:N0}" -f $_.maxInputTokens};Align='right';Width=14},
                                         @{L='Version';E={$_.version};Width=24} -AutoSize -Wrap
    }

    Write-Output ("-" * 100)
    Write-Output " [$($models.Count) model(s) total]"
    Write-Output ""
    Write-Output " Tip: Pipe to Format-Table or use -JsonOutput for scripting."
    Write-Output "      .\Send-IpcChatMessage.ps1 -DiscoverModels -JsonOutput | ..."
    Write-Output ""
}

if ($outcome.success) {
    exit 0
}

$failureReason = ''
if ($outcome -is [hashtable]) {
    if ($outcome.ContainsKey('reason')) {
        $failureReason = [string]$outcome['reason']
    }
} elseif ($null -ne $outcome.PSObject.Properties['reason']) {
    $failureReason = [string]$outcome.reason
}

Write-Error "Command failed: $failureReason"

$isLocalFailure = ($failureReason -eq 'poll_timeout' -or $failureReason.StartsWith('write_cmd_failed'))
if ($isLocalFailure) {
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason ("send-ipc local failure: {0}" -f $failureReason) -ExitCode 1
}
exit 2
