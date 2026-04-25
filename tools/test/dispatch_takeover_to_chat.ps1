param(
    [Parameter(Mandatory = $true)][string]$TicketId,
    [AllowEmptyString()][string]$TicketEvent = '',
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$BriefPath = '',
    [switch]$NoOpenEditor,
    [switch]$SkipClipboard
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoPathAllowMissing {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot $Path))
}

function Convert-ToRepoRelativePath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $repoRootFull = [System.IO.Path]::GetFullPath($script:RepoRoot)
        if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
        }

        return $fullPath.Replace('\\', '/')
    }
    catch {
        return $Path.Replace('\\', '/')
    }
}

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Get-SafeToken {
    param([AllowEmptyString()][string]$Text)

    $raw = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return 'default'
    }

    return ([regex]::Replace($raw, '[^A-Za-z0-9._-]', '_')).Trim('_')
}

function Write-DispatchLog {
    param([string]$Message)

    $line = "[CHAT-DISPATCH] timestamp={0} {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), (Convert-ToSingleLineText -Text $Message)
    Write-Host $line

    try {
        Add-Content -LiteralPath $script:DispatchLogPath -Value $line -Encoding utf8
    }
    catch {
        Write-Warning ("[CHAT-DISPATCH] log_write_failed path={0}" -f $script:DispatchLogPath)
    }
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dispatchRoot = Join-Path $script:RepoRoot 'out\artifacts\ab_agent_queue\chat_dispatch'
New-Item -ItemType Directory -Path $dispatchRoot -Force | Out-Null

$startFilePath = Resolve-RepoPathAllowMissing -Path $StartFile
$startToken = Get-SafeToken -Text ([System.IO.Path]::GetFileNameWithoutExtension($startFilePath))
$script:DispatchLogPath = Join-Path $dispatchRoot ("dispatch_{0}.log" -f $startToken)

$queueFilePath = if ([string]::IsNullOrWhiteSpace($QueuePath)) {
    Resolve-RepoPathAllowMissing -Path 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
}
else {
    Resolve-RepoPathAllowMissing -Path $QueuePath
}

$briefFilePath = Resolve-RepoPathAllowMissing -Path $BriefPath
$briefExists = (-not [string]::IsNullOrWhiteSpace($briefFilePath)) -and (Test-Path -LiteralPath $briefFilePath)

$ticketToken = Get-SafeToken -Text $TicketId
$eventToken = Get-SafeToken -Text $TicketEvent
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$relayPath = Join-Path $dispatchRoot ("relay_{0}_{1}_{2}.md" -f $ticketToken, $eventToken, $stamp)

$startFileRel = Convert-ToRepoRelativePath -Path $startFilePath
$queueRel = Convert-ToRepoRelativePath -Path $queueFilePath
$briefRel = Convert-ToRepoRelativePath -Path $briefFilePath
$relayRel = Convert-ToRepoRelativePath -Path $relayPath

$eventNormalized = (Convert-ToSingleLineText -Text $TicketEvent).ToLowerInvariant()
$suppressInteractiveActions = ($eventNormalized -eq 'running-status-report')

$firstMessage = "请接管工单 {0}（event={1}），按 {2} 执行恢复：先读取 {3} 与 {4}，然后继续阻塞盯盘并按 D1 90/30/10/20 规则处理。" -f $TicketId, $TicketEvent, $startFileRel, $briefRel, $queueRel

$resumeCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_resume_window.ps1 -StartFile "{0}" -StartMonitors' -f $startFileRel
$guardCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}"' -f $startFileRel

$relayLines = @(
    '# Chat Takeover Relay',
    '',
    ('generated_at={0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')),
    ('ticket_id={0}' -f $TicketId),
    ('event={0}' -f $TicketEvent),
    ('start_file={0}' -f $startFileRel),
    ('queue_path={0}' -f $queueRel),
    ('brief_path={0}' -f $briefRel),
    ('brief_exists={0}' -f $briefExists),
    '',
    'first_message:',
    $firstMessage,
    '',
    'fallback_commands:',
    $resumeCommand,
    $guardCommand
)
Set-Content -LiteralPath $relayPath -Value $relayLines -Encoding utf8

$latestStatePath = Join-Path $dispatchRoot ("latest_relay_{0}.json" -f $startToken)
$latestState = [ordered]@{
    schema = 'AB_CHAT_DISPATCH_STATE_V1'
    updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    ticket_id = $TicketId
    event = $TicketEvent
    start_file = $startFileRel
    queue_path = $queueRel
    brief_path = $briefRel
    relay_path = $relayRel
    first_message = $firstMessage
}
$latestState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $latestStatePath -Encoding utf8

$clipboardApplied = $false
if (-not $SkipClipboard.IsPresent -and -not $suppressInteractiveActions) {
    try {
        Set-Clipboard -Value $firstMessage
        $clipboardApplied = $true
    }
    catch {
        Write-DispatchLog ("clipboard_set_failed detail={0}" -f (Convert-ToSingleLineText -Text $_.Exception.Message))
    }
}
elseif ($suppressInteractiveActions) {
    Write-DispatchLog ("interactive_actions_suppressed event={0} reason=status-report" -f $TicketEvent)
}

$editorOpened = $false
$chatOpenTried = $false
$chatOpenStarted = $false

if (-not $NoOpenEditor.IsPresent -and -not $suppressInteractiveActions) {
    $codeCommand = Get-Command code -ErrorAction SilentlyContinue
    if ($null -ne $codeCommand -and -not [string]::IsNullOrWhiteSpace([string]$codeCommand.Source)) {
        try {
            $openArgs = @('-r', $relayPath)
            if ($briefExists) {
                $openArgs += $briefFilePath
            }
            Start-Process -FilePath $codeCommand.Source -ArgumentList $openArgs -ErrorAction Stop | Out-Null
            $editorOpened = $true
        }
        catch {
            Write-DispatchLog ("editor_open_failed detail={0}" -f (Convert-ToSingleLineText -Text $_.Exception.Message))
        }

        try {
            $chatOpenTried = $true
            Start-Process -FilePath $codeCommand.Source -ArgumentList @('--command', 'workbench.action.chat.open') -ErrorAction Stop | Out-Null
            $chatOpenStarted = $true
        }
        catch {
            Write-DispatchLog ("chat_open_failed detail={0}" -f (Convert-ToSingleLineText -Text $_.Exception.Message))
        }
    }
    else {
        Write-DispatchLog 'code_cli_not_found skip_editor_and_chat_open'
    }
}
elseif ($suppressInteractiveActions) {
    Write-DispatchLog ("skip_editor_and_chat_open event={0} reason=status-report" -f $TicketEvent)
}

Write-DispatchLog ("relay_created ticket={0} event={1} relay={2} brief_exists={3} clipboard={4} editor_opened={5} chat_open_tried={6} chat_open_started={7} interactive_suppressed={8}" -f $TicketId, $TicketEvent, $relayRel, $briefExists, $clipboardApplied, $editorOpened, $chatOpenTried, $chatOpenStarted, $suppressInteractiveActions)
Write-Output ("[CHAT-DISPATCH] ticket={0} event={1} relay={2} first_message_in_clipboard={3} editor_opened={4} chat_open_started={5} interactive_suppressed={6}" -f $TicketId, $TicketEvent, $relayRel, $clipboardApplied, $editorOpened, $chatOpenStarted, $suppressInteractiveActions)

