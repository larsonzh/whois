param(
    [Parameter(Mandatory = $true)][string]$TicketId,
    [AllowEmptyString()][string]$TicketEvent = '',
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$BriefPath = '',
    [switch]$OpenEditor,
    [switch]$NoOpenEditor,
    [switch]$UseClipboard,
    [switch]$SkipClipboard,
    [switch]$UseAhk,
    [AllowEmptyString()][string]$AhkExePath = '',
    [ValidateRange(1000, 60000)][int]$AhkTimeoutMs = 12000
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

function Convert-ToBooleanSetting {
    param(
        [AllowEmptyString()][string]$Value,
        [bool]$Default = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    return $Value.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
}

function Convert-ToIntRangeSetting {
    param(
        [AllowEmptyString()][string]$Value,
        [int]$Default,
        [int]$Min,
        [int]$Max
    )

    $raw = Convert-ToSingleLineText -Text $Value
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    $parsed = 0
    if (-not [int]::TryParse($raw, [ref]$parsed)) {
        return $Default
    }

    if ($parsed -lt $Min -or $parsed -gt $Max) {
        return $Default
    }

    return $parsed
}

function Split-EventListSetting {
    param([AllowEmptyString()][string]$Value)

    $items = New-Object 'System.Collections.Generic.List[string]'
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $items.ToArray()
    }

    foreach ($part in @($Value -split '[,;]')) {
        $token = (Convert-ToSingleLineText -Text ([string]$part)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($token)) {
            continue
        }

        if (-not $items.Contains($token)) {
            [void]$items.Add($token)
        }
    }

    return $items.ToArray()
}

function Test-EventAllowedByList {
    param(
        [AllowEmptyString()][string]$EventName,
        [string[]]$AllowList
    )

    $normalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $false
    }

    foreach ($entry in @($AllowList)) {
        $token = (Convert-ToSingleLineText -Text ([string]$entry)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($token)) {
            continue
        }

        if ($token -eq '*' -or $token -eq 'all') {
            return $true
        }

        if ($token -eq $normalized) {
            return $true
        }
    }

    return $false
}

function Read-KeyValueFile {
    param([string]$Path)

    $keyLineMap = @{}
    $map = [ordered]@{}
    $lineNo = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        $lineNo++
        if ($line -match '^([^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            if ($map.Contains($key)) {
                $firstLine = [int]$keyLineMap[$key]
                throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, $firstLine, $lineNo)
            }

            $keyLineMap[$key] = $lineNo
            $map[$key] = $Matches[2]
        }
    }

    return $map
}

function Resolve-AhkExecutablePath {
    param(
        [AllowEmptyString()][string]$ConfiguredPath,
        [bool]$StrictConfiguredPath = $false
    )

    $candidates = New-Object 'System.Collections.Generic.List[string]'

    $normalizedConfigured = Convert-ToSingleLineText -Text $ConfiguredPath
    if (-not [string]::IsNullOrWhiteSpace($normalizedConfigured)) {
        $resolvedConfigured = Resolve-RepoPathAllowMissing -Path $normalizedConfigured
        if ($StrictConfiguredPath) {
            if ([string]::IsNullOrWhiteSpace($resolvedConfigured)) {
                return ''
            }

            try {
                $configuredFullPath = [System.IO.Path]::GetFullPath($resolvedConfigured)
                if (Test-Path -LiteralPath $configuredFullPath) {
                    return $configuredFullPath
                }
            }
            catch {
            }

            return ''
        }

        [void]$candidates.Add($resolvedConfigured)
    }

    $envPath = Convert-ToSingleLineText -Text $env:AUTOHOTKEY_EXE
    if (-not [string]::IsNullOrWhiteSpace($envPath)) {
        [void]$candidates.Add((Resolve-RepoPathAllowMissing -Path $envPath))
    }

    [void]$candidates.Add('C:\Users\妙妙呜\AppData\Local\Programs\AutoHotkey\v2\AutoHotkey64.exe')
    [void]$candidates.Add('C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe')

    foreach ($candidate in @($candidates)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        try {
            $fullPath = [System.IO.Path]::GetFullPath($candidate)
            if (Test-Path -LiteralPath $fullPath) {
                return $fullPath
            }
        }
        catch {
            continue
        }
    }

    $command = Get-Command AutoHotkey64.exe -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
        return [string]$command.Source
    }

    return ''
}

function Invoke-AhkChatDispatch {
    param(
        [string]$AhkExecutable,
        [string]$Message,
        [int]$TimeoutMs = 12000,
        [System.Collections.IDictionary]$Settings = $null,
        [AllowEmptyString()][string]$EventName = '',
        [bool]$HeartbeatTimeoutRequireCodeFocus = $true
    )

    if ([string]::IsNullOrWhiteSpace($AhkExecutable) -or -not (Test-Path -LiteralPath $AhkExecutable)) {
        return [pscustomobject]@{
            started = $false
            sent = $false
            exit_code = -1
            reason = 'ahk-executable-missing'
            attempt_count = 0
            auto_resend_triggered = $false
            auto_resend_reason = ''
            esc_preflight_enabled = $false
        }
    }

    $sendScriptPath = Join-Path $script:RepoRoot 'tools\test\send_chat_message_ahk.ps1'
    if (-not (Test-Path -LiteralPath $sendScriptPath)) {
        return [pscustomobject]@{
            started = $false
            sent = $false
            exit_code = -1
            reason = 'send-script-missing'
            attempt_count = 0
            auto_resend_triggered = $false
            auto_resend_reason = ''
            esc_preflight_enabled = $false
        }
    }

    $invokeParams = @{
        Message = $Message
        AhkExePath = $AhkExecutable
        TimeoutMs = ([Math]::Max(1000, $TimeoutMs))
    }

    if ($null -ne $Settings) {
        if ($Settings.Contains('AI_CHAT_DISPATCH_PRESEND_DELAY_MS')) {
            $invokeParams.PreSendDelayMs = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_PRESEND_DELAY_MS) -Default 700 -Min 0 -Max 60000
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_BOTTOM_AVOID_PX')) {
            $invokeParams.ChatBottomAvoidPx = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_BOTTOM_AVOID_PX) -Default 170 -Min 0 -Max 400
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_RIGHT_OFFSET_PX')) {
            $invokeParams.ChatInputRightOffsetPx = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_RIGHT_OFFSET_PX) -Default 300 -Min 0 -Max 2400
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_X_MODE')) {
            $xMode = (Convert-ToSingleLineText -Text ([string]$Settings.AI_CHAT_DISPATCH_X_MODE)).ToLowerInvariant()
            if ($xMode -in @('ratio', 'right-offset')) {
                $invokeParams.ChatInputXMode = $xMode
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_RECONNECT_DELAY_MS')) {
            $invokeParams.ReconnectResendDelayMs = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_RECONNECT_DELAY_MS) -Default 1800 -Min 200 -Max 30000
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_RECONNECT_WINDOW_SEC')) {
            $invokeParams.ReconnectDetectWindowSec = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_RECONNECT_WINDOW_SEC) -Default 300 -Min 60 -Max 1800
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_MAXIMIZE_WINDOW')) {
            $maximizeWindow = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_MAXIMIZE_WINDOW) -Default $true
            if (-not $maximizeWindow) {
                $invokeParams.NoMaximizeCodeWindow = $true
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT_ENABLED')) {
            $toggleEnabled = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT_ENABLED) -Default $false
            if (-not $toggleEnabled) {
                $invokeParams.NoChatToggleShortcut = $true
            }
            else {
                $invokeParams.EnableChatToggleShortcut = $true
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT')) {
            $toggleShortcut = Convert-ToSingleLineText -Text ([string]$Settings.AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT)
            if (-not [string]::IsNullOrWhiteSpace($toggleShortcut)) {
                $invokeParams.ChatToggleShortcut = $toggleShortcut
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_AUTO_RECONNECT_RESEND')) {
            $autoResendEnabled = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_AUTO_RECONNECT_RESEND) -Default $true
            if (-not $autoResendEnabled) {
                $invokeParams.NoAutoReconnectResend = $true
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_ESC_PREFLIGHT')) {
            $escPreflightEnabled = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_ESC_PREFLIGHT) -Default $false
            if ($escPreflightEnabled) {
                $invokeParams.EnableEscPreflight = $true
            }
        }
    }

    $eventNormalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    if ($eventNormalized -eq 'chat-session-heartbeat-timeout') {
        $invokeParams.NoPaletteFocusCommand = $true
    }

    if ($eventNormalized -eq 'running-status-report') {
        # Patrol/status messages should never fall back to whatever currently has focus.
        $invokeParams.NoPaletteFocusCommand = $true
        $invokeParams.NoClickFocusFallback = $true
        $invokeParams.ForceInvokeCodeChatFocus = $true
        $invokeParams.RequireCodeChatFocusSuccess = $true
    }

    if ($eventNormalized -eq 'chat-session-heartbeat-timeout' -and $HeartbeatTimeoutRequireCodeFocus) {
        $invokeParams.NoClickFocusFallback = $true
        $invokeParams.ForceInvokeCodeChatFocus = $true
        $invokeParams.RequireCodeChatFocusSuccess = $true
    }

    try {
        $sendResult = & $sendScriptPath @invokeParams
        if ($null -eq $sendResult) {
            return [pscustomobject]@{
                started = $true
                sent = $false
                exit_code = -1
                reason = 'send-script-no-output'
                attempt_count = 0
                auto_resend_triggered = $false
                auto_resend_reason = ''
                esc_preflight_enabled = $false
            }
        }

        $sent = [bool]$sendResult.sent
        $exitCode = Convert-ToIntRangeSetting -Value ([string]$sendResult.ahk_exit_code) -Default -1 -Min -1 -Max 9999

        $attemptCount = 0
        if ($sendResult.PSObject.Properties['dispatch_attempts'] -and $null -ne $sendResult.dispatch_attempts) {
            $attemptCount = @($sendResult.dispatch_attempts).Count
        }

        $autoResendTriggered = $false
        $autoResendReason = ''
        if ($sendResult.PSObject.Properties['auto_reconnect_resend'] -and $null -ne $sendResult.auto_reconnect_resend) {
            $autoResendTriggered = [bool]$sendResult.auto_reconnect_resend.triggered
            $autoResendReason = Convert-ToSingleLineText -Text ([string]$sendResult.auto_reconnect_resend.trigger_reason)
        }

        $escPreflightEnabled = $false
        if ($sendResult.PSObject.Properties['esc_preflight_enabled']) {
            $escPreflightEnabled = [bool]$sendResult.esc_preflight_enabled
        }
        elseif ($sendResult.PSObject.Properties['code_focus_policy'] -and $null -ne $sendResult.code_focus_policy) {
            if ($sendResult.code_focus_policy.PSObject.Properties['effective_esc_preflight']) {
                $escPreflightEnabled = [bool]$sendResult.code_focus_policy.effective_esc_preflight
            }
        }

        $sendNote = ''
        if ($sendResult.PSObject.Properties['note']) {
            $sendNote = Convert-ToSingleLineText -Text ([string]$sendResult.note)
        }

        $reason = 'ok'
        if ($sent -and $autoResendTriggered) {
            $reason = if ([string]::IsNullOrWhiteSpace($autoResendReason)) { 'ok-after-auto-resend' } else { ('ok-after-auto-resend:{0}' -f $autoResendReason) }
        }
        elseif (-not $sent) {
            $reason = if ($sendResult.PSObject.Properties['dispatch_attempts'] -and @($sendResult.dispatch_attempts).Count -gt 0) {
                Convert-ToSingleLineText -Text ([string]$sendResult.dispatch_attempts[-1].failure)
            }
            else {
                ''
            }

            if ([string]::IsNullOrWhiteSpace($reason)) {
                $reason = if ($exitCode -eq -1) { 'send-script-reported-unsent' } else { ('ahk-exit-{0}' -f $exitCode) }
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($sendNote)) {
            $reason = if ([string]::IsNullOrWhiteSpace($reason)) { ('note:{0}' -f $sendNote) } else { ('{0};note={1}' -f $reason, $sendNote) }
        }

        return [pscustomobject]@{
            started = $true
            sent = $sent
            exit_code = $exitCode
            reason = $reason
            attempt_count = $attemptCount
            auto_resend_triggered = $autoResendTriggered
            auto_resend_reason = $autoResendReason
            esc_preflight_enabled = $escPreflightEnabled
        }
    }
    catch {
        return [pscustomobject]@{
            started = $false
            sent = $false
            exit_code = -1
            reason = (Convert-ToSingleLineText -Text $_.Exception.Message)
            attempt_count = 0
            auto_resend_triggered = $false
            auto_resend_reason = ''
            esc_preflight_enabled = $false
        }
    }
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

$startSettings = [ordered]@{}
if (-not [string]::IsNullOrWhiteSpace($startFilePath) -and (Test-Path -LiteralPath $startFilePath)) {
    try {
        $startSettings = Read-KeyValueFile -Path $startFilePath
    }
    catch {
        Write-Warning ("[CHAT-DISPATCH] start_file_parse_failed path={0} detail={1}" -f (Convert-ToRepoRelativePath -Path $startFilePath), (Convert-ToSingleLineText -Text $_.Exception.Message))
    }
}

$openEditorByPolicy = $false
if ($startSettings.Contains('AI_CHAT_DISPATCH_OPEN_EDITOR')) {
    $openEditorByPolicy = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_OPEN_EDITOR) -Default $false
}
if ($OpenEditor.IsPresent) {
    $openEditorByPolicy = $true
}
if ($NoOpenEditor.IsPresent) {
    $openEditorByPolicy = $false
}

$useClipboardByPolicy = $false
if ($startSettings.Contains('AI_CHAT_DISPATCH_USE_CLIPBOARD')) {
    $useClipboardByPolicy = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_USE_CLIPBOARD) -Default $false
}
if ($UseClipboard.IsPresent) {
    $useClipboardByPolicy = $true
}
if ($SkipClipboard.IsPresent) {
    $useClipboardByPolicy = $false
}

$useAhkDispatch = $UseAhk.IsPresent
if (-not $useAhkDispatch -and $startSettings.Contains('AI_CHAT_DISPATCH_USE_AHK')) {
    $useAhkDispatch = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_USE_AHK) -Default $false
}

$configuredAhkPath = $AhkExePath
$strictConfiguredAhkPath = -not [string]::IsNullOrWhiteSpace((Convert-ToSingleLineText -Text $AhkExePath))
if ([string]::IsNullOrWhiteSpace($configuredAhkPath) -and $startSettings.Contains('AI_CHAT_DISPATCH_AHK_EXE')) {
    $configuredAhkPath = [string]$startSettings.AI_CHAT_DISPATCH_AHK_EXE
    $strictConfiguredAhkPath = $false
}

$ahkExecutable = ''
if ($useAhkDispatch) {
    $ahkExecutable = Resolve-AhkExecutablePath -ConfiguredPath $configuredAhkPath -StrictConfiguredPath:$strictConfiguredAhkPath
    if ([string]::IsNullOrWhiteSpace($ahkExecutable)) {
        if ($strictConfiguredAhkPath) {
            Write-DispatchLog ("ahk_dispatch_enabled_but_configured_executable_missing configured_path={0}" -f (Convert-ToSingleLineText -Text $configuredAhkPath))
        }
        else {
            Write-DispatchLog 'ahk_dispatch_enabled_but_executable_missing'
        }
    }
}

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
$statusReportInteractiveEnabled = $false
if ($startSettings.Contains('AI_CHAT_DISPATCH_STATUS_REPORT_INTERACTIVE')) {
    $statusReportInteractiveEnabled = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_STATUS_REPORT_INTERACTIVE) -Default $false
}
$heartbeatTimeoutSendEnabled = $false
if ($startSettings.Contains('AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_SEND_ENABLED')) {
    $heartbeatTimeoutSendEnabled = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_SEND_ENABLED) -Default $false
}
$heartbeatTimeoutRequireCodeFocus = $true
if ($startSettings.Contains('AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_REQUIRE_CODE_FOCUS')) {
    $heartbeatTimeoutRequireCodeFocus = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_REQUIRE_CODE_FOCUS) -Default $true
}
$suppressInteractiveActions = ($eventNormalized -eq 'running-status-report' -and -not $statusReportInteractiveEnabled)

$defaultAhkEventAllowList = @(
    'incident-captured',
    'recovery-await-confirmation',
    'auto-fix-await-confirmation',
    'chat-session-final-status'
)
$ahkEventAllowList = $defaultAhkEventAllowList
if ($startSettings.Contains('AI_CHAT_DISPATCH_AHK_EVENT_ALLOWLIST')) {
    $configuredAllowList = Split-EventListSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_AHK_EVENT_ALLOWLIST)
    if ($configuredAllowList.Count -gt 0) {
        $ahkEventAllowList = $configuredAllowList
    }
}

$ahkAllowedByEvent = Test-EventAllowedByList -EventName $eventNormalized -AllowList $ahkEventAllowList
$ahkSkipReason = ''
if ($eventNormalized -eq 'chat-session-heartbeat-timeout' -and -not $heartbeatTimeoutSendEnabled) {
    $ahkAllowedByEvent = $false
    $ahkSkipReason = 'heartbeat-timeout-send-disabled'
}

$runningStatusFullMessage = @'
从现在起，会话内代理进入阻塞式持续盯盘模式，不要结束会话，以监控与汇报为主；修改 start-file 用 UTF-8 编码；发现脚本故障可直接修复脚本，并可在预算内执行闭环自动修复代码（修复->重启->复核->记录）；工单从 LOCAL_GUARD_AGENT_QUEUE_PATH（默认 out/artifacts/ab_agent_queue/agent_tickets.jsonl）读取，并通过 tools/test/poll_agent_tickets.ps1 每轮主动拉取；每次取到工单后按先 business_command、后 continue_watch_command 的顺序逐条执行（business_command 为空则仅执行 continue_watch_command）；会话内需定时主动调用 tools/test/update_chat_session_heartbeat.ps1 发送心跳（建议每 5~10 分钟一次，并在关键恢复动作后补发一次），poll 保持读心跳模式（AI_CHAT_HEARTBEAT_WRITE_ON_POLL=false）；每 10 分钟汇报一次（包含 event_policy_strict_mode、event_policy_adjustments 与心跳摘要，文本标签为 chat_heartbeat，JSON 键为 chat_session_heartbeat）；若 strict 违规先修正 LOCAL_GUARD_POLL_* 配置再继续；仅在 A/B 都到终态或我明确下达“停止盯盘”时结束。
'@
if ($eventNormalized -eq 'running-status-report') {
    $firstMessage = "请接管工单 {0}（event={1}），先读取 {2} 与 {3}。{4}" -f $TicketId, $TicketEvent, $briefRel, $queueRel, $runningStatusFullMessage
}
else {
    $firstMessage = "请接管工单 {0}（event={1}），按 {2} 执行恢复：先读取 {3} 与 {4}，然后继续阻塞盯盘并按 D1 90/30/10/20 规则处理。" -f $TicketId, $TicketEvent, $startFileRel, $briefRel, $queueRel
}

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
if ($useClipboardByPolicy -and -not $suppressInteractiveActions) {
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
else {
    Write-DispatchLog ("skip_clipboard event={0} reason=disabled-by-policy" -f $TicketEvent)
}

$editorOpened = $false
$chatOpenTried = $false
$chatOpenStarted = $false
$ahkDispatchTried = $false
$ahkDispatchSent = $false
$ahkDispatchExitCode = -1
$ahkDispatchReason = ''
$ahkDispatchAttemptCount = 0
$ahkAutoResendTriggered = $false
$ahkAutoResendReason = ''
$ahkEscPreflightEnabled = $false

if ($openEditorByPolicy -and -not $suppressInteractiveActions) {
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
            Start-Process -FilePath $codeCommand.Source -ArgumentList @('--reuse-window', '--command', 'workbench.action.chat.open') -ErrorAction Stop | Out-Null
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
else {
    Write-DispatchLog ("skip_editor_and_chat_open event={0} reason=disabled-by-policy" -f $TicketEvent)
}

if ($useAhkDispatch -and -not $suppressInteractiveActions -and $ahkAllowedByEvent) {
    $ahkDispatchTried = $true
    $ahkResult = Invoke-AhkChatDispatch -AhkExecutable $ahkExecutable -Message $firstMessage -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus
    $ahkDispatchSent = [bool]$ahkResult.sent
    $ahkDispatchExitCode = [int]$ahkResult.exit_code
    $ahkDispatchReason = Convert-ToSingleLineText -Text ([string]$ahkResult.reason)
    $ahkDispatchAttemptCount = [int]$ahkResult.attempt_count
    $ahkAutoResendTriggered = [bool]$ahkResult.auto_resend_triggered
    $ahkAutoResendReason = Convert-ToSingleLineText -Text ([string]$ahkResult.auto_resend_reason)
    $ahkEscPreflightEnabled = [bool]$ahkResult.esc_preflight_enabled
    Write-DispatchLog ("ahk_dispatch_result ticket={0} sent={1} exit_code={2} reason={3} attempts={4} auto_resend_triggered={5} auto_resend_reason={6} esc_preflight_enabled={7}" -f $TicketId, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkDispatchAttemptCount, $ahkAutoResendTriggered, $ahkAutoResendReason, $ahkEscPreflightEnabled)
}
elseif ($useAhkDispatch -and -not $ahkAllowedByEvent) {
    if ([string]::IsNullOrWhiteSpace($ahkSkipReason)) {
        $ahkSkipReason = 'event-not-in-allowlist'
    }
    Write-DispatchLog ("ahk_dispatch_skipped event={0} reason={1} allowlist={2} heartbeat_timeout_send_enabled={3} heartbeat_timeout_require_code_focus={4}" -f $TicketEvent, $ahkSkipReason, (($ahkEventAllowList -join ';')), $heartbeatTimeoutSendEnabled, $heartbeatTimeoutRequireCodeFocus)
}
elseif ($useAhkDispatch) {
    Write-DispatchLog ("ahk_dispatch_skipped event={0} reason=status-report" -f $TicketEvent)
}

Write-DispatchLog ("relay_created ticket={0} event={1} relay={2} brief_exists={3} clipboard={4} clipboard_enabled={5} editor_opened={6} editor_enabled={7} chat_open_tried={8} chat_open_started={9} interactive_suppressed={10} status_report_interactive_enabled={11} use_ahk={12} ahk_allowed_by_event={13} ahk_event_allowlist={14} heartbeat_timeout_send_enabled={15} heartbeat_timeout_require_code_focus={16} ahk_tried={17} ahk_sent={18} ahk_exit_code={19} ahk_reason={20} ahk_esc_preflight_enabled={21}" -f $TicketId, $TicketEvent, $relayRel, $briefExists, $clipboardApplied, $useClipboardByPolicy, $editorOpened, $openEditorByPolicy, $chatOpenTried, $chatOpenStarted, $suppressInteractiveActions, $statusReportInteractiveEnabled, $useAhkDispatch, $ahkAllowedByEvent, (($ahkEventAllowList -join ';')), $heartbeatTimeoutSendEnabled, $heartbeatTimeoutRequireCodeFocus, $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkEscPreflightEnabled)
Write-Output ("[CHAT-DISPATCH] ticket={0} event={1} relay={2} first_message_in_clipboard={3} clipboard_enabled={4} editor_opened={5} editor_enabled={6} chat_open_started={7} interactive_suppressed={8}" -f $TicketId, $TicketEvent, $relayRel, $clipboardApplied, $useClipboardByPolicy, $editorOpened, $openEditorByPolicy, $chatOpenStarted, $suppressInteractiveActions)
Write-Output ("[CHAT-DISPATCH] use_ahk={0} status_report_interactive_enabled={1} ahk_allowed_by_event={2} ahk_event_allowlist={3} heartbeat_timeout_send_enabled={4} heartbeat_timeout_require_code_focus={5} ahk_tried={6} ahk_sent={7} ahk_exit_code={8} ahk_reason={9} ahk_attempts={10} ahk_auto_resend_triggered={11} ahk_auto_resend_reason={12} ahk_esc_preflight_enabled={13}" -f $useAhkDispatch, $statusReportInteractiveEnabled, $ahkAllowedByEvent, (($ahkEventAllowList -join ';')), $heartbeatTimeoutSendEnabled, $heartbeatTimeoutRequireCodeFocus, $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkDispatchAttemptCount, $ahkAutoResendTriggered, $ahkAutoResendReason, $ahkEscPreflightEnabled)

