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

function Get-CompactStatusToken {
    param([AllowEmptyString()][string]$Value)

    $token = (Convert-ToSingleLineText -Text $Value).ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($token)) {
        return 'UNKNOWN'
    }

    return $token
}

function Get-StageExitDigest {
    param([AllowEmptyString()][string]$StageName)

    $stageToken = (Convert-ToSingleLineText -Text $StageName).Trim().ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($stageToken)) {
        return ''
    }

    $stageLower = $stageToken.ToLowerInvariant()
    $artifactPath = Join-Path $script:RepoRoot (Join-Path 'out\artifacts\ab_stage_exit' ("latest_{0}_exit.json" -f $stageLower))
    if (-not (Test-Path -LiteralPath $artifactPath)) {
        return ''
    }

    try {
        $payload = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
        if ($null -eq $payload) {
            return ''
        }

        $result = (Convert-ToSingleLineText -Text ([string]$payload.result)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($result)) {
            return ''
        }

        $exitCode = -1
        if (-not [int]::TryParse(([string]$payload.exit_code), [ref]$exitCode)) {
            $exitCode = -1
        }

        if ($result -eq 'pass') {
            return ("{0}=PASS(exit={1})" -f $stageToken, $exitCode)
        }

        if ($result -eq 'fail') {
            $category = Convert-ToSingleLineText -Text ([string]$payload.fail_category)
            $reason = Convert-ToSingleLineText -Text ([string]$payload.fail_reason)
            if ($reason.Length -gt 96) {
                $reason = $reason.Substring(0, 96).TrimEnd() + '...'
            }

            $parts = New-Object 'System.Collections.Generic.List[string]'
            [void]$parts.Add(("{0}=FAIL(exit={1})" -f $stageToken, $exitCode))
            if (-not [string]::IsNullOrWhiteSpace($category)) {
                [void]$parts.Add(("cat={0}" -f $category))
            }
            if (-not [string]::IsNullOrWhiteSpace($reason)) {
                [void]$parts.Add(("reason={0}" -f $reason))
            }

            return ($parts -join ', ')
        }

        return ''
    }
    catch {
        return ''
    }
}

function Get-EnumSetting {
    param(
        [AllowEmptyString()][string]$Value,
        [string[]]$Allowed,
        [string]$Default
    )

    if ([string]::IsNullOrWhiteSpace($Default)) {
        $Default = ''
    }

    $allowedList = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($Allowed)) {
        $token = (Convert-ToSingleLineText -Text ([string]$item)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($token)) {
            continue
        }

        if (-not $allowedList.Contains($token)) {
            [void]$allowedList.Add($token)
        }
    }

    $defaultNormalized = (Convert-ToSingleLineText -Text $Default).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($defaultNormalized) -or -not $allowedList.Contains($defaultNormalized)) {
        $defaultNormalized = if ($allowedList.Count -gt 0) { [string]$allowedList[0] } else { '' }
    }

    $raw = (Convert-ToSingleLineText -Text $Value).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $defaultNormalized
    }

    if ($allowedList.Contains($raw)) {
        return $raw
    }

    return $defaultNormalized
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
        [bool]$HeartbeatTimeoutRequireCodeFocus = $true,
        [bool]$RestorePreviousForegroundWindow = $true,
        [int]$RestorePreviousForegroundWindowCount = 1,
        [bool]$ActiveWindowOnly = $false,
        [bool]$StatusReportForcePaletteFocus = $false,
        [bool]$ForceFocusRecovery = $false
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

    if ($RestorePreviousForegroundWindow) {
        $invokeParams.RestorePreviousForegroundWindow = $true
        $invokeParams.RestorePreviousWindowCount = [Math]::Min(30, [Math]::Max(1, $RestorePreviousForegroundWindowCount))
    }

    if ($ActiveWindowOnly) {
        $invokeParams.NoActivateWindow = $true
        $invokeParams.NoInvokeCodeChatFocus = $true
        $invokeParams.RequireActiveCodeWindow = $true
        $invokeParams.EnablePaletteFocusCommand = $true
        $invokeParams.NoClickFocusFallback = $true
        $invokeParams.NoMaximizeCodeWindow = $true
    }

    if ($null -ne $Settings) {
        if ($Settings.Contains('AI_CHAT_DISPATCH_RESET_ZOOM_BEFORE_SEND')) {
            $resetZoomBeforeSend = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_RESET_ZOOM_BEFORE_SEND) -Default $true
            if (-not $resetZoomBeforeSend) {
                $invokeParams.NoResetZoomBeforeSend = $true
            }
        }
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
        if ($StatusReportForcePaletteFocus) {
            $invokeParams.EnablePaletteFocusCommand = $true
            $invokeParams.UseClickFocusFallback = $true
            $invokeParams.NoInvokeCodeChatFocus = $true
            if ($invokeParams.ContainsKey('ForceInvokeCodeChatFocus')) {
                $invokeParams.Remove('ForceInvokeCodeChatFocus')
            }
            if ($invokeParams.ContainsKey('RequireCodeChatFocusSuccess')) {
                $invokeParams.Remove('RequireCodeChatFocusSuccess')
            }
            if ($invokeParams.ContainsKey('NoPaletteFocusCommand')) {
                $invokeParams.Remove('NoPaletteFocusCommand')
            }
        }
        else {
            $invokeParams.NoPaletteFocusCommand = $true
        }
        if ($ActiveWindowOnly) {
            $invokeParams.NoClickFocusFallback = $true
        }
        elseif (-not $StatusReportForcePaletteFocus) {
            $invokeParams.ForceInvokeCodeChatFocus = $true
            # First stage requires code command focus; if unavailable, dispatch layer
            # performs a second-stage palette fallback to keep delivery resilient.
            $invokeParams.RequireCodeChatFocusSuccess = $true
        }
    }

    if ($eventNormalized -eq 'chat-session-heartbeat-timeout' -and $HeartbeatTimeoutRequireCodeFocus) {
        $invokeParams.NoClickFocusFallback = $true
        if (-not $ActiveWindowOnly) {
            $invokeParams.ForceInvokeCodeChatFocus = $true
            $invokeParams.RequireCodeChatFocusSuccess = $true
        }
    }

    if ($ForceFocusRecovery) {
        # Failure-driven recovery path: reopen/focus chat input once and retry.
        $invokeParams.EnablePaletteFocusCommand = $true
        $invokeParams.UseClickFocusFallback = $true
        $invokeParams.NoInvokeCodeChatFocus = $true
        if ($invokeParams.ContainsKey('ForceInvokeCodeChatFocus')) {
            $invokeParams.Remove('ForceInvokeCodeChatFocus')
        }
        if ($invokeParams.ContainsKey('RequireCodeChatFocusSuccess')) {
            $invokeParams.Remove('RequireCodeChatFocusSuccess')
        }
        if ($invokeParams.ContainsKey('NoPaletteFocusCommand')) {
            $invokeParams.Remove('NoPaletteFocusCommand')
        }
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
                restore_previous_window_count_requested = 0
                restore_previous_window_count_captured = 0
                restore_previous_window_handles = ''
                restore_previous_window_capture_summary = ''
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

        $restorePreviousWindowCountRequested = 0
        $restorePreviousWindowCountCaptured = 0
        $restorePreviousWindowHandles = ''
        $restorePreviousWindowCaptureSummary = ''

        if ($sendResult.PSObject.Properties['code_focus_policy'] -and $null -ne $sendResult.code_focus_policy) {
            if ($sendResult.code_focus_policy.PSObject.Properties['restore_previous_window_count_requested']) {
                $restorePreviousWindowCountRequested = Convert-ToIntRangeSetting -Value ([string]$sendResult.code_focus_policy.restore_previous_window_count_requested) -Default 0 -Min 0 -Max 30
            }
            if ($sendResult.code_focus_policy.PSObject.Properties['restore_previous_window_count_captured']) {
                $restorePreviousWindowCountCaptured = Convert-ToIntRangeSetting -Value ([string]$sendResult.code_focus_policy.restore_previous_window_count_captured) -Default 0 -Min 0 -Max 30
            }
            if ($sendResult.code_focus_policy.PSObject.Properties['restore_previous_window_handles']) {
                $handles = @($sendResult.code_focus_policy.restore_previous_window_handles)
                if ($handles.Count -gt 0) {
                    $restorePreviousWindowHandles = Convert-ToSingleLineText -Text (($handles | ForEach-Object { [string]$_ }) -join ',')
                }
            }
            if ($sendResult.code_focus_policy.PSObject.Properties['restore_previous_window_capture_summary']) {
                $restorePreviousWindowCaptureSummary = Convert-ToSingleLineText -Text ([string]$sendResult.code_focus_policy.restore_previous_window_capture_summary)
            }
        }

        if ([string]::IsNullOrWhiteSpace($restorePreviousWindowHandles) -and $sendResult.PSObject.Properties['restore_previous_window_handles']) {
            $handles = @($sendResult.restore_previous_window_handles)
            if ($handles.Count -gt 0) {
                $restorePreviousWindowHandles = Convert-ToSingleLineText -Text (($handles | ForEach-Object { [string]$_ }) -join ',')
            }
        }
        if ([string]::IsNullOrWhiteSpace($restorePreviousWindowCaptureSummary) -and $sendResult.PSObject.Properties['restore_previous_window_capture_summary']) {
            $restorePreviousWindowCaptureSummary = Convert-ToSingleLineText -Text ([string]$sendResult.restore_previous_window_capture_summary)
        }
        if ($restorePreviousWindowCaptureSummary.Length -gt 1200) {
            $restorePreviousWindowCaptureSummary = $restorePreviousWindowCaptureSummary.Substring(0, 1200).TrimEnd() + '...'
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
            restore_previous_window_count_requested = $restorePreviousWindowCountRequested
            restore_previous_window_count_captured = $restorePreviousWindowCountCaptured
            restore_previous_window_handles = $restorePreviousWindowHandles
            restore_previous_window_capture_summary = $restorePreviousWindowCaptureSummary
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
            restore_previous_window_count_requested = 0
            restore_previous_window_count_captured = 0
            restore_previous_window_handles = ''
            restore_previous_window_capture_summary = ''
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

function Test-IsCodeGuiExecutablePath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    try {
        $fileName = [System.IO.Path]::GetFileName($Path)
        if ([string]::IsNullOrWhiteSpace($fileName)) {
            return $false
        }

        $normalized = $fileName.Trim().ToLowerInvariant()
        return ($normalized -eq 'code.exe' -or $normalized -eq 'code-insiders.exe')
    }
    catch {
        return $false
    }
}

function Resolve-CodeCliPath {
    $candidates = New-Object 'System.Collections.Generic.List[string]'

    foreach ($name in @('code.cmd', 'code-insiders.cmd', 'code')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
            [void]$candidates.Add([string]$command.Source)
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        [void]$candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code\bin\code.cmd'))
        [void]$candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code Insiders\bin\code-insiders.cmd'))
    }

    foreach ($candidate in @($candidates)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        try {
            $fullPath = [System.IO.Path]::GetFullPath($candidate)
            if (-not (Test-Path -LiteralPath $fullPath)) {
                continue
            }

            if (Test-IsCodeGuiExecutablePath -Path $fullPath) {
                $binLauncher = Join-Path (Join-Path (Split-Path -Parent $fullPath) 'bin') 'code.cmd'
                if (Test-Path -LiteralPath $binLauncher) {
                    return [System.IO.Path]::GetFullPath($binLauncher)
                }

                continue
            }

            return $fullPath
        }
        catch {
            continue
        }
    }

    return ''
}

function Get-CodeRendererWindowMap {
    $map = @{}

    $processes = Get-CimInstance Win32_Process -Filter "Name='Code.exe'" -ErrorAction SilentlyContinue
    foreach ($processItem in @($processes)) {
        $cmd = Convert-ToSingleLineText -Text ([string]$processItem.CommandLine)
        if ([string]::IsNullOrWhiteSpace($cmd)) {
            continue
        }

        if ($cmd -notmatch '(^|\s)--type=renderer(\s|$)') {
            continue
        }

        if ($cmd -notmatch '--vscode-window-config=([^\s]+)') {
            continue
        }

        $windowConfig = Convert-ToSingleLineText -Text ([string]$matches[1])
        if ([string]::IsNullOrWhiteSpace($windowConfig)) {
            continue
        }

        $processId = [int]$processItem.ProcessId
        if ($processId -le 0) {
            continue
        }

        if (-not $map.ContainsKey($windowConfig)) {
            $map[$windowConfig] = New-Object 'System.Collections.Generic.List[int]'
        }

        [void]$map[$windowConfig].Add($processId)
    }

    return $map
}

function Get-CodeMainProcessMap {
    $map = @{}

    $processes = Get-CimInstance Win32_Process -Filter "Name='Code.exe'" -ErrorAction SilentlyContinue
    foreach ($processItem in @($processes)) {
        $cmd = Convert-ToSingleLineText -Text ([string]$processItem.CommandLine)
        if ([string]::IsNullOrWhiteSpace($cmd)) {
            continue
        }

        $isTypedProcess = $cmd -match '(^|\s)--type='
        $isNodeIpcProcess = $cmd -match '--node-ipc'
        $isClientProcess = $cmd -match '--clientProcessId='
        if ($isTypedProcess -or $isNodeIpcProcess -or $isClientProcess) {
            continue
        }

        $processId = [int]$processItem.ProcessId
        if ($processId -le 0) {
            continue
        }

        $map[$processId] = $cmd
    }

    return $map
}

function Stop-ProcessListBestEffort {
    param([int[]]$ProcessIds)

    $stopped = New-Object 'System.Collections.Generic.List[int]'
    foreach ($processId in @($ProcessIds)) {
        if ($processId -le 0) {
            continue
        }

        try {
            Stop-Process -Id $processId -Force -ErrorAction Stop
            [void]$stopped.Add($processId)
        }
        catch {
        }
    }

    return $stopped.ToArray()
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
$statusReportMessageMode = 'short'
if ($startSettings.Contains('AI_CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE')) {
    $statusReportMessageMode = Get-EnumSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE) -Allowed @('short', 'full') -Default 'short'
}
$statusReportSendFullOnFirst = $true
if ($startSettings.Contains('AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST')) {
    $statusReportSendFullOnFirst = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST) -Default $true
}
$heartbeatTimeoutSendEnabled = $false
if ($startSettings.Contains('AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_SEND_ENABLED')) {
    $heartbeatTimeoutSendEnabled = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_SEND_ENABLED) -Default $false
}
$heartbeatTimeoutRequireCodeFocus = $true
if ($startSettings.Contains('AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_REQUIRE_CODE_FOCUS')) {
    $heartbeatTimeoutRequireCodeFocus = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_REQUIRE_CODE_FOCUS) -Default $true
}
$activeWindowOnly = $false
if ($startSettings.Contains('AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY')) {
    $activeWindowOnly = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY) -Default $false
}
$restorePreviousForegroundWindow = $true
if ($startSettings.Contains('AI_CHAT_DISPATCH_RESTORE_PREVIOUS_WINDOW_AFTER_SEND')) {
    $restorePreviousForegroundWindow = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_RESTORE_PREVIOUS_WINDOW_AFTER_SEND) -Default $restorePreviousForegroundWindow
}
$restorePreviousForegroundWindowCount = 1
if ($startSettings.Contains('AI_CHAT_DISPATCH_RESTORE_PREVIOUS_WINDOW_COUNT')) {
    $restorePreviousForegroundWindowCount = Convert-ToIntRangeSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_RESTORE_PREVIOUS_WINDOW_COUNT) -Default 1 -Min 1 -Max 30
}
$statusReportMessageStatePath = Join-Path $dispatchRoot ("status_report_message_state_{0}.json" -f $startToken)
$statusReportState = [ordered]@{
    schema = 'AB_STATUS_REPORT_MESSAGE_STATE_V1'
    updated_at = ''
    full_sent_once = $false
    first_full_ticket_id = ''
    last_ticket_id = ''
    last_mode = ''
}
if (Test-Path -LiteralPath $statusReportMessageStatePath) {
    try {
        $rawState = Get-Content -LiteralPath $statusReportMessageStatePath -Raw -Encoding utf8 | ConvertFrom-Json
        if ($null -ne $rawState) {
            if ($rawState.PSObject.Properties['schema']) { $statusReportState.schema = Convert-ToSingleLineText -Text ([string]$rawState.schema) }
            if ($rawState.PSObject.Properties['updated_at']) { $statusReportState.updated_at = Convert-ToSingleLineText -Text ([string]$rawState.updated_at) }
            if ($rawState.PSObject.Properties['full_sent_once']) { $statusReportState.full_sent_once = [bool]$rawState.full_sent_once }
            if ($rawState.PSObject.Properties['first_full_ticket_id']) { $statusReportState.first_full_ticket_id = Convert-ToSingleLineText -Text ([string]$rawState.first_full_ticket_id) }
            if ($rawState.PSObject.Properties['last_ticket_id']) { $statusReportState.last_ticket_id = Convert-ToSingleLineText -Text ([string]$rawState.last_ticket_id) }
            if ($rawState.PSObject.Properties['last_mode']) { $statusReportState.last_mode = Convert-ToSingleLineText -Text ([string]$rawState.last_mode) }
        }
    }
    catch {
        Write-DispatchLog ("status_report_message_state_parse_failed path={0} detail={1}" -f (Convert-ToRepoRelativePath -Path $statusReportMessageStatePath), (Convert-ToSingleLineText -Text $_.Exception.Message))
    }
}
$suppressInteractiveActions = ($eventNormalized -eq 'running-status-report' -and -not $statusReportInteractiveEnabled)

$sessionStatus = ''
if ($startSettings.Contains('SESSION_FINAL_STATUS')) {
    $sessionStatus = (Convert-ToSingleLineText -Text ([string]$startSettings.SESSION_FINAL_STATUS)).ToUpperInvariant()
}
$aStatus = ''
if ($startSettings.Contains('A_FINAL_STATUS')) {
    $aStatus = (Convert-ToSingleLineText -Text ([string]$startSettings.A_FINAL_STATUS)).ToUpperInvariant()
}
$bStatus = ''
if ($startSettings.Contains('B_FINAL_STATUS')) {
    $bStatus = (Convert-ToSingleLineText -Text ([string]$startSettings.B_FINAL_STATUS)).ToUpperInvariant()
}
$sessionClosedByFlagRaw = $false
if ($startSettings.Contains('SESSION_CLOSED')) {
    $sessionClosedByFlagRaw = Convert-ToBooleanSetting -Value ([string]$startSettings.SESSION_CLOSED) -Default $false
}
$sessionClosedByPassFinal = ($sessionStatus -eq 'PASS') -or ($aStatus -eq 'PASS' -and $bStatus -eq 'PASS')
$sessionClosedByFlag = $sessionClosedByFlagRaw -and $sessionClosedByPassFinal
$sessionClosedGate = $sessionClosedByPassFinal -or $sessionClosedByFlag

$runningStatusStateSummary = "SESSION={0}, A={1}, B={2}" -f (Get-CompactStatusToken -Value $sessionStatus), (Get-CompactStatusToken -Value $aStatus), (Get-CompactStatusToken -Value $bStatus)
$runningStatusBExitDigest = Get-StageExitDigest -StageName 'B'
$runningStatusShortSummary = if ([string]::IsNullOrWhiteSpace($runningStatusBExitDigest)) {
    $runningStatusStateSummary
}
else {
    "{0}; {1}" -f $runningStatusStateSummary, $runningStatusBExitDigest
}

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
$runningStatusShortMessage = '请接管工单 {0}（event={1}），先读取 {2} 与 {3}；这是每10分钟状态票，请按既定阻塞盯盘流程执行（business_command -> continue_watch_command，business 为空则仅 continue），并回传 chat_heartbeat。状态摘要：{4}。'
$runningStatusUseFullMessage = $false
$runningStatusEffectiveMode = 'n/a'
if ($eventNormalized -eq 'running-status-report') {
    $runningStatusEffectiveMode = 'short'
    if ($statusReportMessageMode -eq 'full') {
        $runningStatusUseFullMessage = $true
        $runningStatusEffectiveMode = 'full'
    }
    elseif ($statusReportSendFullOnFirst -and -not [bool]$statusReportState.full_sent_once) {
        $runningStatusUseFullMessage = $true
        $runningStatusEffectiveMode = 'full-first'
    }
}
if ($eventNormalized -eq 'running-status-report') {
    if ($runningStatusUseFullMessage) {
        $firstMessage = "请接管工单 {0}（event={1}），先读取 {2} 与 {3}。{4}" -f $TicketId, $TicketEvent, $briefRel, $queueRel, $runningStatusFullMessage
    }
    else {
        $firstMessage = $runningStatusShortMessage -f $TicketId, $TicketEvent, $briefRel, $queueRel, $runningStatusShortSummary
    }
}
else {
    $firstMessage = "请接管工单 {0}（event={1}），按 {2} 执行恢复：先读取 {3} 与 {4}，然后继续阻塞盯盘并按 D1 90/30/10/20 规则处理。" -f $TicketId, $TicketEvent, $startFileRel, $briefRel, $queueRel
}

$resumeCommand = ''
$guardCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}" -NoRestartIfRunning' -f $startFileRel
if ($eventNormalized -ne 'running-status-report' -and $eventNormalized -ne 'chat-session-final-status' -and -not $sessionClosedGate) {
    $resumeCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_resume_window.ps1 -StartFile "{0}" -StartMonitors' -f $startFileRel
    $guardCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}"' -f $startFileRel
}

$fallbackCommands = New-Object 'System.Collections.Generic.List[string]'
if (-not [string]::IsNullOrWhiteSpace($resumeCommand)) {
    [void]$fallbackCommands.Add($resumeCommand)
}
if (-not [string]::IsNullOrWhiteSpace($guardCommand)) {
    [void]$fallbackCommands.Add($guardCommand)
}
if ($fallbackCommands.Count -lt 1) {
    [void]$fallbackCommands.Add('# no fallback command')
}

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
    ('status_report_message_mode={0}' -f $statusReportMessageMode),
    ('status_report_send_full_on_first={0}' -f $statusReportSendFullOnFirst),
    ('status_report_effective_message={0}' -f $runningStatusEffectiveMode),
    '',
    'first_message:',
    $firstMessage,
    '',
    'fallback_commands:'
)
$relayLines += @($fallbackCommands.ToArray())
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
    status_report_message_mode = $statusReportMessageMode
    status_report_send_full_on_first = $statusReportSendFullOnFirst
    status_report_effective_message = $runningStatusEffectiveMode
    first_message = $firstMessage
}
$latestState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $latestStatePath -Encoding utf8

if ($eventNormalized -eq 'running-status-report') {
    $statusReportState.updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $statusReportState.last_ticket_id = $TicketId
    $statusReportState.last_mode = $runningStatusEffectiveMode
    if ($runningStatusUseFullMessage -and -not [bool]$statusReportState.full_sent_once) {
        $statusReportState.full_sent_once = $true
        $statusReportState.first_full_ticket_id = $TicketId
    }

    try {
        $statusReportState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statusReportMessageStatePath -Encoding utf8
    }
    catch {
        Write-DispatchLog ("status_report_message_state_write_failed path={0} detail={1}" -f (Convert-ToRepoRelativePath -Path $statusReportMessageStatePath), (Convert-ToSingleLineText -Text $_.Exception.Message))
    }
}

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
$ahkRestorePreviousWindowCountRequested = 0
$ahkRestorePreviousWindowCountCaptured = 0
$ahkRestorePreviousWindowHandles = ''
$ahkRestorePreviousWindowCaptureSummary = ''
$ahkFallbackTriggered = $false
$ahkFallbackSent = $false
$ahkFallbackExitCode = -1
$ahkFallbackReason = ''
$ahkPaletteFallbackTriggered = $false
$ahkPaletteFallbackSent = $false
$ahkPaletteFallbackExitCode = -1
$ahkPaletteFallbackReason = ''
$ahkFocusGuardFallbackTriggered = $false
$ahkFocusGuardFallbackSent = $false
$ahkFocusGuardFallbackExitCode = -1
$ahkFocusGuardFallbackReason = ''
$newCodeMainDetected = @()
$newCodeMainClosed = @()
$newCodeWindowConfigsDetected = @()
$newCodeWindowPidsDetected = @()
$newCodeWindowPidsClosed = @()
$codeMainBefore = @{}
$codeRendererBefore = @{}

if ($activeWindowOnly) {
    $codeMainBefore = Get-CodeMainProcessMap
    $codeRendererBefore = Get-CodeRendererWindowMap
}

if ($openEditorByPolicy -and -not $suppressInteractiveActions) {
    $codeCliPath = Resolve-CodeCliPath
    if (-not [string]::IsNullOrWhiteSpace($codeCliPath)) {
        try {
            $openArgs = @('-r', $relayPath)
            if ($briefExists) {
                $openArgs += $briefFilePath
            }
            Start-Process -FilePath $codeCliPath -ArgumentList $openArgs -ErrorAction Stop | Out-Null
            $editorOpened = $true
        }
        catch {
            Write-DispatchLog ("editor_open_failed detail={0}" -f (Convert-ToSingleLineText -Text $_.Exception.Message))
        }

        try {
            $chatOpenTried = $true
            Start-Process -FilePath $codeCliPath -ArgumentList @('--reuse-window', '--command', 'workbench.action.chat.open') -ErrorAction Stop | Out-Null
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
    $ahkResult = Invoke-AhkChatDispatch -AhkExecutable $ahkExecutable -Message $firstMessage -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $activeWindowOnly
    $ahkDispatchSent = [bool]$ahkResult.sent
    $ahkDispatchExitCode = [int]$ahkResult.exit_code
    $ahkDispatchReason = Convert-ToSingleLineText -Text ([string]$ahkResult.reason)
    $ahkDispatchAttemptCount = [int]$ahkResult.attempt_count
    $ahkAutoResendTriggered = [bool]$ahkResult.auto_resend_triggered
    $ahkAutoResendReason = Convert-ToSingleLineText -Text ([string]$ahkResult.auto_resend_reason)
    $ahkEscPreflightEnabled = [bool]$ahkResult.esc_preflight_enabled
    $ahkRestorePreviousWindowCountRequested = [int]$ahkResult.restore_previous_window_count_requested
    $ahkRestorePreviousWindowCountCaptured = [int]$ahkResult.restore_previous_window_count_captured
    $ahkRestorePreviousWindowHandles = Convert-ToSingleLineText -Text ([string]$ahkResult.restore_previous_window_handles)
    $ahkRestorePreviousWindowCaptureSummary = Convert-ToSingleLineText -Text ([string]$ahkResult.restore_previous_window_capture_summary)

    $shouldRetryWithoutActiveWindow = $activeWindowOnly -and (-not $ahkDispatchSent) -and ($eventNormalized -eq 'running-status-report') -and (($ahkDispatchExitCode -eq 40) -or ($ahkDispatchReason -like '*active-code-window-required*'))
    if ($shouldRetryWithoutActiveWindow) {
        $ahkFallbackTriggered = $true
        Write-DispatchLog ("ahk_dispatch_retry ticket={0} reason=active-window-only-blocked retry_active_window_only=false" -f $TicketId)

        $fallbackResult = Invoke-AhkChatDispatch -AhkExecutable $ahkExecutable -Message $firstMessage -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $false
        $ahkFallbackSent = [bool]$fallbackResult.sent
        $ahkFallbackExitCode = [int]$fallbackResult.exit_code
        $ahkFallbackReason = Convert-ToSingleLineText -Text ([string]$fallbackResult.reason)

        if ($ahkFallbackSent) {
            $ahkDispatchSent = $ahkFallbackSent
            $ahkDispatchExitCode = $ahkFallbackExitCode
            $ahkDispatchReason = $ahkFallbackReason
            $ahkDispatchAttemptCount = [int]$fallbackResult.attempt_count
            $ahkAutoResendTriggered = [bool]$fallbackResult.auto_resend_triggered
            $ahkAutoResendReason = Convert-ToSingleLineText -Text ([string]$fallbackResult.auto_resend_reason)
            $ahkEscPreflightEnabled = [bool]$fallbackResult.esc_preflight_enabled
            $ahkRestorePreviousWindowCountRequested = [int]$fallbackResult.restore_previous_window_count_requested
            $ahkRestorePreviousWindowCountCaptured = [int]$fallbackResult.restore_previous_window_count_captured
            $ahkRestorePreviousWindowHandles = Convert-ToSingleLineText -Text ([string]$fallbackResult.restore_previous_window_handles)
            $ahkRestorePreviousWindowCaptureSummary = Convert-ToSingleLineText -Text ([string]$fallbackResult.restore_previous_window_capture_summary)
        }
        else {
            if ([string]::IsNullOrWhiteSpace($ahkFallbackReason)) {
                $ahkFallbackReason = 'fallback-unsent'
            }
            if ([string]::IsNullOrWhiteSpace($ahkDispatchReason)) {
                $ahkDispatchReason = ('fallback={0}' -f $ahkFallbackReason)
            }
            else {
                $ahkDispatchReason = ('{0};fallback={1}' -f $ahkDispatchReason, $ahkFallbackReason)
            }
        }

        Write-DispatchLog ("ahk_dispatch_retry_result ticket={0} sent={1} exit_code={2} reason={3}" -f $TicketId, $ahkFallbackSent, $ahkFallbackExitCode, $ahkFallbackReason)
    }

    $shouldRetryWithPaletteFocus = (-not $ahkDispatchSent) -and ($eventNormalized -eq 'running-status-report') -and (($ahkDispatchExitCode -eq 39) -or ($ahkDispatchReason -like '*required-code-chat-focus*'))
    if ($shouldRetryWithPaletteFocus) {
        $ahkPaletteFallbackTriggered = $true
        Write-DispatchLog ("ahk_dispatch_palette_retry ticket={0} reason=focus-validation-failed" -f $TicketId)

        $paletteFallbackResult = Invoke-AhkChatDispatch -AhkExecutable $ahkExecutable -Message $firstMessage -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $false -StatusReportForcePaletteFocus $true
        $ahkPaletteFallbackSent = [bool]$paletteFallbackResult.sent
        $ahkPaletteFallbackExitCode = [int]$paletteFallbackResult.exit_code
        $ahkPaletteFallbackReason = Convert-ToSingleLineText -Text ([string]$paletteFallbackResult.reason)

        if ($ahkPaletteFallbackSent) {
            $ahkDispatchSent = $ahkPaletteFallbackSent
            $ahkDispatchExitCode = $ahkPaletteFallbackExitCode
            $ahkDispatchReason = $ahkPaletteFallbackReason
            $ahkDispatchAttemptCount = [int]$paletteFallbackResult.attempt_count
            $ahkAutoResendTriggered = [bool]$paletteFallbackResult.auto_resend_triggered
            $ahkAutoResendReason = Convert-ToSingleLineText -Text ([string]$paletteFallbackResult.auto_resend_reason)
            $ahkEscPreflightEnabled = [bool]$paletteFallbackResult.esc_preflight_enabled
            $ahkRestorePreviousWindowCountRequested = [int]$paletteFallbackResult.restore_previous_window_count_requested
            $ahkRestorePreviousWindowCountCaptured = [int]$paletteFallbackResult.restore_previous_window_count_captured
            $ahkRestorePreviousWindowHandles = Convert-ToSingleLineText -Text ([string]$paletteFallbackResult.restore_previous_window_handles)
            $ahkRestorePreviousWindowCaptureSummary = Convert-ToSingleLineText -Text ([string]$paletteFallbackResult.restore_previous_window_capture_summary)
        }
        else {
            if ([string]::IsNullOrWhiteSpace($ahkPaletteFallbackReason)) {
                $ahkPaletteFallbackReason = 'palette-fallback-unsent'
            }
            if ([string]::IsNullOrWhiteSpace($ahkDispatchReason)) {
                $ahkDispatchReason = ('palette_fallback={0}' -f $ahkPaletteFallbackReason)
            }
            else {
                $ahkDispatchReason = ('{0};palette_fallback={1}' -f $ahkDispatchReason, $ahkPaletteFallbackReason)
            }
        }

        Write-DispatchLog ("ahk_dispatch_palette_retry_result ticket={0} sent={1} exit_code={2} reason={3}" -f $TicketId, $ahkPaletteFallbackSent, $ahkPaletteFallbackExitCode, $ahkPaletteFallbackReason)
    }

    $focusGuardReason = (Convert-ToSingleLineText -Text $ahkDispatchReason).ToLowerInvariant()
    $suppressFocusGuardRecovery = ($eventNormalized -eq 'running-status-report') -and ($ahkDispatchAttemptCount -gt 1 -or $ahkAutoResendTriggered)
    if ($suppressFocusGuardRecovery) {
        Write-DispatchLog ("ahk_dispatch_focus_guard_retry_suppressed ticket={0} reason=already-retried attempts={1} auto_resend_triggered={2}" -f $TicketId, $ahkDispatchAttemptCount, $ahkAutoResendTriggered)
    }

    $shouldRetryWithFocusGuardRecovery = (-not $suppressFocusGuardRecovery) -and (-not $ahkDispatchSent) -and (
        ($ahkDispatchExitCode -in @(38, 41)) -or
        ($focusGuardReason -like '*chat input was not focused*') -or
        ($focusGuardReason -like '*chat input caret is not in expected area*') -or
        ($focusGuardReason -like '*ahk-exit-38*') -or
        ($focusGuardReason -like '*ahk-exit-41*')
    )
    if ($shouldRetryWithFocusGuardRecovery) {
        $ahkFocusGuardFallbackTriggered = $true
        Write-DispatchLog ("ahk_dispatch_focus_guard_retry ticket={0} reason=focus-guard-failed retry_active_window_only=false force_focus_recovery=true" -f $TicketId)

        $focusGuardFallbackResult = Invoke-AhkChatDispatch -AhkExecutable $ahkExecutable -Message $firstMessage -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $false -ForceFocusRecovery $true
        $ahkFocusGuardFallbackSent = [bool]$focusGuardFallbackResult.sent
        $ahkFocusGuardFallbackExitCode = [int]$focusGuardFallbackResult.exit_code
        $ahkFocusGuardFallbackReason = Convert-ToSingleLineText -Text ([string]$focusGuardFallbackResult.reason)

        if ($ahkFocusGuardFallbackSent) {
            $ahkDispatchSent = $ahkFocusGuardFallbackSent
            $ahkDispatchExitCode = $ahkFocusGuardFallbackExitCode
            $ahkDispatchReason = $ahkFocusGuardFallbackReason
            $ahkDispatchAttemptCount = [int]$focusGuardFallbackResult.attempt_count
            $ahkAutoResendTriggered = [bool]$focusGuardFallbackResult.auto_resend_triggered
            $ahkAutoResendReason = Convert-ToSingleLineText -Text ([string]$focusGuardFallbackResult.auto_resend_reason)
            $ahkEscPreflightEnabled = [bool]$focusGuardFallbackResult.esc_preflight_enabled
            $ahkRestorePreviousWindowCountRequested = [int]$focusGuardFallbackResult.restore_previous_window_count_requested
            $ahkRestorePreviousWindowCountCaptured = [int]$focusGuardFallbackResult.restore_previous_window_count_captured
            $ahkRestorePreviousWindowHandles = Convert-ToSingleLineText -Text ([string]$focusGuardFallbackResult.restore_previous_window_handles)
            $ahkRestorePreviousWindowCaptureSummary = Convert-ToSingleLineText -Text ([string]$focusGuardFallbackResult.restore_previous_window_capture_summary)
        }
        else {
            if ([string]::IsNullOrWhiteSpace($ahkFocusGuardFallbackReason)) {
                $ahkFocusGuardFallbackReason = 'focus-guard-fallback-unsent'
            }
            if ([string]::IsNullOrWhiteSpace($ahkDispatchReason)) {
                $ahkDispatchReason = ('focus_guard_fallback={0}' -f $ahkFocusGuardFallbackReason)
            }
            else {
                $ahkDispatchReason = ('{0};focus_guard_fallback={1}' -f $ahkDispatchReason, $ahkFocusGuardFallbackReason)
            }
        }

        Write-DispatchLog ("ahk_dispatch_focus_guard_retry_result ticket={0} sent={1} exit_code={2} reason={3}" -f $TicketId, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason)
    }

    if ($activeWindowOnly) {
        $codeMainAfter = Get-CodeMainProcessMap
        $newCodeMainDetected = @($codeMainAfter.Keys | Where-Object { -not $codeMainBefore.ContainsKey([int]$_) } | ForEach-Object { [int]$_ })
        if ($newCodeMainDetected.Count -gt 0) {
            $newCmds = @($newCodeMainDetected | ForEach-Object { Convert-ToSingleLineText -Text ([string]$codeMainAfter[[int]$_]) })
            Write-DispatchLog ("new_code_main_detected pids={0} commands={1}" -f ($newCodeMainDetected -join ','), (Convert-ToSingleLineText -Text ($newCmds -join ' || ')))

            $newCodeMainClosed = @(Stop-ProcessListBestEffort -ProcessIds $newCodeMainDetected)
            if ($newCodeMainClosed.Count -gt 0) {
                Write-DispatchLog ("new_code_main_closed pids={0}" -f ($newCodeMainClosed -join ','))
            }

            $ahkDispatchSent = $false
            if ($ahkDispatchExitCode -eq 0) {
                $ahkDispatchExitCode = 42
            }
            if ([string]::IsNullOrWhiteSpace($ahkDispatchReason) -or $ahkDispatchReason -eq 'ok') {
                $ahkDispatchReason = 'new-code-main-instance-detected'
            }
            else {
                $ahkDispatchReason = ("{0};new-code-main-instance-detected" -f $ahkDispatchReason)
            }
        }

        $codeRendererAfter = Get-CodeRendererWindowMap
        $newCodeWindowConfigsDetected = @($codeRendererAfter.Keys | Where-Object { -not $codeRendererBefore.ContainsKey([string]$_) } | Sort-Object)
        if ($newCodeWindowConfigsDetected.Count -gt 0) {
            $pidCollector = New-Object 'System.Collections.Generic.List[int]'
            foreach ($windowConfig in @($newCodeWindowConfigsDetected)) {
                foreach ($rendererPid in @($codeRendererAfter[$windowConfig])) {
                    $pidValue = [int]$rendererPid
                    if ($pidValue -gt 0 -and -not $pidCollector.Contains($pidValue)) {
                        [void]$pidCollector.Add($pidValue)
                    }
                }
            }

            $newCodeWindowPidsDetected = $pidCollector.ToArray()
            Write-DispatchLog ("new_code_window_detected configs={0} pids={1}" -f (($newCodeWindowConfigsDetected -join ',')), (($newCodeWindowPidsDetected -join ',')))

            if ($newCodeWindowPidsDetected.Count -gt 0) {
                $newCodeWindowPidsClosed = @(Stop-ProcessListBestEffort -ProcessIds $newCodeWindowPidsDetected)
                if ($newCodeWindowPidsClosed.Count -gt 0) {
                    Write-DispatchLog ("new_code_window_closed pids={0}" -f ($newCodeWindowPidsClosed -join ','))
                }
            }

            $ahkDispatchSent = $false
            if ($ahkDispatchExitCode -eq 0) {
                $ahkDispatchExitCode = 42
            }
            if ([string]::IsNullOrWhiteSpace($ahkDispatchReason) -or $ahkDispatchReason -eq 'ok') {
                $ahkDispatchReason = 'new-code-window-detected'
            }
            else {
                $ahkDispatchReason = ("{0};new-code-window-detected" -f $ahkDispatchReason)
            }
        }
    }

    Write-DispatchLog ("ahk_dispatch_result ticket={0} sent={1} exit_code={2} reason={3} attempts={4} auto_resend_triggered={5} auto_resend_reason={6} esc_preflight_enabled={7} restore_requested={8} restore_captured={9} restore_handles={10}" -f $TicketId, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkDispatchAttemptCount, $ahkAutoResendTriggered, $ahkAutoResendReason, $ahkEscPreflightEnabled, $ahkRestorePreviousWindowCountRequested, $ahkRestorePreviousWindowCountCaptured, $ahkRestorePreviousWindowHandles)
    if (-not [string]::IsNullOrWhiteSpace($ahkRestorePreviousWindowCaptureSummary)) {
        Write-DispatchLog ("ahk_dispatch_restore_trace ticket={0} trace={1}" -f $TicketId, $ahkRestorePreviousWindowCaptureSummary)
    }
    if ($ahkFallbackTriggered) {
        Write-DispatchLog ("ahk_dispatch_fallback ticket={0} fallback_sent={1} fallback_exit_code={2} fallback_reason={3}" -f $TicketId, $ahkFallbackSent, $ahkFallbackExitCode, $ahkFallbackReason)
    }
    if ($ahkPaletteFallbackTriggered) {
        Write-DispatchLog ("ahk_dispatch_palette_fallback ticket={0} fallback_sent={1} fallback_exit_code={2} fallback_reason={3}" -f $TicketId, $ahkPaletteFallbackSent, $ahkPaletteFallbackExitCode, $ahkPaletteFallbackReason)
    }
    if ($ahkFocusGuardFallbackTriggered) {
        Write-DispatchLog ("ahk_dispatch_focus_guard_fallback ticket={0} fallback_sent={1} fallback_exit_code={2} fallback_reason={3}" -f $TicketId, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason)
    }
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

Write-DispatchLog ("relay_created ticket={0} event={1} relay={2} brief_exists={3} clipboard={4} clipboard_enabled={5} editor_opened={6} editor_enabled={7} chat_open_tried={8} chat_open_started={9} interactive_suppressed={10} status_report_interactive_enabled={11} use_ahk={12} ahk_allowed_by_event={13} ahk_event_allowlist={14} heartbeat_timeout_send_enabled={15} heartbeat_timeout_require_code_focus={16} active_window_only={17} new_code_main_detected={18} new_code_main_closed={19} new_code_window_configs_detected={20} new_code_window_pids_closed={21} ahk_tried={22} ahk_sent={23} ahk_exit_code={24} ahk_reason={25} ahk_esc_preflight_enabled={26} ahk_focus_guard_fallback_triggered={27} ahk_focus_guard_fallback_sent={28} ahk_focus_guard_fallback_exit_code={29} ahk_focus_guard_fallback_reason={30} ahk_restore_requested={31} ahk_restore_captured={32} ahk_restore_handles={33}" -f $TicketId, $TicketEvent, $relayRel, $briefExists, $clipboardApplied, $useClipboardByPolicy, $editorOpened, $openEditorByPolicy, $chatOpenTried, $chatOpenStarted, $suppressInteractiveActions, $statusReportInteractiveEnabled, $useAhkDispatch, $ahkAllowedByEvent, (($ahkEventAllowList -join ';')), $heartbeatTimeoutSendEnabled, $heartbeatTimeoutRequireCodeFocus, $activeWindowOnly, ($newCodeMainDetected -join ','), ($newCodeMainClosed -join ','), ($newCodeWindowConfigsDetected -join ','), ($newCodeWindowPidsClosed -join ','), $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkEscPreflightEnabled, $ahkFocusGuardFallbackTriggered, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason, $ahkRestorePreviousWindowCountRequested, $ahkRestorePreviousWindowCountCaptured, $ahkRestorePreviousWindowHandles)
Write-Output ("[CHAT-DISPATCH] ticket={0} event={1} relay={2} first_message_in_clipboard={3} clipboard_enabled={4} editor_opened={5} editor_enabled={6} chat_open_started={7} interactive_suppressed={8}" -f $TicketId, $TicketEvent, $relayRel, $clipboardApplied, $useClipboardByPolicy, $editorOpened, $openEditorByPolicy, $chatOpenStarted, $suppressInteractiveActions)
Write-Output ("[CHAT-DISPATCH] use_ahk={0} status_report_interactive_enabled={1} ahk_allowed_by_event={2} ahk_event_allowlist={3} heartbeat_timeout_send_enabled={4} heartbeat_timeout_require_code_focus={5} active_window_only={6} new_code_main_detected={7} new_code_main_closed={8} new_code_window_configs_detected={9} new_code_window_pids_closed={10} ahk_tried={11} ahk_sent={12} ahk_exit_code={13} ahk_reason={14} ahk_attempts={15} ahk_auto_resend_triggered={16} ahk_auto_resend_reason={17} ahk_esc_preflight_enabled={18} ahk_focus_guard_fallback_triggered={19} ahk_focus_guard_fallback_sent={20} ahk_focus_guard_fallback_exit_code={21} ahk_focus_guard_fallback_reason={22} ahk_restore_requested={23} ahk_restore_captured={24} ahk_restore_handles={25}" -f $useAhkDispatch, $statusReportInteractiveEnabled, $ahkAllowedByEvent, (($ahkEventAllowList -join ';')), $heartbeatTimeoutSendEnabled, $heartbeatTimeoutRequireCodeFocus, $activeWindowOnly, ($newCodeMainDetected -join ','), ($newCodeMainClosed -join ','), ($newCodeWindowConfigsDetected -join ','), ($newCodeWindowPidsClosed -join ','), $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkDispatchAttemptCount, $ahkAutoResendTriggered, $ahkAutoResendReason, $ahkEscPreflightEnabled, $ahkFocusGuardFallbackTriggered, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason, $ahkRestorePreviousWindowCountRequested, $ahkRestorePreviousWindowCountCaptured, $ahkRestorePreviousWindowHandles)

