Set-StrictMode -Version Latest

function Convert-ToPolicyToken {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    return ([regex]::Replace([string]$Value, '\s+', ' ')).Trim().ToLowerInvariant()
}

function Convert-ToPolicyBooleanSetting {
    param(
        [AllowEmptyString()][string]$Value,
        [bool]$Default = $false
    )

    $token = Convert-ToPolicyToken -Value $Value
    if ([string]::IsNullOrWhiteSpace($token)) {
        return $Default
    }

    return $token -in @('1', 'true', 'yes', 'on')
}

function Convert-PolicyBooleanToText {
    param([bool]$Value)

    if ($Value) {
        return 'true'
    }

    return 'false'
}

function Resolve-ChatPolicyWorkMode {
    param(
        [AllowEmptyString()][string]$RawValue,
        [string]$DefaultValue = 'normal'
    )

    $token = Convert-ToPolicyToken -Value $RawValue
    if ([string]::IsNullOrWhiteSpace($token)) {
        return $DefaultValue
    }

    switch ($token) {
        'normal' { return 'normal' }
        'anti-missent' { return 'anti-missent' }
        'anti_missent' { return 'anti-missent' }
        'anti-mis-send' { return 'anti-missent' }
        'antimissent' { return 'anti-missent' }
        'low-disturb' { return 'low-disturb' }
        'low_disturb' { return 'low-disturb' }
        'lowdisturb' { return 'low-disturb' }
        'event-only' { return 'event-only' }
        'event_only' { return 'event-only' }
        'eventonly' { return 'event-only' }
        'event-driven' { return 'event-only' }
        'event_driven' { return 'event-only' }
        'eventdriven' { return 'event-only' }
        default { return $DefaultValue }
    }
}

function Resolve-ChatPolicyDeliveryPrimary {
    param(
        [AllowEmptyString()][string]$RawValue,
        [string]$DefaultValue = 'pywinauto'
    )

    $token = Convert-ToPolicyToken -Value $RawValue
    if ([string]::IsNullOrWhiteSpace($token)) {
        return $DefaultValue
    }

    switch ($token) {
        'pywinauto' { return 'pywinauto' }
        'python' { return 'pywinauto' }
        'py' { return 'pywinauto' }
        'ipc' { return 'ipc' }
        'ahk' { return 'ahk' }
        'autohotkey' { return 'ahk' }
        default { return $DefaultValue }
    }
}

function Resolve-ChatPolicyDeliveryFallback {
    param(
        [AllowEmptyString()][string]$RawValue,
        [string]$DefaultValue = 'on'
    )

    $token = Convert-ToPolicyToken -Value $RawValue
    if ([string]::IsNullOrWhiteSpace($token)) {
        return $DefaultValue
    }

    switch ($token) {
        'on' { return 'on' }
        'off' { return 'off' }
        'true' { return 'on' }
        'false' { return 'off' }
        'enabled' { return 'on' }
        'disabled' { return 'off' }
        default { return $DefaultValue }
    }
}

function Resolve-ChatPolicyFinalStopGate {
    param(
        [AllowEmptyString()][string]$RawValue,
        [string]$DefaultValue = 'trigger-started'
    )

    $token = Convert-ToPolicyToken -Value $RawValue
    if ([string]::IsNullOrWhiteSpace($token)) {
        return $DefaultValue
    }

    switch ($token) {
        'trigger-started' { return 'trigger-started' }
        'trigger_started' { return 'trigger-started' }
        'sender-sent' { return 'sender-sent' }
        'sender_sent' { return 'sender-sent' }
        default { return $DefaultValue }
    }
}

function Convert-ToChatPolicyAllowList {
    param([AllowEmptyString()][string]$AllowList)

    $items = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($raw in @([string]$AllowList -split ';')) {
        $item = Convert-ToPolicyToken -Value $raw
        if ([string]::IsNullOrWhiteSpace($item)) {
            continue
        }

        if ($seen.ContainsKey($item)) {
            continue
        }

        $seen[$item] = $true
        [void]$items.Add($item)
    }

    return ($items.ToArray() -join ';')
}

function Convert-ToDispatchSenderSwitchSanitizedCommand {
    param([AllowEmptyString()][string]$Command)

    $text = Convert-ToPolicyToken -Value $Command
    if ([string]::IsNullOrWhiteSpace($text)) {
        return ''
    }

    $sanitized = [regex]::Replace([string]$Command, '(?i)\s-(UsePythonSender|UseAhk|UseIpcSender)\b', '')
    $sanitized = ([regex]::Replace($sanitized, '\s+', ' ')).Trim()
    return $sanitized
}

function Get-ChatDispatchPolicyPlan {
    param(
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$DefaultTriggerCommand = ''
    )

    $updates = @{}
    $changes = New-Object 'System.Collections.Generic.List[string]'

    $getValue = {
        param([string]$Key)

        if ($null -ne $Settings -and $Settings.Contains($Key)) {
            return [string]$Settings[$Key]
        }

        return ''
    }

    $legacyProfile = Convert-ToPolicyToken -Value (& $getValue 'AI_CHAT_DISPATCH_DELIVERY_PROFILE')
    $workModeDefault = 'normal'
    if ($legacyProfile -eq 'low-disturb') {
        $workModeDefault = 'low-disturb'
    }
    elseif (Convert-ToPolicyBooleanSetting -Value (& $getValue 'AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY') -Default $false) {
        $workModeDefault = 'anti-missent'
    }

    $primaryDefault = 'pywinauto'
    if (Convert-ToPolicyBooleanSetting -Value (& $getValue 'AI_CHAT_DISPATCH_USE_IPC') -Default $false) {
        $primaryDefault = 'ipc'
    }
    elseif (Convert-ToPolicyBooleanSetting -Value (& $getValue 'AI_CHAT_DISPATCH_USE_AHK') -Default $false) {
        $primaryDefault = 'ahk'
    }
    elseif (Convert-ToPolicyBooleanSetting -Value (& $getValue 'AI_CHAT_DISPATCH_USE_PY_SENDER') -Default $true) {
        $primaryDefault = 'pywinauto'
    }

    $fallbackDefault = 'on'
    if ($null -ne $Settings -and $Settings.Contains('AI_CHAT_DISPATCH_SENDER_FALLBACK_ENABLED')) {
        $fallbackDefault = if (Convert-ToPolicyBooleanSetting -Value (& $getValue 'AI_CHAT_DISPATCH_SENDER_FALLBACK_ENABLED') -Default $true) { 'on' } else { 'off' }
    }

    $finalStopDefault = Resolve-ChatPolicyFinalStopGate -RawValue (& $getValue 'AI_CHAT_TRIGGER_FINAL_STOP_GATE') -DefaultValue 'trigger-started'

    $workMode = Resolve-ChatPolicyWorkMode -RawValue (& $getValue 'AI_CHAT_POLICY_WORK_MODE') -DefaultValue $workModeDefault
    $deliveryPrimary = Resolve-ChatPolicyDeliveryPrimary -RawValue (& $getValue 'AI_CHAT_POLICY_DELIVERY_PRIMARY') -DefaultValue $primaryDefault
    $deliveryFallback = Resolve-ChatPolicyDeliveryFallback -RawValue (& $getValue 'AI_CHAT_POLICY_DELIVERY_FALLBACK') -DefaultValue $fallbackDefault
    $finalStopGate = Resolve-ChatPolicyFinalStopGate -RawValue (& $getValue 'AI_CHAT_POLICY_FINAL_STOP_GATE') -DefaultValue $finalStopDefault
    $policyVersion = Convert-ToPolicyToken -Value (& $getValue 'AI_CHAT_POLICY_VERSION')
    if ([string]::IsNullOrWhiteSpace($policyVersion)) {
        $policyVersion = '1'
    }

    $sourceValues = [ordered]@{
        AI_CHAT_POLICY_WORK_MODE = $workMode
        AI_CHAT_POLICY_DELIVERY_PRIMARY = $deliveryPrimary
        AI_CHAT_POLICY_DELIVERY_FALLBACK = $deliveryFallback
        AI_CHAT_POLICY_FINAL_STOP_GATE = $finalStopGate
        AI_CHAT_POLICY_VERSION = $policyVersion
    }

    foreach ($key in $sourceValues.Keys) {
        $currentToken = Convert-ToPolicyToken -Value (& $getValue $key)
        $desiredToken = Convert-ToPolicyToken -Value ([string]$sourceValues[$key])
        if ($currentToken -eq $desiredToken) {
            continue
        }

        $updates[$key] = [string]$sourceValues[$key]
        $displayCurrent = if ([string]::IsNullOrWhiteSpace((& $getValue $key))) { '<empty>' } else { [string](& $getValue $key) }
        [void]$changes.Add(('{0}:{1}->{2}' -f $key, $displayCurrent, [string]$sourceValues[$key]))
    }

    $statusReportInteractive = ($workMode -ne 'event-only')
    $statusReportTriggerEnabled = ($workMode -ne 'event-only')
    $statusTicketEnabled = ($workMode -ne 'event-only')
    $deliveryProfile = if ($workMode -in @('low-disturb', 'event-only')) { 'low-disturb' } else { 'interactive-smoke' }
    $activeWindowOnly = ($workMode -eq 'anti-missent')
    $statusAllowInconclusiveSubmit = if ($workMode -eq 'anti-missent') { 'false' } else { 'true' }
    $desiredStatusReportMessageMode = if ($workMode -eq 'low-disturb') { 'short' } else { 'alternate' }
    $desiredStatusReportSendFullOnFirst = ($workMode -ne 'low-disturb')
    $useIpc = ($deliveryPrimary -eq 'ipc')
    $usePython = ($deliveryPrimary -eq 'pywinauto')
    $useAhk = ($deliveryPrimary -eq 'ahk')
    $senderFallbackEnabled = ($deliveryFallback -eq 'on')
    $interactivePreActionsEnabled = (-not $useIpc)

    $allowListBase = 'incident-captured;recovery-await-confirmation;auto-fix-await-confirmation;task-definition-fix-required;main-process-exit-review;manual-wait-paused;budget-exhausted-stop;known-infra-transient-stop;a-pass-conclusion-b-started;chat-session-final-status'
    $desiredAllowList = if ($statusReportInteractive) { '{0};running-status-report' -f $allowListBase } else { $allowListBase }
    $desiredAllowList = Convert-ToChatPolicyAllowList -AllowList $desiredAllowList

    $desiredSwitches = [ordered]@{
        LOCAL_GUARD_AGENT_QUEUE_ENABLED = 'true'
        LOCAL_GUARD_STATUS_TICKET_ENABLED = (Convert-PolicyBooleanToText -Value $statusTicketEnabled)
        AI_CHAT_TRIGGER_EVENT_DRIVEN_QUEUE = 'true'
        AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START = 'true'
        AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS = (Convert-PolicyBooleanToText -Value $statusReportTriggerEnabled)
        AI_CHAT_DISPATCH_STATUS_REPORT_INTERACTIVE = (Convert-PolicyBooleanToText -Value $statusReportInteractive)
        AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_SEND_ENABLED = 'false'
        AI_CHAT_DISPATCH_USE_IPC = (Convert-PolicyBooleanToText -Value $useIpc)
        AI_CHAT_DISPATCH_USE_PY_SENDER = (Convert-PolicyBooleanToText -Value $usePython)
        AI_CHAT_DISPATCH_USE_AHK = (Convert-PolicyBooleanToText -Value $useAhk)
        AI_CHAT_DISPATCH_DELIVERY_PROFILE = $deliveryProfile
        AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY = (Convert-PolicyBooleanToText -Value $activeWindowOnly)
        AI_CHAT_DISPATCH_INTERACTIVE_PRE_ACTIONS_ENABLED = (Convert-PolicyBooleanToText -Value $interactivePreActionsEnabled)
        AI_CHAT_DISPATCH_STATUS_REPORT_ALLOW_INCONCLUSIVE_SUBMIT = $statusAllowInconclusiveSubmit
        AI_CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE = $desiredStatusReportMessageMode
        AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST = (Convert-PolicyBooleanToText -Value $desiredStatusReportSendFullOnFirst)
        AI_CHAT_DISPATCH_SENDER_PRIMARY = $deliveryPrimary
        AI_CHAT_DISPATCH_SENDER_FALLBACK_ENABLED = (Convert-PolicyBooleanToText -Value $senderFallbackEnabled)
        AI_CHAT_TRIGGER_FINAL_STOP_GATE = $finalStopGate
        EXTERNAL_TRIGGER_EXECUTE = 'true'
        AUTO_START_TAKEOVER_TRIGGER = 'true'
    }

    $allowRunningStatusOverrideRaw = [string](& $getValue 'AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE')
    if ([string]::IsNullOrWhiteSpace($allowRunningStatusOverrideRaw)) {
        $updates['AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE'] = 'true'
        [void]$changes.Add('AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE:<empty>->true')
    }

    foreach ($key in $desiredSwitches.Keys) {
        $desiredValue = [string]$desiredSwitches[$key]
        $currentRaw = [string](& $getValue $key)

        if ($desiredValue -in @('true', 'false')) {
            $currentBool = Convert-ToPolicyBooleanSetting -Value $currentRaw -Default $false
            $desiredBool = Convert-ToPolicyBooleanSetting -Value $desiredValue -Default $false
            if ($currentBool -eq $desiredBool) {
                continue
            }
        }
        else {
            $currentToken = Convert-ToPolicyToken -Value $currentRaw
            $desiredToken = Convert-ToPolicyToken -Value $desiredValue
            if ($currentToken -eq $desiredToken) {
                continue
            }
        }

        $updates[$key] = $desiredValue
        $displayCurrent = if ([string]::IsNullOrWhiteSpace($currentRaw)) { '<empty>' } else { $currentRaw }
        [void]$changes.Add(('{0}:{1}->{2}' -f $key, $displayCurrent, $desiredValue))
    }

    $currentAllowList = Convert-ToChatPolicyAllowList -AllowList (& $getValue 'AI_CHAT_DISPATCH_AHK_EVENT_ALLOWLIST')
    if ($currentAllowList -ne $desiredAllowList) {
        $updates['AI_CHAT_DISPATCH_AHK_EVENT_ALLOWLIST'] = $desiredAllowList
        $displayAllowList = if ([string]::IsNullOrWhiteSpace((& $getValue 'AI_CHAT_DISPATCH_AHK_EVENT_ALLOWLIST'))) { '<empty>' } else { [string](& $getValue 'AI_CHAT_DISPATCH_AHK_EVENT_ALLOWLIST') }
        [void]$changes.Add(('AI_CHAT_DISPATCH_AHK_EVENT_ALLOWLIST:{0}->{1}' -f $displayAllowList, $desiredAllowList))
    }

    $messageModeRaw = [string](& $getValue 'AI_CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE')
    $messageMode = Convert-ToPolicyToken -Value $messageModeRaw
    if ($messageMode -ne (Convert-ToPolicyToken -Value $desiredStatusReportMessageMode)) {
        $updates['AI_CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE'] = $desiredStatusReportMessageMode
        $displayMessageMode = if ([string]::IsNullOrWhiteSpace($messageModeRaw)) { '<empty>' } else { $messageModeRaw }
        [void]$changes.Add(('AI_CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE:{0}->{1}' -f $displayMessageMode, $desiredStatusReportMessageMode))
    }

    $statusReportSendFullOnFirstRaw = [string](& $getValue 'AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST')
    $statusReportSendFullOnFirstCurrent = Convert-ToPolicyBooleanSetting -Value $statusReportSendFullOnFirstRaw -Default $true
    if ([string]::IsNullOrWhiteSpace($statusReportSendFullOnFirstRaw) -or $statusReportSendFullOnFirstCurrent -ne $desiredStatusReportSendFullOnFirst) {
        $updates['AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST'] = (Convert-PolicyBooleanToText -Value $desiredStatusReportSendFullOnFirst)
        $displaySendFullOnFirst = if ([string]::IsNullOrWhiteSpace($statusReportSendFullOnFirstRaw)) { '<empty>' } else { $statusReportSendFullOnFirstRaw }
        [void]$changes.Add(('AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST:{0}->{1}' -f $displaySendFullOnFirst, (Convert-PolicyBooleanToText -Value $desiredStatusReportSendFullOnFirst)))
    }

    $ipcModeRaw = [string](& $getValue 'AI_CHAT_DISPATCH_IPC_MODE')
    $ipcModeToken = Convert-ToPolicyToken -Value $ipcModeRaw
    if ([string]::IsNullOrWhiteSpace($ipcModeToken)) {
        $updates['AI_CHAT_DISPATCH_IPC_MODE'] = 'visible'
        [void]$changes.Add('AI_CHAT_DISPATCH_IPC_MODE:<empty>->visible')
        $ipcModeToken = 'visible'
    }
    elseif ($ipcModeToken -notin @('visible', 'silent', 'auto')) {
        $updates['AI_CHAT_DISPATCH_IPC_MODE'] = 'visible'
        [void]$changes.Add(('AI_CHAT_DISPATCH_IPC_MODE:{0}->visible' -f $ipcModeRaw))
        $ipcModeToken = 'visible'
    }

    $triggerCommandRaw = [string](& $getValue 'EXTERNAL_TRIGGER_COMMAND')
    $triggerCommandTarget = $triggerCommandRaw
    if ([string]::IsNullOrWhiteSpace($triggerCommandTarget)) {
        $triggerCommandTarget = $DefaultTriggerCommand
    }
    else {
        $triggerCommandTarget = Convert-ToDispatchSenderSwitchSanitizedCommand -Command $triggerCommandTarget
        if ([string]::IsNullOrWhiteSpace($triggerCommandTarget)) {
            $triggerCommandTarget = $DefaultTriggerCommand
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($triggerCommandTarget)) {
        $normalizedCurrentCommand = ([regex]::Replace([string]$triggerCommandRaw, '\s+', ' ')).Trim()
        $normalizedTargetCommand = ([regex]::Replace([string]$triggerCommandTarget, '\s+', ' ')).Trim()
        if ($normalizedCurrentCommand -ne $normalizedTargetCommand) {
            $updates['EXTERNAL_TRIGGER_COMMAND'] = $triggerCommandTarget
            $displayCommand = if ([string]::IsNullOrWhiteSpace($triggerCommandRaw)) { '<empty>' } else { $triggerCommandRaw }
            [void]$changes.Add(('EXTERNAL_TRIGGER_COMMAND:{0}->{1}' -f $displayCommand, $triggerCommandTarget))
        }
    }

    return [pscustomobject]@{
        Updates = $updates
        Changes = @($changes.ToArray())
        ResolvedPolicy = [ordered]@{
            work_mode = $workMode
            delivery_primary = $deliveryPrimary
            delivery_fallback = $deliveryFallback
            final_stop_gate = $finalStopGate
            delivery_profile = $deliveryProfile
            status_report_interactive = $statusReportInteractive
            active_window_only = $activeWindowOnly
            ipc_mode = $ipcModeToken
        }
    }
}
