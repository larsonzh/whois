param(
    [Parameter(Mandatory = $true)]
    [string]$Message,

    [AllowEmptyString()]
    [string]$AhkExePath = '',

    [ValidateRange(0, 60000)]
    [int]$PreSendDelayMs = 700,

    [ValidateRange(1000, 60000)]
    [int]$TimeoutMs = 12000,

    [ValidateRange(0, 5000)]
    [int]$FocusCommandDelayMs = 220,

    [ValidateRange(0.0, 1.0)]
    [double]$ChatInputClickXRatio = 0.84,

    [ValidateRange(0.0, 1.0)]
    [double]$ChatInputClickYRatio = 0.94,

    [ValidateRange(0, 400)]
    [int]$ChatBottomAvoidPx = 170,

    [ValidateSet('ratio', 'right-offset')]
    [string]$ChatInputXMode = 'right-offset',

    [ValidateRange(0, 2400)]
    [int]$ChatInputRightOffsetPx = 300,

    [ValidateRange(200, 30000)]
    [int]$ReconnectResendDelayMs = 1800,

    [ValidateRange(60, 1800)]
    [int]$ReconnectDetectWindowSec = 300,

    [AllowEmptyString()]
    [string]$ChatToggleShortcut = '^!b',

    [switch]$NoActivateWindow,
    [switch]$NoMaximizeCodeWindow,
    [switch]$NoFocusChatInput,
    [switch]$NoPaletteFocusCommand,
    [switch]$EnablePaletteFocusCommand,
    [switch]$UseClickFocusFallback,
    [switch]$NoClickFocusFallback,
    [switch]$EnableChatToggleShortcut,
    [switch]$NoChatToggleShortcut,
    [switch]$EnableEscPreflight,
    [switch]$EnableAutoReconnectResend,
    [switch]$NoAutoReconnectResend,
    [switch]$NoInvokeCodeChatFocus,
    [switch]$ForceInvokeCodeChatFocus,
    [switch]$KeepTempFiles,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-AhkExecutablePath {
    param([AllowEmptyString()][string]$ConfiguredPath)

    $candidates = New-Object 'System.Collections.Generic.List[string]'

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
        [void]$candidates.Add($ConfiguredPath)
    }

    if (-not [string]::IsNullOrWhiteSpace($env:AUTOHOTKEY_EXE)) {
        [void]$candidates.Add($env:AUTOHOTKEY_EXE)
    }

    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        [void]$candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\AutoHotkey\v2\AutoHotkey64.exe'))
    }

    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        [void]$candidates.Add((Join-Path $env:ProgramFiles 'AutoHotkey\v2\AutoHotkey64.exe'))
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

function Invoke-CodeCommandBestEffort {
    param(
        [string]$CommandId,
        [int]$DelayMs = 220
    )

    $result = [ordered]@{
        command = $CommandId
        tried = $false
        success = $false
        reason = 'not-invoked'
    }

    $codeCommand = Get-Command code -ErrorAction SilentlyContinue
    if ($null -eq $codeCommand -or [string]::IsNullOrWhiteSpace([string]$codeCommand.Source)) {
        $result.reason = 'code-cli-not-found'
        return [pscustomobject]$result
    }

    try {
        $result.tried = $true
        Start-Process -FilePath $codeCommand.Source -ArgumentList @('--command', $CommandId) -ErrorAction Stop | Out-Null
        if ($DelayMs -gt 0) {
            Start-Sleep -Milliseconds $DelayMs
        }

        $result.success = $true
        $result.reason = 'ok'
        return [pscustomobject]$result
    }
    catch {
        $result.reason = $_.Exception.Message
        return [pscustomobject]$result
    }
}

function Get-AhkExitReason {
    param([int]$ExitCode)

    switch ($ExitCode) {
        31 { return 'Message file not found by AHK.' }
        32 { return 'Message content was empty in AHK.' }
        33 { return 'Clipboard write failed in AHK while sending message.' }
        34 { return 'Clipboard write failed in AHK while running focus command.' }
        35 { return 'VS Code window did not become active within activation timeout.' }
        36 { return 'VS Code window was not found for activation.' }
        37 { return 'Message appears to remain in chat input after Enter; submit likely failed.' }
        38 { return 'Chat input was not focused before send; dispatch aborted to avoid false success.' }
        default { return ("AHK dispatch failed with exit code {0}." -f $ExitCode) }
    }
}

function Invoke-AhkDispatchAttempt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AhkExecutable,

        [Parameter(Mandatory = $true)]
        [string[]]$AhkArgumentList,

        [ValidateRange(1000, 60000)]
        [int]$TimeoutMs = 12000
    )

    $attempt = [ordered]@{
        sent = $false
        timed_out = $false
        exit_code = -1
        failure = ''
        duration_ms = 0
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $process = Start-Process -FilePath $AhkExecutable -ArgumentList $AhkArgumentList -PassThru

        $timeout = [Math]::Max(1000, $TimeoutMs)
        $exited = $process.WaitForExit($timeout)
        if (-not $exited) {
            try {
                $process.Kill()
            }
            catch {
            }

            $attempt.timed_out = $true
            $attempt.failure = ("AHK dispatch timed out after {0} ms." -f $timeout)
            return [pscustomobject]$attempt
        }

        $attempt.exit_code = [int]$process.ExitCode
        $attempt.sent = ($attempt.exit_code -eq 0)
        if (-not $attempt.sent) {
            $attempt.failure = Get-AhkExitReason -ExitCode $attempt.exit_code
        }

        return [pscustomobject]$attempt
    }
    catch {
        $attempt.failure = $_.Exception.Message
        return [pscustomobject]$attempt
    }
    finally {
        $stopwatch.Stop()
        $attempt.duration_ms = [int]$stopwatch.ElapsedMilliseconds
    }
}

function Get-VsCodeChatOOMSignal {
    param(
        [ValidateRange(60, 1800)]
        [int]$DetectWindowSec = 300,

        [ValidateRange(1, 40)]
        [int]$MaxFiles = 12,

        [ValidateRange(20, 400)]
        [int]$TailLines = 140
    )

    $result = [ordered]@{
        detected = $false
        event_utc = ''
        source_file = ''
        signature = ''
        line = ''
        index_from_end = -1
        recent = $false
    }

    if ([string]::IsNullOrWhiteSpace($env:APPDATA)) {
        return [pscustomobject]$result
    }

    $logsRoot = Join-Path $env:APPDATA 'Code\logs'
    if (-not (Test-Path -LiteralPath $logsRoot)) {
        return [pscustomobject]$result
    }

    $latestLogDir = Get-ChildItem -Path $logsRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1

    if ($null -eq $latestLogDir) {
        return [pscustomobject]$result
    }

    $cutoff = (Get-Date).ToUniversalTime().AddSeconds(-1 * $DetectWindowSec)
    $pattern = 'Worker terminated due to reaching memory limit|JS heap out of memory'

    $candidateFiles = Get-ChildItem -Path $latestLogDir.FullName -File -Recurse -Filter *.log -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -ge $cutoff } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First $MaxFiles

    foreach ($file in @($candidateFiles)) {
        $tail = @()
        try {
            $tail = @(Get-Content -LiteralPath $file.FullName -Tail $TailLines -ErrorAction Stop)
        }
        catch {
            continue
        }

        if ($tail.Count -eq 0) {
            continue
        }

        for ($i = $tail.Count - 1; $i -ge 0; $i--) {
            $line = [string]$tail[$i]
            if ($line -match $pattern) {
                $indexFromEnd = ($tail.Count - 1) - $i
                $trimmedLine = $line.Trim()
                $signature = ("{0}|{1}|{2}" -f $file.FullName, $indexFromEnd, $trimmedLine)

                $result.detected = $true
                $result.event_utc = $file.LastWriteTimeUtc.ToString('o')
                $result.source_file = $file.FullName
                $result.signature = $signature
                $result.line = $trimmedLine
                $result.index_from_end = $indexFromEnd
                $result.recent = ($indexFromEnd -le 4)
                return [pscustomobject]$result
            }
        }
    }

    return [pscustomobject]$result
}

$ahkExecutable = Resolve-AhkExecutablePath -ConfiguredPath $AhkExePath
if ([string]::IsNullOrWhiteSpace($ahkExecutable)) {
    throw 'AutoHotkey executable not found. Set -AhkExePath or AUTOHOTKEY_EXE.'
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'ahk-chat-send'
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

$token = [guid]::NewGuid().ToString('N')
$messagePath = Join-Path $tempRoot ("msg_{0}.txt" -f $token)
$scriptPath = Join-Path $tempRoot ("send_{0}.ahk" -f $token)

$termProgram = [string]$env:TERM_PROGRAM
$isVsCodeIntegratedTerminal = (-not [string]::IsNullOrWhiteSpace($termProgram)) -and ($termProgram.Trim().ToLowerInvariant() -eq 'vscode')
$usePaletteFocusCommand = $false
if ($EnablePaletteFocusCommand.IsPresent) {
    $usePaletteFocusCommand = $true
}
if ($NoPaletteFocusCommand.IsPresent) {
    $usePaletteFocusCommand = $false
}

$useClickFocusFallback = $true
if ($NoClickFocusFallback.IsPresent) {
    $useClickFocusFallback = $false
}
if ($UseClickFocusFallback.IsPresent) {
    $useClickFocusFallback = $true
}
if ($NoFocusChatInput.IsPresent) {
    $useClickFocusFallback = $false
}

$useMaximizeCodeWindow = (-not $NoMaximizeCodeWindow.IsPresent)

$chatToggleShortcutForcedDisabled = $true
$chatToggleShortcutDisabledReason = 'hard-disabled-by-policy'
$useChatToggleShortcut = $false
if ($NoFocusChatInput.IsPresent) {
    $useChatToggleShortcut = $false
}

$useEscPreflight = $false
if ($EnableEscPreflight.IsPresent) {
    $useEscPreflight = $true
}
if ($NoFocusChatInput.IsPresent) {
    $useEscPreflight = $false
}

$useAutoReconnectResend = $true
if ($NoAutoReconnectResend.IsPresent) {
    $useAutoReconnectResend = $false
}
if ($EnableAutoReconnectResend.IsPresent) {
    $useAutoReconnectResend = $true
}
if ($NoFocusChatInput.IsPresent) {
    $useAutoReconnectResend = $false
}

$effectiveChatInputXMode = $ChatInputXMode.Trim().ToLowerInvariant()

$shouldInvokeCodeChatFocus = (-not $NoInvokeCodeChatFocus.IsPresent) -and (-not $NoFocusChatInput.IsPresent) -and $ForceInvokeCodeChatFocus.IsPresent

$ahkScript = @(
    '#Requires AutoHotkey v2.0',
    '#SingleInstance Force',
    '#Warn All, Off',
    'CoordMode "Caret", "Screen"',
    'SetTitleMatchMode "RegEx"',
    'messagePath := A_Args[1]',
    'noActivate := (A_Args.Length >= 2 && A_Args[2] = "1")',
    'preDelay := (A_Args.Length >= 3) ? Integer(A_Args[3]) : 500',
    'noFocusChatInput := (A_Args.Length >= 4 && A_Args[4] = "1")',
    'useClickFocusFallback := (A_Args.Length >= 5 && A_Args[5] = "1")',
    'usePaletteFocus := (A_Args.Length >= 6 && A_Args[6] = "1")',
    'clickXRatio := (A_Args.Length >= 7) ? Number(A_Args[7]) : 0.84',
    'clickYRatio := (A_Args.Length >= 8) ? Number(A_Args[8]) : 0.94',
    'bottomAvoidPx := (A_Args.Length >= 9) ? Integer(A_Args[9]) : 170',
    'xMode := (A_Args.Length >= 10) ? Trim(StrLower(A_Args[10])) : "right-offset"',
    'rightOffsetPx := (A_Args.Length >= 11) ? Integer(A_Args[11]) : 300',
    'useMaximize := (A_Args.Length >= 12 && A_Args[12] = "1")',
    'useToggleShortcut := (A_Args.Length >= 13 && A_Args[13] = "1")',
    'toggleShortcut := (A_Args.Length >= 14) ? A_Args[14] : "^!b"',
    'useEscPreflight := (A_Args.Length >= 15 && A_Args[15] = "1")',
    'if !FileExist(messagePath)',
    '    ExitApp(31)',
    'message := FileRead(messagePath, "UTF-8")',
    'if (message = "")',
    '    ExitApp(32)',
    'RunPaletteCommand(commandText) {',
    '    A_Clipboard := commandText',
    '    if !ClipWait(1)',
    '        ExitApp(34)',
    '    Send "{F1}"',
    '    Sleep 220',
    '    Send "^a"',
    '    Sleep 60',
    '    Send "^v"',
    '    Sleep 120',
    '    Send "{Enter}"',
    '    Sleep 260',
    '}',
    'IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx) {',
    '    cx := 0',
    '    cy := 0',
    '    try',
    '        hasCaret := CaretGetPos(&cx, &cy)',
    '    catch',
    '        return -1',
    '    if (!hasCaret)',
    '        return -1',
    '    minX := wx + Floor(ww * 0.45)',
    '    maxX := wx + ww - 16',
    '    minY := wy + wh - bottomAvoidPx - 50',
    '    maxY := wy + wh - 8',
    '    if (cx >= minX && cx <= maxX && cy >= minY && cy <= maxY)',
    '        return 1',
    '    return 0',
    '}',
    'ProbeRetainedInputAfterSend(messageText, wx, wy, ww, wh, bottomAvoidPx) {',
    '    focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx)',
    '    if (focusState != 1)',
    '        return false',
    '    backup := ClipboardAll()',
    '    A_Clipboard := ""',
    '    Send "^a"',
    '    Sleep 60',
    '    Send "^c"',
    '    if !ClipWait(0.6) {',
    '        A_Clipboard := backup',
    '        return false',
    '    }',
    '    copied := A_Clipboard',
    '    A_Clipboard := backup',
    '    copiedNorm := Trim(StrReplace(StrReplace(copied, "`r", " "), "`n", " "))',
    '    messageNorm := Trim(StrReplace(StrReplace(messageText, "`r", " "), "`n", " "))',
    '    if (copiedNorm = "" || messageNorm = "")',
    '        return false',
    '    return (copiedNorm = messageNorm)',
    '}',
    'if !noActivate {',
    '    if !WinExist("ahk_exe Code.exe")',
    '        ExitApp(36)',
    '    WinActivate("ahk_exe Code.exe")',
    '    if useMaximize',
    '        WinMaximize("ahk_exe Code.exe")',
    '    if !WinWaitActive("ahk_exe Code.exe",, 2)',
    '        ExitApp(35)',
    '    Sleep 180',
    '}',
    'if !noFocusChatInput {',
    '    ; Optional popup dismissal preflight; disabled by default to avoid hiding the chat panel.',
    '    if useEscPreflight {',
    '        Send "{Esc}"',
    '        Sleep 80',
    '        Send "{Esc}"',
    '        Sleep 80',
    '    }',
    '    if usePaletteFocus {',
    '        RunPaletteCommand(">chat.action.focus")',
    '        RunPaletteCommand(">workbench.action.chat.open")',
    '        RunPaletteCommand(">workbench.action.chat.focusInput")',
    '    } else {',
    '        Send "^!i"',
    '        Sleep 180',
    '    }',
    '    if useClickFocusFallback && WinExist("ahk_exe Code.exe") {',
    '        WinGetPos &wx, &wy, &ww, &wh, "ahk_exe Code.exe"',
    '        if (ww > 0 && wh > 0) {',
    '            if (xMode = "right-offset")',
    '                clickX := wx + ww - rightOffsetPx',
    '            else',
    '                clickX := wx + Floor(ww * clickXRatio)',
    '            clickY := wy + Floor(wh * clickYRatio)',
    '            safeMinX := wx + 120',
    '            safeMaxX := wx + ww - 80',
    '            safeMaxY := wy + wh - bottomAvoidPx',
    '            safeMinY := wy + 80',
    '            if (clickX > safeMaxX)',
    '                clickX := safeMaxX',
    '            if (clickX < safeMinX)',
    '                clickX := safeMinX',
    '            if (clickY > safeMaxY)',
    '                clickY := safeMaxY',
    '            if (clickY < safeMinY)',
    '                clickY := safeMinY',
    '            Click clickX, clickY',
    '            Sleep 120',
    '            if useEscPreflight {',
    '                Send "{Esc}"',
    '                Sleep 60',
    '            }',
    '            focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx)',
    '            if (focusState = 0 && useToggleShortcut) {',
    '                Send toggleShortcut',
    '                Sleep 220',
    '                Click clickX, clickY',
    '                Sleep 120',
    '                if useEscPreflight {',
    '                    Send "{Esc}"',
    '                    Sleep 60',
    '                }',
    '            }',
    '        }',
    '    }',
    '}',
    'if !noFocusChatInput && WinExist("ahk_exe Code.exe") {',
    '    WinGetPos &wx0, &wy0, &ww0, &wh0, "ahk_exe Code.exe"',
    '    if (ww0 > 0 && wh0 > 0) {',
    '        focusBeforeSend := IsLikelyChatCaretInInput(wx0, wy0, ww0, wh0, bottomAvoidPx)',
    '        if (focusBeforeSend = 0)',
    '            ExitApp(38)',
    '    }',
    '}',
    'Sleep preDelay',
    'A_Clipboard := message',
    'if !ClipWait(1)',
    '    ExitApp(33)',
    'Send "^v"',
    'Sleep 120',
    'Send "{Enter}"',
    'Sleep 300',
    'if WinExist("ahk_exe Code.exe") {',
    '    WinGetPos &wx2, &wy2, &ww2, &wh2, "ahk_exe Code.exe"',
    '    if (ww2 > 0 && wh2 > 0) {',
    '        if (ProbeRetainedInputAfterSend(message, wx2, wy2, ww2, wh2, bottomAvoidPx))',
    '            ExitApp(37)',
    '    }',
    '}',
    'ExitApp(0)'
)

$result = [ordered]@{
    schema = 'AHK_CHAT_SEND_RESULT_V1'
    timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    sent = $false
    ahk_exe = $ahkExecutable
    ahk_exit_code = -1
    message_chars = $Message.Length
    temp_script = $scriptPath
    temp_message = $messagePath
    focus_chat_input = (-not $NoFocusChatInput.IsPresent)
    palette_focus_command = $usePaletteFocusCommand
    click_focus_fallback = $useClickFocusFallback
    maximize_code_window = $useMaximizeCodeWindow
    chat_toggle_shortcut = [ordered]@{
        key = $ChatToggleShortcut
        enabled = $useChatToggleShortcut
        forced_disabled = $chatToggleShortcutForcedDisabled
        disabled_reason = $chatToggleShortcutDisabledReason
        requested_enable_switch = [bool]$EnableChatToggleShortcut
    }
    chat_input_x_mode = $effectiveChatInputXMode
    chat_input_right_offset_px = $ChatInputRightOffsetPx
    chat_input_click_ratio = [ordered]@{
        x = $ChatInputClickXRatio
        y = $ChatInputClickYRatio
    }
    chat_bottom_avoid_px = $ChatBottomAvoidPx
    auto_reconnect_resend = [ordered]@{
        enabled = $useAutoReconnectResend
        detect_window_sec = $ReconnectDetectWindowSec
        retry_delay_ms = $ReconnectResendDelayMs
        triggered = $false
        trigger_reason = 'not-triggered'
        pre_signal = $null
        post_signal = $null
    }
    esc_preflight_enabled = $useEscPreflight
    dispatch_attempts = @()
    code_chat_open = [ordered]@{
        command = 'workbench.action.chat.open'
        tried = $false
        success = $false
        reason = 'not-invoked'
    }
    code_chat_focus = [ordered]@{
        command = 'workbench.action.chat.focusInput'
        tried = $false
        success = $false
        reason = 'not-invoked'
    }
    code_focus_policy = [ordered]@{
        term_program = $termProgram
        integrated_terminal = $isVsCodeIntegratedTerminal
        no_palette_focus_switch = [bool]$NoPaletteFocusCommand
        enable_palette_focus_switch = [bool]$EnablePaletteFocusCommand
        no_click_focus_fallback_switch = [bool]$NoClickFocusFallback
        no_maximize_window_switch = [bool]$NoMaximizeCodeWindow
        no_chat_toggle_shortcut_switch = [bool]$NoChatToggleShortcut
        enable_chat_toggle_shortcut_switch = [bool]$EnableChatToggleShortcut
        no_auto_reconnect_resend_switch = [bool]$NoAutoReconnectResend
        enable_auto_reconnect_resend_switch = [bool]$EnableAutoReconnectResend
        no_invoke_switch = [bool]$NoInvokeCodeChatFocus
        force_invoke_switch = [bool]$ForceInvokeCodeChatFocus
        effective_chat_input_x_mode = $effectiveChatInputXMode
        effective_palette_focus = $usePaletteFocusCommand
        effective_click_fallback = $useClickFocusFallback
        effective_maximize_window = $useMaximizeCodeWindow
        effective_chat_toggle_shortcut = $useChatToggleShortcut
        chat_toggle_shortcut_forced_disabled = $chatToggleShortcutForcedDisabled
        effective_esc_preflight = $useEscPreflight
        effective_auto_reconnect_resend = $useAutoReconnectResend
        allowed = $shouldInvokeCodeChatFocus
    }
    dry_run = [bool]$DryRun
}

try {
    Set-Content -LiteralPath $messagePath -Value $Message -Encoding utf8
    Set-Content -LiteralPath $scriptPath -Value $ahkScript -Encoding utf8

    if ($DryRun.IsPresent) {
        $result.sent = $false
        $result.ahk_exit_code = 0
        $result.note = 'dry-run-no-dispatch'
        [pscustomobject]$result
        exit 0
    }

    if ($shouldInvokeCodeChatFocus) {
        $result.code_chat_open = Invoke-CodeCommandBestEffort -CommandId 'workbench.action.chat.open' -DelayMs $FocusCommandDelayMs
        $result.code_chat_focus = Invoke-CodeCommandBestEffort -CommandId 'workbench.action.chat.focusInput' -DelayMs $FocusCommandDelayMs
    }
    elseif (-not $NoFocusChatInput.IsPresent) {
        $result.code_chat_open.reason = if ($NoInvokeCodeChatFocus.IsPresent) { 'disabled-by-switch' } elseif (-not $ForceInvokeCodeChatFocus.IsPresent) { 'disabled-by-default-use-force-switch' } else { 'eligible-but-skipped' }
        $result.code_chat_focus.reason = $result.code_chat_open.reason
    }

    $noActivateFlag = if ($NoActivateWindow.IsPresent) { '1' } else { '0' }
    $noFocusFlag = if ($NoFocusChatInput.IsPresent) { '1' } else { '0' }
    $clickFallbackFlag = if ($useClickFocusFallback) { '1' } else { '0' }
    $paletteFocusFlag = if ($usePaletteFocusCommand) { '1' } else { '0' }
    $maximizeFlag = if ($useMaximizeCodeWindow) { '1' } else { '0' }
    $toggleShortcutFlag = if ($useChatToggleShortcut) { '1' } else { '0' }
    $escPreflightFlag = if ($useEscPreflight) { '1' } else { '0' }
    $ahkArgumentList = @(
        $scriptPath,
        $messagePath,
        $noActivateFlag,
        [string]$PreSendDelayMs,
        $noFocusFlag,
        $clickFallbackFlag,
        $paletteFocusFlag,
        ([string]$ChatInputClickXRatio),
        ([string]$ChatInputClickYRatio),
        ([string]$ChatBottomAvoidPx),
        $effectiveChatInputXMode,
        ([string]$ChatInputRightOffsetPx),
        $maximizeFlag,
        $toggleShortcutFlag,
        $ChatToggleShortcut,
        $escPreflightFlag
    )

    $preSignal = $null
    if ($useAutoReconnectResend) {
        $preSignal = Get-VsCodeChatOOMSignal -DetectWindowSec $ReconnectDetectWindowSec
        $result.auto_reconnect_resend.pre_signal = $preSignal
    }

    $attempt1 = Invoke-AhkDispatchAttempt -AhkExecutable $ahkExecutable -AhkArgumentList $ahkArgumentList -TimeoutMs $TimeoutMs
    $result.dispatch_attempts += [pscustomobject]@{
        attempt = 1
        sent = $attempt1.sent
        timed_out = $attempt1.timed_out
        exit_code = $attempt1.exit_code
        failure = $attempt1.failure
        duration_ms = $attempt1.duration_ms
    }

    $needSecondAttempt = $false
    $secondAttemptReason = ''

    if (-not $attempt1.sent) {
        if ($useAutoReconnectResend -and ($attempt1.timed_out -or ($attempt1.exit_code -in @(35, 36)))) {
            $needSecondAttempt = $true
            $secondAttemptReason = 'first-attempt-transient-failure'
        }
        else {
            $failure = if ([string]::IsNullOrWhiteSpace($attempt1.failure)) { Get-AhkExitReason -ExitCode $attempt1.exit_code } else { $attempt1.failure }
            throw $failure
        }
    }
    elseif ($useAutoReconnectResend) {
        $postSignal = Get-VsCodeChatOOMSignal -DetectWindowSec $ReconnectDetectWindowSec
        $result.auto_reconnect_resend.post_signal = $postSignal

        $preSignature = if ($null -ne $preSignal) { [string]$preSignal.signature } else { '' }
        $postSignature = [string]$postSignal.signature
        if ($postSignal.detected -and $postSignal.recent -and ($postSignature -ne $preSignature)) {
            $needSecondAttempt = $true
            $secondAttemptReason = 'new-oom-signal-after-send'
        }
    }

    if ($needSecondAttempt) {
        $result.auto_reconnect_resend.triggered = $true
        $result.auto_reconnect_resend.trigger_reason = $secondAttemptReason

        Start-Sleep -Milliseconds $ReconnectResendDelayMs
        $attempt2 = Invoke-AhkDispatchAttempt -AhkExecutable $ahkExecutable -AhkArgumentList $ahkArgumentList -TimeoutMs $TimeoutMs

        $result.dispatch_attempts += [pscustomobject]@{
            attempt = 2
            sent = $attempt2.sent
            timed_out = $attempt2.timed_out
            exit_code = $attempt2.exit_code
            failure = $attempt2.failure
            duration_ms = $attempt2.duration_ms
        }

        $result.ahk_exit_code = $attempt2.exit_code
        $result.sent = $attempt2.sent
        if (-not $attempt2.sent) {
            $failure = if ([string]::IsNullOrWhiteSpace($attempt2.failure)) { Get-AhkExitReason -ExitCode $attempt2.exit_code } else { $attempt2.failure }
            throw $failure
        }
    }
    else {
        $result.ahk_exit_code = $attempt1.exit_code
        $result.sent = $attempt1.sent
    }

    [pscustomobject]$result
}
finally {
    if (-not $KeepTempFiles.IsPresent) {
        foreach ($path in @($scriptPath, $messagePath)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }
}