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
    [switch]$RequireCodeChatFocusSuccess,
    [switch]$RequireActiveCodeWindow,
    [switch]$RequireChatCaretInInput,
    [switch]$NoClearInputBeforePaste,
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
    param([AllowEmptyString()][string]$PreferredPath = '')

    $candidates = New-Object 'System.Collections.Generic.List[string]'

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
        [void]$candidates.Add($PreferredPath)
    }

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

    $rawCodeCommand = Get-Command code -ErrorAction SilentlyContinue
    $preferredPath = ''
    if ($null -ne $rawCodeCommand -and -not [string]::IsNullOrWhiteSpace([string]$rawCodeCommand.Source)) {
        $preferredPath = [string]$rawCodeCommand.Source
    }

    $codeCliPath = Resolve-CodeCliPath -PreferredPath $preferredPath
    if ([string]::IsNullOrWhiteSpace($codeCliPath)) {
        $result.reason = 'code-cli-not-found'
        return [pscustomobject]$result
    }

    if (Test-IsCodeGuiExecutablePath -Path $codeCliPath) {
        $result.reason = 'code-cli-resolves-to-gui-exe'
        return [pscustomobject]$result
    }

    try {
        $result.tried = $true
        Start-Process -FilePath $codeCliPath -ArgumentList @('--reuse-window', '--command', $CommandId) -ErrorAction Stop | Out-Null
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

function Test-IsForegroundCodeWindow {
    $typeName = 'WcForegroundWindowInfo'
    if (-not ($typeName -as [type])) {
        $typeDef = @"
using System;
using System.Runtime.InteropServices;

public static class WcForegroundWindowInfo
{
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
}
"@

        try {
            Add-Type -TypeDefinition $typeDef -ErrorAction Stop | Out-Null
        }
        catch {
            return $false
        }
    }

    $hwnd = [WcForegroundWindowInfo]::GetForegroundWindow()
    if ($hwnd -eq [IntPtr]::Zero) {
        return $false
    }

    $foregroundProcessId = [uint32]0
    [void][WcForegroundWindowInfo]::GetWindowThreadProcessId($hwnd, [ref]$foregroundProcessId)
    if ($foregroundProcessId -eq 0) {
        return $false
    }

    try {
        $proc = Get-Process -Id ([int]$foregroundProcessId) -ErrorAction Stop
        return ($proc.ProcessName -ieq 'Code')
    }
    catch {
        return $false
    }
}
function Test-CodeCliSupportsCommandOption {
    param([AllowEmptyString()][string]$CodeExecutable)

    if ([string]::IsNullOrWhiteSpace($CodeExecutable) -or -not (Test-Path -LiteralPath $CodeExecutable)) {
        return $false
    }

    if (Test-IsCodeGuiExecutablePath -Path $CodeExecutable) {
        return $false
    }

    try {
        $helpText = & $CodeExecutable --help 2>$null | Out-String
        if ([string]::IsNullOrWhiteSpace($helpText)) {
            return $false
        }

        return ($helpText -match '(?im)^\s*--command\b')
    }
    catch {
        return $false
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
        39 { return 'Required VS Code chat focus command did not succeed; dispatch aborted.' }
        40 { return 'Active VS Code window is required; dispatch aborted.' }
        41 { return 'Chat input caret is not in expected area; dispatch aborted.' }
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
$hasVsCodeCliHook = -not [string]::IsNullOrWhiteSpace([string]$env:VSCODE_IPC_HOOK_CLI)
$rawCodeCliCommand = Get-Command code -ErrorAction SilentlyContinue
$rawCodeCliSource = ''
if ($null -ne $rawCodeCliCommand -and -not [string]::IsNullOrWhiteSpace([string]$rawCodeCliCommand.Source)) {
    $rawCodeCliSource = [string]$rawCodeCliCommand.Source
}
$rawCodeCliIsGuiExe = Test-IsCodeGuiExecutablePath -Path $rawCodeCliSource
$resolvedCodeCliPath = Resolve-CodeCliPath -PreferredPath $rawCodeCliSource
$codeCliAvailable = -not [string]::IsNullOrWhiteSpace($resolvedCodeCliPath)
$codeCliSupportsCommand = $false
if ($codeCliAvailable) {
    $codeCliSupportsCommand = Test-CodeCliSupportsCommandOption -CodeExecutable $resolvedCodeCliPath
}
$codeCliFocusEligible = $codeCliAvailable -and $codeCliSupportsCommand -and $hasVsCodeCliHook
$usePaletteFocusCommand = $false
if ($EnablePaletteFocusCommand.IsPresent) {
    $usePaletteFocusCommand = $true
}
if ($NoPaletteFocusCommand.IsPresent) {
    $usePaletteFocusCommand = $false
}

$effectiveClickFocusFallback = $true
if ($NoClickFocusFallback.IsPresent) {
    $effectiveClickFocusFallback = $false
}
if ($UseClickFocusFallback.IsPresent) {
    $effectiveClickFocusFallback = $true
}
if ($NoFocusChatInput.IsPresent) {
    $effectiveClickFocusFallback = $false
}

$useMaximizeCodeWindow = (-not $NoMaximizeCodeWindow.IsPresent)

$chatToggleShortcutForcedDisabled = $false
$chatToggleShortcutDisabledReason = 'disabled-by-default'
$useChatToggleShortcut = $EnableChatToggleShortcut.IsPresent
if ($NoChatToggleShortcut.IsPresent) {
    $useChatToggleShortcut = $false
}
if ($NoFocusChatInput.IsPresent) {
    $useChatToggleShortcut = $false
    $chatToggleShortcutForcedDisabled = $true
    $chatToggleShortcutDisabledReason = 'disabled-by-no-focus-mode'
}
elseif ($useChatToggleShortcut) {
    $chatToggleShortcutDisabledReason = 'enabled-by-switch'
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
$requireCodeChatFocusSuccess = $RequireCodeChatFocusSuccess.IsPresent -and (-not $NoFocusChatInput.IsPresent)
$activeCodeWindowRequired = $RequireActiveCodeWindow.IsPresent
$requireChatCaretInInput = $RequireChatCaretInInput.IsPresent
$clearInputBeforePaste = (-not $NoClearInputBeforePaste.IsPresent) -and (-not $NoFocusChatInput.IsPresent)

$shouldInvokeCodeChatFocus = (-not $NoInvokeCodeChatFocus.IsPresent) -and (-not $NoFocusChatInput.IsPresent) -and $codeCliFocusEligible
if ($activeCodeWindowRequired) {
    $shouldInvokeCodeChatFocus = $false
}

$foregroundIsCodeWindow = $null
$foregroundProbePerformed = $false
if ($activeCodeWindowRequired -or $NoActivateWindow.IsPresent) {
    $foregroundIsCodeWindow = Test-IsForegroundCodeWindow
    $foregroundProbePerformed = $true
}

$noActivateWindowAutoDisabled = $false
$noActivateWindowAutoDisabledReason = 'not-applicable'
if ($NoActivateWindow.IsPresent -and (-not $activeCodeWindowRequired)) {
    if (-not [bool]$foregroundIsCodeWindow) {
        $noActivateWindowAutoDisabled = $true
        if ($isVsCodeIntegratedTerminal) {
            $noActivateWindowAutoDisabledReason = 'integrated-terminal-foreground-not-code-window'
        }
        else {
            $noActivateWindowAutoDisabledReason = 'external-shell-foreground-not-code-window'
        }
    }
    else {
        $noActivateWindowAutoDisabledReason = 'foreground-already-code-window'
    }
}

$ahkScript = @(
    '#Requires AutoHotkey v2.0',
    '#SingleInstance Force',
    '#Warn All, Off',
    'CoordMode "Caret", "Screen"',
    'SetTitleMatchMode "RegEx"',
    'if (A_Args.Length < 1)',
    '    ExitApp(31)',
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
    'strictFocusRequired := (A_Args.Length >= 16 && A_Args[16] = "1")',
    'requireCaretInInput := (A_Args.Length >= 17 && A_Args[17] = "1")',
    'clearInputBeforePaste := (A_Args.Length >= 18 && A_Args[18] = "1")',
    'clipboardBackup := ClipboardAll()',
    'RestoreClipboard(ExitReason, ExitCode) {',
    '    global clipboardBackup',
    '    try A_Clipboard := clipboardBackup',
    '}',
    'OnExit(RestoreClipboard)',
    'if !FileExist(messagePath)',
    '    ExitApp(31)',
    'message := FileRead(messagePath, "UTF-8")',
    'targetWin := "ahk_class Chrome_WidgetWin_1 ahk_exe Code.exe"',
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
    '    if !WinExist(targetWin)',
    '        ExitApp(36)',
    '    activationOk := false',
    '    Loop 3 {',
    '        WinActivate(targetWin)',
    '        if useMaximize',
    '            WinMaximize(targetWin)',
    '        if WinWaitActive(targetWin,, 2) {',
    '            activationOk := true',
    '            break',
    '        }',
    '        Sleep 180',
    '    }',
    '    if !activationOk',
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
    '    }',
    '    focusStateBeforeFallback := -1',
    '    if WinExist(targetWin) {',
    '        WinGetPos &wxPre, &wyPre, &wwPre, &whPre, targetWin',
    '        if (wwPre > 0 && whPre > 0)',
    '            focusStateBeforeFallback := IsLikelyChatCaretInInput(wxPre, wyPre, wwPre, whPre, bottomAvoidPx)',
    '    }',
    '    ; Avoid keyboard toggle shortcuts here to prevent panel visibility drift.',
    '    if useClickFocusFallback && WinExist(targetWin) {',
    '        WinGetPos &wx, &wy, &ww, &wh, targetWin',
    '        if (ww > 0 && wh > 0) {',
    '            focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx)',
    '            if (focusState != 1) {',
    '            if (xMode = "right-offset") {',
    '                effectiveRightOffset := rightOffsetPx',
    '                if (effectiveRightOffset > 420)',
    '                    effectiveRightOffset := 420',
    '                if (effectiveRightOffset < 240)',
    '                    effectiveRightOffset := 240',
    '                clickX := wx + ww - effectiveRightOffset',
    '            } else {',
    '                clickX := wx + Floor(ww * clickXRatio)',
    '            }',
    '            clickY := wy + wh - bottomAvoidPx - 84',
    '            safeMinX := wx + Floor(ww * 0.52)',
    '            safeMaxX := wx + ww - 110',
    '            safeMinY := wy + wh - bottomAvoidPx - 124',
    '            safeMaxY := wy + wh - bottomAvoidPx - 52',
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
    '            if (focusState != 1) {',
    '                altClickX := clickX - Floor(Max(34, rightOffsetPx * 0.12))',
    '                altClickY := wy + wh - bottomAvoidPx - 68',
    '                altMinX := wx + Floor(ww * 0.48)',
    '                altMaxX := wx + ww - 120',
    '                altMinY := wy + wh - bottomAvoidPx - 138',
    '                altMaxY := wy + wh - bottomAvoidPx - 34',
    '                if (altClickX < altMinX)',
    '                    altClickX := altMinX',
    '                if (altClickX > altMaxX)',
    '                    altClickX := altMaxX',
    '                if (altClickY < altMinY)',
    '                    altClickY := altMinY',
    '                if (altClickY > altMaxY)',
    '                    altClickY := altMaxY',
    '                Click altClickX, altClickY',
    '                Sleep 140',
    '                focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx)',
    '            }',
    '            if (focusState = -1 && useToggleShortcut) {',
    '                Send toggleShortcut',
    '                Sleep 220',
    '                Click clickX, clickY',
    '                Sleep 120',
    '                if useEscPreflight {',
    '                    Send "{Esc}"',
    '                    Sleep 60',
    '                }',
    '            }',
    '            }',
    '        }',
    '    }',
    '}',
    'if !noFocusChatInput && WinExist(targetWin) {',
    '    WinGetPos &wx0, &wy0, &ww0, &wh0, targetWin',
    '    if (ww0 > 0 && wh0 > 0) {',
    '        focusBeforeSend := IsLikelyChatCaretInInput(wx0, wy0, ww0, wh0, bottomAvoidPx)',
    '        if (strictFocusRequired && focusBeforeSend != 1)',
    '            ExitApp(38)',
    '        if (focusBeforeSend = 0)',
    '            ExitApp(38)',
    '    }',
    '}',
    'if requireCaretInInput && WinExist(targetWin) {',
    '    WinGetPos &wxReq, &wyReq, &wwReq, &whReq, targetWin',
    '    if (wwReq > 0 && whReq > 0) {',
    '        requiredFocusState := IsLikelyChatCaretInInput(wxReq, wyReq, wwReq, whReq, bottomAvoidPx)',
    '        if (requiredFocusState != 1)',
    '            ExitApp(41)',
    '    }',
    '}',
    'if clearInputBeforePaste && !noFocusChatInput && WinExist(targetWin) {',
    '    WinGetPos &wxClr, &wyClr, &wwClr, &whClr, targetWin',
    '    if (wwClr > 0 && whClr > 0) {',
    '        clearFocusState := IsLikelyChatCaretInInput(wxClr, wyClr, wwClr, whClr, bottomAvoidPx)',
    '        if (clearFocusState = 1) {',
    '            Send "^a"',
    '            Sleep 60',
    '            Send "{Backspace}"',
    '            Sleep 80',
    '        }',
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
    'if WinExist(targetWin) {',
    '    WinGetPos &wx2, &wy2, &ww2, &wh2, targetWin',
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
    click_focus_fallback = $effectiveClickFocusFallback
    maximize_code_window = $useMaximizeCodeWindow
    clear_input_before_paste = $clearInputBeforePaste
    chat_toggle_shortcut = [ordered]@{
        key = $ChatToggleShortcut
        enabled = $useChatToggleShortcut
        forced_disabled = $chatToggleShortcutForcedDisabled
        disabled_reason = $chatToggleShortcutDisabledReason
        requested_enable_switch = [bool]$EnableChatToggleShortcut
    }
    chat_input_x_mode = $effectiveChatInputXMode
    chat_input_right_offset_px = $ChatInputRightOffsetPx
    chat_input_effective_right_offset_px = [Math]::Min(420, [Math]::Max(240, $ChatInputRightOffsetPx))
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
        vscode_ipc_hook_present = $hasVsCodeCliHook
        code_cli_available = $codeCliAvailable
        code_cli_supports_command = $codeCliSupportsCommand
        code_cli_focus_eligible = $codeCliFocusEligible
        raw_code_command_source = $rawCodeCliSource
        raw_code_command_is_gui_exe = $rawCodeCliIsGuiExe
        resolved_code_cli_path = $resolvedCodeCliPath
        active_code_window_required = $activeCodeWindowRequired
        require_chat_caret_in_input = $requireChatCaretInInput
        foreground_probe_performed = $foregroundProbePerformed
        foreground_is_code_window = $foregroundIsCodeWindow
        requested_no_activate_window_switch = [bool]$NoActivateWindow
        no_activate_window_auto_disabled = $noActivateWindowAutoDisabled
        no_activate_window_auto_disabled_reason = $noActivateWindowAutoDisabledReason
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
        require_code_focus_success_switch = [bool]$RequireCodeChatFocusSuccess
        require_active_code_window_switch = [bool]$RequireActiveCodeWindow
        require_chat_caret_in_input_switch = [bool]$RequireChatCaretInInput
        no_clear_input_before_paste_switch = [bool]$NoClearInputBeforePaste
        effective_chat_input_x_mode = $effectiveChatInputXMode
        effective_chat_input_right_offset_px = [Math]::Min(420, [Math]::Max(240, $ChatInputRightOffsetPx))
        effective_palette_focus = $usePaletteFocusCommand
        effective_click_fallback = $effectiveClickFocusFallback
        effective_maximize_window = $useMaximizeCodeWindow
        effective_clear_input_before_paste = $clearInputBeforePaste
        effective_chat_toggle_shortcut = $useChatToggleShortcut
        chat_toggle_shortcut_forced_disabled = $chatToggleShortcutForcedDisabled
        effective_esc_preflight = $useEscPreflight
        effective_auto_reconnect_resend = $useAutoReconnectResend
        allowed = $shouldInvokeCodeChatFocus
        required = $requireCodeChatFocusSuccess
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

    if ($activeCodeWindowRequired -and (-not [bool]$foregroundIsCodeWindow)) {
        $result.sent = $false
        $result.ahk_exit_code = 40
        $result.auto_reconnect_resend.triggered = $false
        $result.auto_reconnect_resend.trigger_reason = 'blocked-by-active-code-window-required'
        $result.note = 'active-code-window-required'
        [pscustomobject]$result
        return
    }

    if ($shouldInvokeCodeChatFocus) {
        $result.code_chat_open = Invoke-CodeCommandBestEffort -CommandId 'workbench.action.chat.open' -DelayMs $FocusCommandDelayMs
        $result.code_chat_focus = Invoke-CodeCommandBestEffort -CommandId 'workbench.action.chat.focusInput' -DelayMs $FocusCommandDelayMs
    }
    elseif (-not $NoFocusChatInput.IsPresent) {
        $result.code_chat_open.reason = if ($NoInvokeCodeChatFocus.IsPresent) {
            'disabled-by-switch'
        }
        elseif ($activeCodeWindowRequired) {
            'disabled-by-active-window-only-policy'
        }
        elseif (-not $hasVsCodeCliHook) {
            'disabled-vscode-ipc-hook-missing'
        }
        elseif (-not $codeCliAvailable) {
            if ($rawCodeCliIsGuiExe) {
                'disabled-code-cli-resolves-to-gui-exe'
            }
            else {
                'disabled-code-cli-not-found'
            }
        }
        elseif (-not $codeCliSupportsCommand) {
            'disabled-code-cli-no-command-option'
        }
        else {
            'eligible-but-skipped'
        }
        $result.code_chat_focus.reason = $result.code_chat_open.reason
    }

    if ($requireCodeChatFocusSuccess -and $shouldInvokeCodeChatFocus) {
        $codeFocusReady = $shouldInvokeCodeChatFocus -and [bool]$result.code_chat_open.success -and [bool]$result.code_chat_focus.success
        if (-not $codeFocusReady) {
            $result.sent = $false
            $result.ahk_exit_code = 39
            $result.auto_reconnect_resend.triggered = $false
            $result.auto_reconnect_resend.trigger_reason = 'blocked-by-required-code-focus'
            $result.note = 'required-code-chat-focus-failed'
            [pscustomobject]$result
            return
        }
    }
    elseif ($requireCodeChatFocusSuccess -and -not $shouldInvokeCodeChatFocus) {
        $result.sent = $false
        $result.ahk_exit_code = 39
        $result.auto_reconnect_resend.triggered = $false
        $result.auto_reconnect_resend.trigger_reason = 'blocked-by-required-code-focus-unavailable'
        $result.note = 'required-code-chat-focus-unavailable'
        [pscustomobject]$result
        return
    }

    $effectiveNoActivateWindow = ($NoActivateWindow.IsPresent -or $activeCodeWindowRequired) -and (-not $noActivateWindowAutoDisabled)
    $result.code_focus_policy.effective_no_activate_window = $effectiveNoActivateWindow
    $noActivateFlag = if ($effectiveNoActivateWindow) { '1' } else { '0' }
    $noFocusFlag = if ($NoFocusChatInput.IsPresent) { '1' } else { '0' }
    $clickFallbackFlag = if ($effectiveClickFocusFallback) { '1' } else { '0' }
    $paletteFocusFlag = if ($usePaletteFocusCommand) { '1' } else { '0' }
    $maximizeFlag = if ($useMaximizeCodeWindow) { '1' } else { '0' }
    $toggleShortcutFlag = if ($useChatToggleShortcut) { '1' } else { '0' }
    $escPreflightFlag = if ($useEscPreflight) { '1' } else { '0' }
    $strictFocusRequiredFlag = if ($requireCodeChatFocusSuccess) { '1' } else { '0' }
    $requireChatCaretFlag = if ($requireChatCaretInInput) { '1' } else { '0' }
    $clearInputBeforePasteFlag = if ($clearInputBeforePaste) { '1' } else { '0' }
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
        $escPreflightFlag,
        $strictFocusRequiredFlag,
        $requireChatCaretFlag,
        $clearInputBeforePasteFlag
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
            if (($attempt1.exit_code -eq 35) -and (-not $effectiveNoActivateWindow) -and ($ahkArgumentList.Count -ge 3)) {
                # If activation timed out, retry once without window activation to avoid overlay deadlock.
                $ahkArgumentList[2] = '1'
                $secondAttemptReason = 'activation-timeout-retry-no-activate'
            }
        }
        elseif ((-not $NoFocusChatInput.IsPresent) -and ($attempt1.exit_code -in @(38, 41))) {
            # Keep retry on the same non-palette strategy to avoid panel visibility side effects.
            $needSecondAttempt = $true
            $secondAttemptReason = 'focus-guard-failed-retry-same-strategy'
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

        $maxAttemptCount = 2
        $retryDelayMs = $ReconnectResendDelayMs
        if ($secondAttemptReason -eq 'focus-guard-failed-retry-same-strategy') {
            $maxAttemptCount = 4
            $retryDelayMs = [Math]::Max(600, [Math]::Min($ReconnectResendDelayMs, 1500))
        }

        $lastAttempt = $attempt1
        for ($attemptNo = 2; $attemptNo -le $maxAttemptCount; $attemptNo++) {
            Start-Sleep -Milliseconds $retryDelayMs
            $attemptN = Invoke-AhkDispatchAttempt -AhkExecutable $ahkExecutable -AhkArgumentList $ahkArgumentList -TimeoutMs $TimeoutMs

            $result.dispatch_attempts += [pscustomobject]@{
                attempt = $attemptNo
                sent = $attemptN.sent
                timed_out = $attemptN.timed_out
                exit_code = $attemptN.exit_code
                failure = $attemptN.failure
                duration_ms = $attemptN.duration_ms
            }

            $lastAttempt = $attemptN
            if ($attemptN.sent) {
                break
            }

            $canRetryFocusGuard = ($secondAttemptReason -eq 'focus-guard-failed-retry-same-strategy') -and ($attemptN.exit_code -in @(38, 41)) -and ($attemptNo -lt $maxAttemptCount)
            if ($canRetryFocusGuard) {
                continue
            }

            break
        }

        $result.ahk_exit_code = $lastAttempt.exit_code
        $result.sent = $lastAttempt.sent
        if (-not $lastAttempt.sent) {
            $failure = if ([string]::IsNullOrWhiteSpace($lastAttempt.failure)) { Get-AhkExitReason -ExitCode $lastAttempt.exit_code } else { $lastAttempt.failure }
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