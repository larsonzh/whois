param(
    [ValidateSet('sidebar-chat', 'quick-chat', 'raw', 'toggle', 'toggle-shortcut', 'toggle-then-esc')][string]$Mode = 'toggle',
    [ValidateRange(0, 5)][int]$EscCount = 0,
    [AllowEmptyString()][string]$TargetWindowTitle = 'whois',
    [AllowEmptyString()][string]$AhkExePath = '',
    [AllowEmptyString()][string]$ChatToggleShortcut = '^!b',
    [ValidateRange(0.0, 1.0)][double]$ChatInputClickXRatio = 0.84,
    [ValidateRange(0.0, 1.0)][double]$ChatInputClickYRatio = 0.94,
    [ValidateRange(0, 400)][int]$ChatBottomAvoidPx = 170,
    [ValidateSet('ratio', 'right-offset')][string]$ChatInputXMode = 'right-offset',
    [ValidateRange(0, 2400)][int]$ChatInputRightOffsetPx = 300,
    [ValidateRange(0, 5000)][int]$ObserveDelayMs = 800,
    [switch]$NoClickFocusFallback,
    [switch]$NoMaximizeCodeWindow,
    [switch]$KeepTempFiles,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Convert-ToInvariantNumber {
    param([double]$Value)

    return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
}

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

function Resolve-AhkExecutablePath {
    param([AllowEmptyString()][string]$ConfiguredPath)

    $candidates = New-Object 'System.Collections.Generic.List[string]'

    $normalizedConfigured = Convert-ToSingleLineText -Text $ConfiguredPath
    if (-not [string]::IsNullOrWhiteSpace($normalizedConfigured)) {
        [void]$candidates.Add((Resolve-RepoPathAllowMissing -Path $normalizedConfigured))
    }

    $envPath = Convert-ToSingleLineText -Text $env:AUTOHOTKEY_EXE
    if (-not [string]::IsNullOrWhiteSpace($envPath)) {
        [void]$candidates.Add((Resolve-RepoPathAllowMissing -Path $envPath))
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

function Get-AhkExitReason {
    param([int]$ExitCode)

    switch ($ExitCode) {
        0 { return 'ok' }
        34 { return 'clipboard-write-failed-while-running-focus-command' }
        35 { return 'vscode-window-not-active-in-time' }
        36 { return 'vscode-window-not-found' }
        38 { return 'chat-input-not-focused-before-esc' }
        default { return ('ahk-exit-{0}' -f $ExitCode) }
    }
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$ahkExecutable = Resolve-AhkExecutablePath -ConfiguredPath $AhkExePath
if ([string]::IsNullOrWhiteSpace($ahkExecutable)) {
    throw 'AutoHotkey executable not found. Provide -AhkExePath or install AutoHotkey v2.'
}

$tmpDir = Join-Path $script:RepoRoot 'tmp'
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$scriptPath = Join-Path $tmpDir ("chat_esc_repro_{0}.ahk" -f $stamp)

$targetToken = Convert-ToSingleLineText -Text $TargetWindowTitle
$targetToken = $targetToken.Replace('"', '""')
$toggleShortcutToken = Convert-ToSingleLineText -Text $ChatToggleShortcut
if ([string]::IsNullOrWhiteSpace($toggleShortcutToken)) {
    $toggleShortcutToken = '^!b'
}
$requestedMode = $Mode
$effectiveMode = $Mode
$effectiveEscCount = $EscCount
if ($effectiveMode -eq 'toggle-shortcut') {
    $effectiveMode = 'toggle'
    $effectiveEscCount = 0
}
elseif ($effectiveMode -eq 'toggle-then-esc') {
    $effectiveMode = 'toggle'
    if ($effectiveEscCount -lt 1) {
        $effectiveEscCount = 1
    }
}
$useMaximizeCodeWindow = (-not $NoMaximizeCodeWindow.IsPresent)
$useClickFocusFallback = (-not $NoClickFocusFallback.IsPresent)

$ahkScript = @(
    '#Requires AutoHotkey v2.0',
    '#SingleInstance Force',
    '#Warn All, Off',
    'CoordMode "Caret", "Screen"',
    'SetTitleMatchMode 2',
    'targetToken := (A_Args.Length >= 1) ? Trim(A_Args[1]) : ""',
    'mode := (A_Args.Length >= 2) ? Trim(StrLower(A_Args[2])) : "toggle"',
    'escCount := (A_Args.Length >= 3) ? Integer(A_Args[3]) : 0',
    'useClickFocusFallback := (A_Args.Length >= 4 && A_Args[4] = "1")',
    'clickXRatio := (A_Args.Length >= 5) ? Number(A_Args[5]) : 0.84',
    'clickYRatio := (A_Args.Length >= 6) ? Number(A_Args[6]) : 0.94',
    'bottomAvoidPx := (A_Args.Length >= 7) ? Integer(A_Args[7]) : 170',
    'xMode := (A_Args.Length >= 8) ? Trim(StrLower(A_Args[8])) : "right-offset"',
    'rightOffsetPx := (A_Args.Length >= 9) ? Integer(A_Args[9]) : 300',
    'useMaximize := (A_Args.Length >= 10 && A_Args[10] = "1")',
    'observeDelayMs := (A_Args.Length >= 11) ? Integer(A_Args[11]) : 800',
    'toggleShortcut := (A_Args.Length >= 12) ? A_Args[12] : "^!b"',
    'if (observeDelayMs < 0)',
    '    observeDelayMs := 0',
    'if (escCount < 0)',
    '    escCount := 0',
    'if (mode != "toggle" && escCount < 1)',
    '    escCount := 1',
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
    'title := "ahk_exe Code.exe"',
    'if (targetToken != "") {',
    '    candidate := targetToken " ahk_exe Code.exe"',
    '    if WinExist(candidate)',
    '        title := candidate',
    '}',
    'if !WinExist(title)',
    '    ExitApp(36)',
    'WinActivate(title)',
    'if useMaximize',
    '    WinMaximize(title)',
    'if !WinWaitActive(title,,3)',
    '    ExitApp(35)',
    'Sleep 180',
    'if (mode = "sidebar-chat") {',
    '    RunPaletteCommand(">chat.action.focus")',
    '    RunPaletteCommand(">workbench.action.chat.open")',
    '    RunPaletteCommand(">workbench.action.chat.focusInput")',
    '    if useClickFocusFallback && WinExist(title) {',
    '        WinGetPos &wx, &wy, &ww, &wh, title',
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
    '            focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx)',
    '            if (focusState = 0)',
    '                RunPaletteCommand(">workbench.action.chat.focusInput")',
    '        }',
    '    }',
    '    if WinExist(title) {',
    '        WinGetPos &wx0, &wy0, &ww0, &wh0, title',
    '        if (ww0 > 0 && wh0 > 0) {',
    '            focusBeforeEsc := IsLikelyChatCaretInInput(wx0, wy0, ww0, wh0, bottomAvoidPx)',
    '            if (focusBeforeEsc = 0)',
    '                ExitApp(38)',
    '        }',
    '    }',
    '} else if (mode = "quick-chat") {',
    '    RunPaletteCommand(">workbench.action.quickchat.toggle")',
    '    Sleep 350',
    '} else if (mode = "toggle") {',
    '    Send toggleShortcut',
    '    Sleep 260',
    '}',
    'if (observeDelayMs > 0)',
    '    Sleep observeDelayMs',
    'if (escCount > 0) {',
    '    Loop escCount {',
    '        Send "{Esc}"',
    '        if (A_Index < escCount)',
    '            Sleep 120',
    '    }',
    '}',
    'ExitApp(0)'
)

$clickFallbackFlag = if ($useClickFocusFallback) { '1' } else { '0' }
$maximizeFlag = if ($useMaximizeCodeWindow) { '1' } else { '0' }
$ahkArgumentList = @(
    $scriptPath,
    $targetToken,
    $effectiveMode,
    ([string]$effectiveEscCount),
    $clickFallbackFlag,
    (Convert-ToInvariantNumber -Value $ChatInputClickXRatio),
    (Convert-ToInvariantNumber -Value $ChatInputClickYRatio),
    ([string]$ChatBottomAvoidPx),
    $ChatInputXMode,
    ([string]$ChatInputRightOffsetPx),
    $maximizeFlag,
    ([string]$ObserveDelayMs),
    $toggleShortcutToken
)

$result = [ordered]@{
    schema = 'CHAT_ESC_REPRO_V2'
    mode = $effectiveMode
    requested_mode = $requestedMode
    esc_count = $effectiveEscCount
    chat_toggle_shortcut = $toggleShortcutToken
    target_window_title = $TargetWindowTitle
    ahk_executable = $ahkExecutable
    click_focus_fallback = $useClickFocusFallback
    maximize_code_window = $useMaximizeCodeWindow
    chat_input_x_mode = $ChatInputXMode
    chat_input_right_offset_px = $ChatInputRightOffsetPx
    observe_delay_ms = $ObserveDelayMs
    chat_input_click_ratio = [ordered]@{
        x = $ChatInputClickXRatio
        y = $ChatInputClickYRatio
    }
    chat_bottom_avoid_px = $ChatBottomAvoidPx
    script_path = $scriptPath
    exit_code = -1
    exit_reason = ''
}

try {
    Set-Content -LiteralPath $scriptPath -Value $ahkScript -Encoding ascii
    $process = Start-Process -FilePath $ahkExecutable -ArgumentList $ahkArgumentList -PassThru -Wait
    $result.exit_code = [int]$process.ExitCode
    $result.exit_reason = Get-AhkExitReason -ExitCode $result.exit_code

    if ($AsJson.IsPresent) {
        $result | ConvertTo-Json -Depth 8
    }
    else {
        Write-Output ("[CHAT-ESC-REPRO] mode={0} requested_mode={1} esc_count={2} target={3} script={4}" -f $effectiveMode, $requestedMode, $effectiveEscCount, $TargetWindowTitle, $scriptPath)
        Write-Output ("[CHAT-ESC-REPRO] click_fallback={0} maximize={1} x_mode={2} right_offset={3}" -f [bool]$result.click_focus_fallback, [bool]$result.maximize_code_window, [string]$result.chat_input_x_mode, [int]$result.chat_input_right_offset_px)
        Write-Output ("[CHAT-ESC-REPRO] observe_delay_ms={0}" -f [int]$result.observe_delay_ms)
        Write-Output ("[CHAT-ESC-REPRO] exit_code={0} exit_reason={1}" -f [int]$result.exit_code, [string]$result.exit_reason)
    }
}
finally {
    if (-not $KeepTempFiles.IsPresent -and (Test-Path -LiteralPath $scriptPath)) {
        Remove-Item -LiteralPath $scriptPath -Force -ErrorAction SilentlyContinue
    }
}
