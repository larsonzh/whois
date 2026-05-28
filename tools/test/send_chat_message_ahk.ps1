param(
    [Parameter(Mandatory = $true)]
    [string]$Message,

    [AllowEmptyString()]
    [string]$TicketId = '',

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
    [switch]$NoResetZoomBeforeSend,
    [switch]$RequireActiveCodeWindow,
    [switch]$RequireChatCaretInInput,
    [switch]$AllowLeftAnchoredChatCaret,
    [switch]$AllowInconclusiveSubmitOutcome,
    [switch]$NoClearInputBeforePaste,
    [switch]$RestorePreviousForegroundWindow,
    [ValidateRange(1, 30)]
    [int]$RestorePreviousWindowCount = 1,
    [AllowEmptyString()]
    [string]$RestorePreviousWindowHandlesCsv = '',
    [switch]$EnableRestoreActivationTrace,
    [switch]$ClearInputOnly,
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

function Get-ForegroundWindowHandleBestEffort {
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
            return 0
        }
    }

    try {
        $hwnd = [WcForegroundWindowInfo]::GetForegroundWindow()
        if ($hwnd -eq [IntPtr]::Zero) {
            return 0
        }

        return [Int64]$hwnd.ToInt64()
    }
    catch {
        return 0
    }
}

function Get-WindowProcessNameBestEffort {
    param(
        [Int64]$Handle
    )

    if ($Handle -le 0) {
        return ''
    }

    if (-not ('WcForegroundWindowInfo' -as [type])) {
        [void](Get-ForegroundWindowHandleBestEffort)
    }

    if (-not ('WcForegroundWindowInfo' -as [type])) {
        return ''
    }

    try {
        $windowHandle = [System.IntPtr]::new($Handle)
        if ($windowHandle -eq [System.IntPtr]::Zero) {
            return ''
        }

        $processId = [uint32]0
        [void][WcForegroundWindowInfo]::GetWindowThreadProcessId($windowHandle, [ref]$processId)
        if ($processId -eq 0) {
            return ''
        }

        $proc = Get-Process -Id ([int]$processId) -ErrorAction Stop
        return [string]$proc.ProcessName
    }
    catch {
        return ''
    }
}

$script:LastForegroundWindowCaptureTrace = @()

function Test-WcWindowZOrderInfoType {
    if ('WcWindowZOrderInfo' -as [type]) {
        return $true
    }

    $typeDef = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class WcWindowZOrderInfo
{
    public const uint GW_HWNDNEXT = 2;
    public const uint GW_OWNER = 4;
    public const uint GA_ROOTOWNER = 3;

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    public static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowEnabled(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern IntPtr GetAncestor(IntPtr hWnd, uint gaFlags);

    [DllImport("user32.dll")]
    public static extern IntPtr GetLastActivePopup(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetWindowTextLengthW")]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetWindowTextW")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int maxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetClassNameW")]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder className, int maxCount);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongW", SetLastError = true)]
    private static extern IntPtr GetWindowLong32(IntPtr hWnd, int nIndex);

    public static IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex)
    {
        if (IntPtr.Size == 8)
            return GetWindowLongPtr64(hWnd, nIndex);
        return GetWindowLong32(hWnd, nIndex);
    }
}
"@

    try {
        Add-Type -TypeDefinition $typeDef -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Get-WindowTextBestEffort {
    param([IntPtr]$Handle)

    if (-not (Test-WcWindowZOrderInfoType)) {
        return ''
    }

    try {
        $length = [WcWindowZOrderInfo]::GetWindowTextLength($Handle)
        $capacity = [Math]::Max(2, $length + 4)
        $builder = New-Object System.Text.StringBuilder $capacity
        [void][WcWindowZOrderInfo]::GetWindowText($Handle, $builder, $builder.Capacity)
        return $builder.ToString().Trim()
    }
    catch {
        return ''
    }
}

function Get-WindowClassNameBestEffort {
    param([IntPtr]$Handle)

    if (-not (Test-WcWindowZOrderInfoType)) {
        return ''
    }

    try {
        $builder = New-Object System.Text.StringBuilder 256
        [void][WcWindowZOrderInfo]::GetClassName($Handle, $builder, $builder.Capacity)
        return $builder.ToString().Trim()
    }
    catch {
        return ''
    }
}

function Get-WindowExStyleBestEffort {
    param([IntPtr]$Handle)

    if (-not (Test-WcWindowZOrderInfoType)) {
        return [uint32]0
    }

    try {
        $stylePtr = [WcWindowZOrderInfo]::GetWindowLongPtr($Handle, -20)
        $styleInt64 = [Int64]$stylePtr.ToInt64()
        return [uint32]($styleInt64 -band 0xFFFFFFFF)
    }
    catch {
        return [uint32]0
    }
}

function Test-IsAltTabMainWindowBestEffort {
    param([IntPtr]$Handle)

    if (-not (Test-WcWindowZOrderInfoType)) {
        return $false
    }

    if ($Handle -eq [IntPtr]::Zero) {
        return $false
    }

    try {
        $walk = [WcWindowZOrderInfo]::GetAncestor($Handle, [WcWindowZOrderInfo]::GA_ROOTOWNER)
        if ($walk -eq [IntPtr]::Zero) {
            $walk = $Handle
        }

        $guard = 0
        while ($guard -lt 64) {
            $popup = [WcWindowZOrderInfo]::GetLastActivePopup($walk)
            if ($popup -eq [IntPtr]::Zero -or $popup -eq $walk) {
                break
            }

            if ([WcWindowZOrderInfo]::IsWindowVisible($popup)) {
                $walk = $popup
                break
            }

            $walk = $popup
            $guard++
        }

        return ($walk -eq $Handle)
    }
    catch {
        return $false
    }
}

function Get-ForegroundWindowHandleStackBestEffort {
    param(
        [ValidateRange(1, 30)]
        [int]$MaxCount = 1
    )

    $handles = New-Object 'System.Collections.Generic.List[Int64]'
    $trace = New-Object 'System.Collections.Generic.List[object]'

    if (-not (Test-WcWindowZOrderInfoType)) {
        $script:LastForegroundWindowCaptureTrace = @()
        return @()
    }

    if (-not ('WcForegroundWindowInfo' -as [type])) {
        [void](Get-ForegroundWindowHandleBestEffort)
    }

    if (-not ('WcForegroundWindowInfo' -as [type])) {
        $script:LastForegroundWindowCaptureTrace = @()
        return @()
    }

    try {
        $current = [WcWindowZOrderInfo]::GetForegroundWindow()
        $scanIndex = 0
        while ($current -ne [IntPtr]::Zero -and $handles.Count -lt $MaxCount) {
            $scanIndex++

            if (-not [WcWindowZOrderInfo]::IsWindow($current)) {
                [void]$trace.Add([pscustomobject]@{
                        scan_index = $scanIndex
                        handle = 0
                        process_id = 0
                        process_name = ''
                        class_name = ''
                        title = ''
                        visible = $false
                        enabled = $false
                        alt_tab_main = $false
                        ex_style_hex = '0x00000000'
                        owner_handle = 0
                        accepted = $false
                        reason = 'stop:invalid-window'
                    })
                break
            }

            $processId = [uint32]0
            [void][WcForegroundWindowInfo]::GetWindowThreadProcessId($current, [ref]$processId)

            $processName = ''
            if ($processId -gt 0) {
                try {
                    $proc = Get-Process -Id ([int]$processId) -ErrorAction Stop
                    $processName = [string]$proc.ProcessName
                    if ($proc.ProcessName -ieq 'Code') {
                        $codeBoundaryReason = if ($handles.Count -gt 0) { 'stop:reached-code-window-boundary' } else { 'skip:foreground-code-window-continue-scan' }
                        [void]$trace.Add([pscustomobject]@{
                                scan_index = $scanIndex
                                handle = [Int64]$current.ToInt64()
                                process_id = [int]$processId
                                process_name = $processName
                                class_name = (Get-WindowClassNameBestEffort -Handle $current)
                                title = (Get-WindowTextBestEffort -Handle $current)
                                visible = [bool]([WcWindowZOrderInfo]::IsWindowVisible($current))
                                enabled = [bool]([WcWindowZOrderInfo]::IsWindowEnabled($current))
                                alt_tab_main = $false
                                ex_style_hex = ('0x{0:X8}' -f (Get-WindowExStyleBestEffort -Handle $current))
                                owner_handle = [Int64]([WcWindowZOrderInfo]::GetWindow($current, [WcWindowZOrderInfo]::GW_OWNER).ToInt64())
                                accepted = $false
                                reason = $codeBoundaryReason
                            })

                        if ($handles.Count -gt 0) {
                            break
                        }

                        $nextFromCode = [WcWindowZOrderInfo]::GetWindow($current, [WcWindowZOrderInfo]::GW_HWNDNEXT)
                        if ($nextFromCode -eq [IntPtr]::Zero -or $nextFromCode -eq $current) {
                            break
                        }

                        $current = $nextFromCode
                        continue
                    }
                }
                catch {
                    # Process may have exited between handle scan and query; keep scanning safely.
                    $processName = ''
                }
            }

            $isVisible = [bool]([WcWindowZOrderInfo]::IsWindowVisible($current))
            $isEnabled = [bool]([WcWindowZOrderInfo]::IsWindowEnabled($current))
            $exStyleRaw = Get-WindowExStyleBestEffort -Handle $current
            $ownerHandle = [WcWindowZOrderInfo]::GetWindow($current, [WcWindowZOrderInfo]::GW_OWNER)
            $ownerValue = [Int64]$ownerHandle.ToInt64()

            $hasToolWindowStyle = (($exStyleRaw -band 0x00000080) -ne 0)
            $hasAppWindowStyle = (($exStyleRaw -band 0x00040000) -ne 0)
            $hasNoActivateStyle = (($exStyleRaw -band 0x08000000) -ne 0)
            $isOwnedNonAppWindow = ($ownerValue -ne 0 -and (-not $hasAppWindowStyle))
            $isAltTabMain = Test-IsAltTabMainWindowBestEffort -Handle $current

            $handleValue = [Int64]$current.ToInt64()
            $accepted = $false
            $reason = 'skip:unclassified'

            if (-not $isVisible) {
                $reason = 'skip:not-visible'
            }
            elseif (-not $isEnabled) {
                $reason = 'skip:not-enabled'
            }
            elseif ($hasNoActivateStyle) {
                $reason = 'skip:noactivate-style'
            }
            elseif ($hasToolWindowStyle) {
                $reason = 'skip:toolwindow-style'
            }
            elseif ($isOwnedNonAppWindow) {
                $reason = 'skip:owned-non-appwindow'
            }
            elseif (-not $isAltTabMain) {
                $reason = 'skip:not-alt-tab-main'
            }
            elseif ($handleValue -le 0 -or $handles.Contains($handleValue)) {
                $reason = 'skip:duplicate-handle'
            }
            else {
                $accepted = $true
                $reason = 'accept:alt-tab-main'
                [void]$handles.Add($handleValue)
            }

            [void]$trace.Add([pscustomobject]@{
                    scan_index = $scanIndex
                    handle = $handleValue
                    process_id = [int]$processId
                    process_name = $processName
                    class_name = (Get-WindowClassNameBestEffort -Handle $current)
                    title = (Get-WindowTextBestEffort -Handle $current)
                    visible = $isVisible
                    enabled = $isEnabled
                    alt_tab_main = $isAltTabMain
                    ex_style_hex = ('0x{0:X8}' -f $exStyleRaw)
                    owner_handle = $ownerValue
                    accepted = $accepted
                    reason = $reason
                })

            $current = [WcWindowZOrderInfo]::GetWindow($current, [WcWindowZOrderInfo]::GW_HWNDNEXT)
        }
    }
    catch {
        $script:LastForegroundWindowCaptureTrace = @()
        return @()
    }

    $script:LastForegroundWindowCaptureTrace = @($trace.ToArray())
    return @($handles.ToArray())
}

function Convert-WindowCaptureTraceToSummary {
    param(
        [object[]]$TraceRows,
        [ValidateRange(120, 4000)]
        [int]$MaxLength = 1200
    )

    if ($null -eq $TraceRows -or @($TraceRows).Count -le 0) {
        return ''
    }

    $segments = New-Object 'System.Collections.Generic.List[string]'
    foreach ($row in @($TraceRows)) {
        if ($null -eq $row) {
            continue
        }

        $scanIndex = [string]$row.scan_index
        $handle = [string]$row.handle
        $processName = [string]$row.process_name
        $title = [string]$row.title
        $reason = [string]$row.reason

        if ([string]::IsNullOrWhiteSpace($processName)) {
            $processName = '-'
        }
        if ([string]::IsNullOrWhiteSpace($title)) {
            $title = '-'
        }
        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = '-'
        }
        if ($title.Length -gt 48) {
            $title = $title.Substring(0, 48).TrimEnd() + '...'
        }

        [void]$segments.Add(('{0}:{1}:{2}:{3}:{4}' -f $scanIndex, $handle, $processName, $reason, $title))
    }

    if ($segments.Count -le 0) {
        return ''
    }

    $joined = ($segments -join ' | ')
    if ($joined.Length -gt $MaxLength) {
        return ($joined.Substring(0, $MaxLength).TrimEnd() + '...')
    }

    return $joined
}

function Convert-RestoreActivationTraceToSummary {
    param(
        [string[]]$TraceLines,
        [ValidateRange(120, 4000)]
        [int]$MaxLength = 1600
    )

    if ($null -eq $TraceLines -or @($TraceLines).Count -le 0) {
        return ''
    }

    $segments = New-Object 'System.Collections.Generic.List[string]'
    foreach ($rawLine in @($TraceLines)) {
        $line = [string]$rawLine
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $normalized = [regex]::Replace($line.Trim(), '\s+', ' ')
        if ($normalized.Length -gt 120) {
            $normalized = $normalized.Substring(0, 120).TrimEnd() + '...'
        }
        [void]$segments.Add($normalized)
    }

    if ($segments.Count -le 0) {
        return ''
    }

    $joined = ($segments -join ' | ')
    if ($joined.Length -gt $MaxLength) {
        return ($joined.Substring(0, $MaxLength).TrimEnd() + '...')
    }

    return $joined
}

function Get-RestoreActivationTraceMetricSet {
    param([string[]]$TraceLines)

    $metrics = [ordered]@{
        attempted = 0
        succeeded = 0
        final_foreground_handle = 0
        restore_executed = $false
        restore_skipped_reason = ''
    }

    if ($null -eq $TraceLines -or @($TraceLines).Count -le 0) {
        return [pscustomobject]$metrics
    }

    foreach ($rawLine in @($TraceLines)) {
        $line = [string]$rawLine
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line -match '^restore\|enabled=(\d+)') {
            $metrics.restore_executed = ($Matches[1] -eq '1')
            continue
        }

        if ($line -match '^restore\|skipped=(.+)$') {
            $metrics.restore_skipped_reason = [string]$Matches[1]
            continue
        }

        if ($line -match '^attempt\|') {
            $metrics.attempted++
            if ($line -match '(?:\|wait_active=1\b)|(?:\|active_now=1\b)') {
                $metrics.succeeded++
            }
            continue
        }

        if ($line -match '^final_foreground\|handle=(-?\d+)$') {
            $metrics.final_foreground_handle = [Int64]$Matches[1]
            continue
        }
    }

    return [pscustomobject]$metrics
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

function Invoke-SettingsZoomResetBestEffort {
    param(
        [ValidateRange(0, 5000)]
        [int]$PostApplyDelayMs = 400
    )

    $result = [ordered]@{
        command = 'settings.apply.zoom-and-font-defaults'
        tried = $false
        success = $false
        reason = 'not-invoked'
        changed = $false
        settings_path = ''
        wait_ms = 0
        defaults = [ordered]@{
            window_zoom_per_window = $false
            window_zoom_level = 0
            editor_font_size = 14
            terminal_integrated_font_size = 14
        }
    }

    if ([string]::IsNullOrWhiteSpace($env:APPDATA)) {
        $result.reason = 'appdata-missing'
        return [pscustomobject]$result
    }

    $settingsPath = Join-Path $env:APPDATA 'Code\User\settings.json'
    $result.settings_path = $settingsPath

    try {
        $result.tried = $true

        if (-not (Test-Path -LiteralPath $settingsPath)) {
            [System.IO.File]::WriteAllText($settingsPath, '{}', (New-Object System.Text.UTF8Encoding($false)))
        }

        $rawSettings = Get-Content -LiteralPath $settingsPath -Raw -Encoding utf8
        if ([string]::IsNullOrWhiteSpace($rawSettings)) {
            $rawSettings = '{}'
        }

        $parsedSettings = $null
        try {
            $parsedSettings = $rawSettings | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            $result.reason = 'settings-parse-failed'
            $result.error = $_.Exception.Message
            return [pscustomobject]$result
        }

        $settingsMap = [ordered]@{}
        if ($null -ne $parsedSettings) {
            foreach ($property in $parsedSettings.PSObject.Properties) {
                $settingsMap[$property.Name] = $property.Value
            }
        }

        $needApply = $false

        $zoomPerWindowConfigured = $settingsMap.Contains('window.zoomPerWindow')
        $zoomPerWindowValue = $false
        if ($zoomPerWindowConfigured) {
            try {
                $zoomPerWindowValue = [bool]$settingsMap['window.zoomPerWindow']
            }
            catch {
                $zoomPerWindowValue = $true
            }
        }
        else {
            $zoomPerWindowValue = $true
        }

        if (-not $zoomPerWindowConfigured -or $zoomPerWindowValue) {
            $needApply = $true
        }

        $zoomLevelValue = 0.0
        if ($settingsMap.Contains('window.zoomLevel')) {
            [double]$parsedZoomLevel = 0
            if ([double]::TryParse(([string]$settingsMap['window.zoomLevel']), [ref]$parsedZoomLevel)) {
                $zoomLevelValue = [double]$parsedZoomLevel
            }
            else {
                $needApply = $true
            }
        }

        if ($zoomLevelValue -ne 0) {
            $needApply = $true
        }

        $editorFontSizeValue = 14.0
        if ($settingsMap.Contains('editor.fontSize')) {
            [double]$parsedEditorFont = 0
            if ([double]::TryParse(([string]$settingsMap['editor.fontSize']), [ref]$parsedEditorFont)) {
                $editorFontSizeValue = [double]$parsedEditorFont
            }
            else {
                $needApply = $true
            }
        }

        if ($editorFontSizeValue -ne 14) {
            $needApply = $true
        }

        $terminalFontSizeValue = 14.0
        if ($settingsMap.Contains('terminal.integrated.fontSize')) {
            [double]$parsedTerminalFont = 0
            if ([double]::TryParse(([string]$settingsMap['terminal.integrated.fontSize']), [ref]$parsedTerminalFont)) {
                $terminalFontSizeValue = [double]$parsedTerminalFont
            }
            else {
                $needApply = $true
            }
        }

        if ($terminalFontSizeValue -ne 14) {
            $needApply = $true
        }

        if ($needApply) {
            $settingsMap['window.zoomPerWindow'] = $false
            $settingsMap['window.zoomLevel'] = 0
            $settingsMap['editor.fontSize'] = 14
            $settingsMap['terminal.integrated.fontSize'] = 14

            [System.IO.File]::WriteAllText($settingsPath, ($settingsMap | ConvertTo-Json -Depth 60), (New-Object System.Text.UTF8Encoding($false)))
            $result.changed = $true

            if ($PostApplyDelayMs -gt 0) {
                Start-Sleep -Milliseconds $PostApplyDelayMs
                $result.wait_ms = $PostApplyDelayMs
            }

            $result.success = $true
            $result.reason = 'applied'
            return [pscustomobject]$result
        }

        $result.success = $true
        $result.reason = 'already-default'
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
        39 { return 'Required VS Code chat focus command did not succeed; dispatch aborted.' }
        40 { return 'Active VS Code window is required; dispatch aborted.' }
        41 { return 'Chat input caret is not in expected area; dispatch aborted.' }
        42 { return 'Unable to verify chat submit outcome because chat input could not be confirmed after Enter.' }
        43 { return 'Ticket fingerprint is missing from dispatch message; dispatch aborted before submit.' }
        44 { return 'Ticket fingerprint mismatch in chat input before submit; dispatch aborted before send.' }
        default { return ("AHK dispatch failed with exit code {0}." -f $ExitCode) }
    }
}

function Invoke-AhkDispatchAttempt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AhkExecutable,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
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
            $killFailureMessage = ''
            try {
                $process.Kill()
            }
            catch {
                $killFailureMessage = $_.Exception.Message
            }

            $attempt.timed_out = $true
            if ([string]::IsNullOrWhiteSpace($killFailureMessage)) {
                $attempt.failure = ("AHK dispatch timed out after {0} ms." -f $timeout)
            }
            else {
                $attempt.failure = ("AHK dispatch timed out after {0} ms; kill failed: {1}" -f $timeout, $killFailureMessage)
            }
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
$emptyArgSentinel = '__WC_EMPTY__'
$restoreTracePath = ''
if ($EnableRestoreActivationTrace.IsPresent) {
    $restoreTracePath = Join-Path $tempRoot ("restore_{0}.trace" -f $token)
}

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
$allowLeftAnchoredChatCaret = $AllowLeftAnchoredChatCaret.IsPresent
$allowInconclusiveSubmitOutcome = $AllowInconclusiveSubmitOutcome.IsPresent
$clearInputBeforePaste = (-not $NoClearInputBeforePaste.IsPresent) -and (-not $NoFocusChatInput.IsPresent)
$clearInputOnly = $ClearInputOnly.IsPresent
$useResetZoomBeforeSend = (-not $NoResetZoomBeforeSend.IsPresent) -and (-not $NoFocusChatInput.IsPresent) -and (-not $activeCodeWindowRequired)

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
    'if (toggleShortcut = "__WC_EMPTY__")',
    '    toggleShortcut := ""',
    'useEscPreflight := (A_Args.Length >= 15 && A_Args[15] = "1")',
    'strictFocusRequired := (A_Args.Length >= 16 && A_Args[16] = "1")',
    'requireCaretInInput := (A_Args.Length >= 17 && A_Args[17] = "1")',
    'clearInputBeforePaste := (A_Args.Length >= 18 && A_Args[18] = "1")',
    'restorePreviousWindow := (A_Args.Length >= 19 && A_Args[19] = "1")',
    'previousWindowHandle := (A_Args.Length >= 20) ? Integer(A_Args[20]) : 0',
    'previousWindowStackCsv := (A_Args.Length >= 21) ? Trim(A_Args[21]) : ""',
    'restorePreviousWindowLimit := (A_Args.Length >= 22) ? Integer(A_Args[22]) : 0',
    'allowLeftAnchoredCaret := (A_Args.Length >= 23 && A_Args[23] = "1")',
    'allowInconclusiveSubmit := (A_Args.Length >= 24 && A_Args[24] = "1")',
    'restoreTracePath := (A_Args.Length >= 25) ? Trim(A_Args[25]) : ""',
    'if (restoreTracePath = "__WC_EMPTY__")',
    '    restoreTracePath := ""',
    'ticketIdFingerprint := (A_Args.Length >= 26) ? Trim(A_Args[26]) : ""',
    'if (ticketIdFingerprint = "__WC_EMPTY__")',
    '    ticketIdFingerprint := ""',
    'clearInputOnly := (A_Args.Length >= 27 && A_Args[27] = "1")',
    'previousWins := []',
    'if restorePreviousWindow {',
    '    try {',
    '        if (previousWindowStackCsv != "") {',
    '            for token in StrSplit(previousWindowStackCsv, ",") {',
    '                tokenTrim := Trim(token)',
    '                if (tokenTrim = "")',
    '                    continue',
    '                h := Integer(tokenTrim)',
    '                if (h)',
    '                    previousWins.Push(h)',
    '            }',
    '        }',
    '        if (previousWindowHandle) {',
    '            seenPrev := false',
    '            for hExisting in previousWins {',
    '                if (hExisting = previousWindowHandle) {',
    '                    seenPrev := true',
    '                    break',
    '                }',
    '            }',
    '            if (!seenPrev)',
    '                previousWins.InsertAt(1, previousWindowHandle)',
    '        }',
    '        if (previousWins.Length = 0) {',
    '            fallbackWin := WinExist("A")',
    '            if (fallbackWin)',
    '                previousWins.Push(fallbackWin)',
    '        }',
    '        if (restorePreviousWindowLimit <= 0)',
    '            restorePreviousWindowLimit := previousWins.Length',
    '    }',
    '}',
    'AppendRestoreTrace(lineText) {',
    '    global restoreTracePath',
    '    if (restoreTracePath = "")',
    '        return',
    '    try FileAppend(lineText "`n", restoreTracePath, "UTF-8")',
    '}',
    'if (restoreTracePath != "") {',
    '    try FileDelete(restoreTracePath)',
    '    AppendRestoreTrace("script|started=1")',
    '}',
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
    'IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx, allowLeftAnchoredCaret := false) {',
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
    '    if (allowLeftAnchoredCaret) {',
    '        leftMinX := wx + 16',
    '        if (cx >= leftMinX && cx <= maxX && cy >= minY && cy <= maxY)',
    '            return 1',
    '    }',
    '    return 0',
    '}',
    'ProbeRetainedInputAfterSend(messageText, wx, wy, ww, wh, bottomAvoidPx) {',
    '    focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx, allowLeftAnchoredCaret)',
    '    if (focusState != 1) {',
    '        probeClickX := wx + ww - 300',
    '        probeClickY := wy + wh - bottomAvoidPx - 80',
    '        probeMinX := wx + Floor(ww * 0.50)',
    '        probeMaxX := wx + ww - 110',
    '        probeMinY := wy + wh - bottomAvoidPx - 128',
    '        probeMaxY := wy + wh - bottomAvoidPx - 36',
    '        if (probeClickX < probeMinX)',
    '            probeClickX := probeMinX',
    '        if (probeClickX > probeMaxX)',
    '            probeClickX := probeMaxX',
    '        if (probeClickY < probeMinY)',
    '            probeClickY := probeMinY',
    '        if (probeClickY > probeMaxY)',
    '            probeClickY := probeMaxY',
    '        Click probeClickX, probeClickY',
    '        Sleep 120',
    '        focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx, allowLeftAnchoredCaret)',
    '        if (focusState != 1)',
    '            return -1',
    '    }',
    '    backup := ClipboardAll()',
    '    A_Clipboard := ""',
    '    Send "^a"',
    '    Sleep 60',
    '    Send "^c"',
    '    if !ClipWait(0.6) {',
    '        A_Clipboard := backup',
    '        return -1',
    '    }',
    '    copied := A_Clipboard',
    '    A_Clipboard := backup',
    '    copiedNorm := Trim(StrReplace(StrReplace(copied, "`r", " "), "`n", " "))',
    '    messageNorm := Trim(StrReplace(StrReplace(messageText, "`r", " "), "`n", " "))',
    '    if (copiedNorm = "" || messageNorm = "")',
    '        return 0',
    '    if (copiedNorm = messageNorm)',
    '        return 1',
    '    return 0',
    '}',
    'NormalizeTicketFingerprint(textValue) {',
    '    lowered := StrLower(Trim(textValue))',
    '    return RegExReplace(lowered, "[^0-9a-z]", "")',
    '}',
    'EnsureTicketFingerprintBeforeSubmit(ticketFingerprint, messageText, wx, wy, ww, wh, bottomAvoidPx) {',
    '    token := NormalizeTicketFingerprint(ticketFingerprint)',
    '    if (token = "")',
    '        return 0',
    '    messageToken := NormalizeTicketFingerprint(messageText)',
    '    if (!InStr(messageToken, token))',
    '        return 43',
    '    focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx, allowLeftAnchoredCaret)',
    '    if (focusState != 1) {',
    '        clickX := wx + ww - 300',
    '        clickY := wy + wh - bottomAvoidPx - 80',
    '        minX := wx + Floor(ww * 0.50)',
    '        maxX := wx + ww - 110',
    '        minY := wy + wh - bottomAvoidPx - 128',
    '        maxY := wy + wh - bottomAvoidPx - 36',
    '        if (clickX < minX)',
    '            clickX := minX',
    '        if (clickX > maxX)',
    '            clickX := maxX',
    '        if (clickY < minY)',
    '            clickY := minY',
    '        if (clickY > maxY)',
    '            clickY := maxY',
    '        Click clickX, clickY',
    '        Sleep 120',
    '        focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx, allowLeftAnchoredCaret)',
    '        if (focusState != 1)',
    '            return 44',
    '    }',
    '    backup := ClipboardAll()',
    '    A_Clipboard := ""',
    '    Send "^a"',
    '    Sleep 60',
    '    Send "^c"',
    '    if !ClipWait(0.7) {',
    '        A_Clipboard := backup',
    '        return 44',
    '    }',
    '    observed := A_Clipboard',
    '    A_Clipboard := backup',
    '    observedToken := NormalizeTicketFingerprint(observed)',
    '    if (!InStr(observedToken, token))',
    '        return 44',
    '    return 0',
    '}',
    'ClearChatInputBestEffort(wx, wy, ww, wh, bottomAvoidPx) {',
    '    if (ww <= 0 || wh <= 0)',
    '        return',
    '    clearClickX := wx + ww - 300',
    '    clearClickY := wy + wh - bottomAvoidPx - 80',
    '    clearMinX := wx + Floor(ww * 0.50)',
    '    clearMaxX := wx + ww - 110',
    '    clearMinY := wy + wh - bottomAvoidPx - 128',
    '    clearMaxY := wy + wh - bottomAvoidPx - 36',
    '    if (clearClickX < clearMinX)',
    '        clearClickX := clearMinX',
    '    if (clearClickX > clearMaxX)',
    '        clearClickX := clearMaxX',
    '    if (clearClickY < clearMinY)',
    '        clearClickY := clearMinY',
    '    if (clearClickY > clearMaxY)',
    '        clearClickY := clearMaxY',
    '    Click clearClickX, clearClickY',
    '    Sleep 120',
    '    Send "^a"',
    '    Sleep 60',
    '    Send "{Backspace}"',
    '    Sleep 80',
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
    '            focusStateBeforeFallback := IsLikelyChatCaretInInput(wxPre, wyPre, wwPre, whPre, bottomAvoidPx, allowLeftAnchoredCaret)',
    '    }',
    '    ; Avoid keyboard toggle shortcuts here to prevent panel visibility drift.',
    '    if useClickFocusFallback && WinExist(targetWin) {',
    '        WinGetPos &wx, &wy, &ww, &wh, targetWin',
    '        if (ww > 0 && wh > 0) {',
    '            focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx, allowLeftAnchoredCaret)',
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
    '            focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx, allowLeftAnchoredCaret)',
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
    '                focusState := IsLikelyChatCaretInInput(wx, wy, ww, wh, bottomAvoidPx, allowLeftAnchoredCaret)',
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
    '        focusBeforeSend := IsLikelyChatCaretInInput(wx0, wy0, ww0, wh0, bottomAvoidPx, allowLeftAnchoredCaret)',
    '        if (strictFocusRequired && focusBeforeSend != 1)',
    '            ExitApp(38)',
    '        if (focusBeforeSend = 0)',
    '            ExitApp(38)',
    '    }',
    '}',
    'if requireCaretInInput && WinExist(targetWin) {',
    '    WinGetPos &wxReq, &wyReq, &wwReq, &whReq, targetWin',
    '    if (wwReq > 0 && whReq > 0) {',
    '        requiredFocusState := IsLikelyChatCaretInInput(wxReq, wyReq, wwReq, whReq, bottomAvoidPx, allowLeftAnchoredCaret)',
    '        if (requiredFocusState != 1) {',
    '            reqClickX := wxReq + wwReq - 300',
    '            reqClickY := wyReq + whReq - bottomAvoidPx - 80',
    '            reqMinX := wxReq + Floor(wwReq * 0.50)',
    '            reqMaxX := wxReq + wwReq - 110',
    '            reqMinY := wyReq + whReq - bottomAvoidPx - 128',
    '            reqMaxY := wyReq + whReq - bottomAvoidPx - 36',
    '            if (reqClickX < reqMinX)',
    '                reqClickX := reqMinX',
    '            if (reqClickX > reqMaxX)',
    '                reqClickX := reqMaxX',
    '            if (reqClickY < reqMinY)',
    '                reqClickY := reqMinY',
    '            if (reqClickY > reqMaxY)',
    '                reqClickY := reqMaxY',
    '            Click reqClickX, reqClickY',
    '            Sleep 120',
    '            requiredFocusState := IsLikelyChatCaretInInput(wxReq, wyReq, wwReq, whReq, bottomAvoidPx, allowLeftAnchoredCaret)',
    '            if (requiredFocusState = 0)',
    '                ExitApp(41)',
    '            if (requiredFocusState = -1 && strictFocusRequired)',
    '                ExitApp(41)',
    '        }',
    '    }',
    '}',
    'if clearInputBeforePaste && !noFocusChatInput && WinExist(targetWin) {',
    '    WinGetPos &wxClr, &wyClr, &wwClr, &whClr, targetWin',
    '    if (wwClr > 0 && whClr > 0) {',
    '        clearFocusState := IsLikelyChatCaretInInput(wxClr, wyClr, wwClr, whClr, bottomAvoidPx, allowLeftAnchoredCaret)',
    '        if (clearFocusState = 1) {',
    '            Send "^a"',
    '            Sleep 60',
    '            Send "{Backspace}"',
    '            Sleep 80',
    '        } else if (requireCaretInInput && clearFocusState = -1) {',
    '            clrClickX := wxClr + wwClr - 300',
    '            clrClickY := wyClr + whClr - bottomAvoidPx - 80',
    '            clrMinX := wxClr + Floor(wwClr * 0.50)',
    '            clrMaxX := wxClr + wwClr - 110',
    '            clrMinY := wyClr + whClr - bottomAvoidPx - 128',
    '            clrMaxY := wyClr + whClr - bottomAvoidPx - 36',
    '            if (clrClickX < clrMinX)',
    '                clrClickX := clrMinX',
    '            if (clrClickX > clrMaxX)',
    '                clrClickX := clrMaxX',
    '            if (clrClickY < clrMinY)',
    '                clrClickY := clrMinY',
    '            if (clrClickY > clrMaxY)',
    '                clrClickY := clrMaxY',
    '            Click clrClickX, clrClickY',
    '            Sleep 120',
    '            Send "^a"',
    '            Sleep 60',
    '            Send "{Backspace}"',
    '            Sleep 80',
    '        }',
    '    }',
    '}',
    'pendingExitCode := 0',
    'if clearInputOnly && !noFocusChatInput && WinExist(targetWin) {',
    '    WinGetPos &wxClearOnly, &wyClearOnly, &wwClearOnly, &whClearOnly, targetWin',
    '    if (wwClearOnly > 0 && whClearOnly > 0)',
    '        ClearChatInputBestEffort(wxClearOnly, wyClearOnly, wwClearOnly, whClearOnly, bottomAvoidPx)',
    '    AppendRestoreTrace("clear_only|executed=1")',
    '}',
    'if !clearInputOnly {',
    '    Sleep preDelay',
    '    A_Clipboard := message',
    '    if !ClipWait(1)',
    '        ExitApp(33)',
    '    Send "^v"',
    '    Sleep 120',
    '    if (ticketIdFingerprint != "") {',
    '        guardCode := 44',
    '        if WinExist(targetWin) {',
    '            WinGetPos &wxGuard, &wyGuard, &wwGuard, &whGuard, targetWin',
    '            if (wwGuard > 0 && whGuard > 0)',
    '                guardCode := EnsureTicketFingerprintBeforeSubmit(ticketIdFingerprint, message, wxGuard, wyGuard, wwGuard, whGuard, bottomAvoidPx)',
    '        }',
    '        if (guardCode = 43) {',
    '            AppendRestoreTrace("pre_submit_guard|ticket_missing_in_message=1")',
    '            if WinExist(targetWin) {',
    '                WinGetPos &wxGuardClear, &wyGuardClear, &wwGuardClear, &whGuardClear, targetWin',
    '                if (wwGuardClear > 0 && whGuardClear > 0)',
    '                    ClearChatInputBestEffort(wxGuardClear, wyGuardClear, wwGuardClear, whGuardClear, bottomAvoidPx)',
    '            }',
    '            ExitApp(43)',
    '        }',
    '        if (guardCode = 44) {',
    '            AppendRestoreTrace("pre_submit_guard|ticket_mismatch_or_unreadable=1")',
    '            if WinExist(targetWin) {',
    '                WinGetPos &wxGuardClear, &wyGuardClear, &wwGuardClear, &whGuardClear, targetWin',
    '                if (wwGuardClear > 0 && whGuardClear > 0)',
    '                    ClearChatInputBestEffort(wxGuardClear, wyGuardClear, wwGuardClear, whGuardClear, bottomAvoidPx)',
    '            }',
    '            ExitApp(44)',
    '        }',
    '    }',
    '    Send "{Enter}"',
    '    Sleep 300',
    '    if WinExist(targetWin) {',
    '        WinGetPos &wx2, &wy2, &ww2, &wh2, targetWin',
    '        if (ww2 > 0 && wh2 > 0) {',
    '            submitProbe := ProbeRetainedInputAfterSend(message, wx2, wy2, ww2, wh2, bottomAvoidPx)',
    '            if (submitProbe = 1) {',
    '                AppendRestoreTrace("submit_probe|retained_input=1|defer_exit=37")',
    '                pendingExitCode := 37',
    '            }',
    '            if (submitProbe = -1) {',
    '                if (allowInconclusiveSubmit) {',
    '                    AppendRestoreTrace("submit_probe|inconclusive=1|allow=1")',
    '                }',
    '                else {',
    '                    AppendRestoreTrace("submit_probe|inconclusive=1|allow=0|defer_exit=42")',
    '                    pendingExitCode := 42',
    '                }',
    '            }',
    '            if (pendingExitCode != 0) {',
    '                ClearChatInputBestEffort(wx2, wy2, ww2, wh2, bottomAvoidPx)',
    '                AppendRestoreTrace("post_submit_clear|exit=" pendingExitCode)',
    '            }',
    '        }',
    '    }',
    '}',
    'if restorePreviousWindow {',
    '    if previousWins.Length > 0 {',
    '        restoreTargetCount := restorePreviousWindowLimit',
    '        if (restoreTargetCount <= 0 || restoreTargetCount > previousWins.Length)',
    '            restoreTargetCount := previousWins.Length',
    '        AppendRestoreTrace("restore|enabled=1|target_count=" restoreTargetCount "|previous_count=" previousWins.Length)',
    '        restoreWins := []',
    '        for idx, prevHandle in previousWins {',
    '            targetPrev := "ahk_id " prevHandle',
    '            if WinExist(targetPrev) {',
    '                restoreWins.Push(prevHandle)',
    '                if (restoreWins.Length >= restoreTargetCount)',
    '                    break',
    '            }',
    '        }',
    '        AppendRestoreTrace("restore|resolved_count=" restoreWins.Length "|target_count=" restoreTargetCount)',
    '        if (restoreWins.Length > 0) {',
    '            loop restoreWins.Length {',
    '                idx := restoreWins.Length - A_Index + 1',
    '                prevHandle := restoreWins[idx]',
    '                targetPrev := "ahk_id " prevHandle',
    '                if WinExist(targetPrev) {',
    '                    prevState := WinGetMinMax(targetPrev)',
    '                    restoreAction := "none"',
    '                    if (prevState = 1) {',
    '                        WinMaximize(targetPrev)',
    '                        restoreAction := "maximize"',
    '                    }',
    '                    else if (prevState = 0) {',
    '                        WinRestore(targetPrev)',
    '                        restoreAction := "restore"',
    '                    }',
    '                    else if (prevState = -1) {',
    '                        WinRestore(targetPrev)',
    '                        restoreAction := "restore-from-minimized"',
    '                    }',
    '                    WinActivate(targetPrev)',
    '                    waitActive := 0',
    '                    if WinWaitActive(targetPrev,, 1)',
    '                        waitActive := 1',
    '                    activeNow := 0',
    '                    if WinActive(targetPrev)',
    '                        activeNow := 1',
    '                    AppendRestoreTrace("attempt|index=" idx "|handle=" prevHandle "|exists=1|pre_state=" prevState "|action=" restoreAction "|wait_active=" waitActive "|active_now=" activeNow)',
    '                    Sleep 40',
    '                }',
    '                else {',
    '                    AppendRestoreTrace("attempt|index=" idx "|handle=" prevHandle "|exists=0")',
    '                }',
    '            }',
    '        }',
    '        else {',
    '            AppendRestoreTrace("restore|enabled=1|target_count=0|reason=no-existing-targets")',
    '        }',
    '    }',
    '    else {',
    '        AppendRestoreTrace("restore|enabled=1|target_count=0|reason=no-previous-wins")',
    '    }',
    '}',
    'else {',
    '    AppendRestoreTrace("restore|enabled=0")',
    '}',
    'finalForeground := WinExist("A")',
    'AppendRestoreTrace("final_foreground|handle=" finalForeground)',
    'ExitApp(pendingExitCode)'
)

$requestedRestoreCount = if ($RestorePreviousForegroundWindow.IsPresent) {
    [Math]::Min(30, [Math]::Max(1, $RestorePreviousWindowCount))
}
else {
    0
}

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
    clear_input_only = $clearInputOnly
    allow_left_anchored_chat_caret = $allowLeftAnchoredChatCaret
    allow_inconclusive_submit_outcome = $allowInconclusiveSubmitOutcome
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
    reset_zoom_before_send = [ordered]@{
        command = 'settings.apply.zoom-and-font-defaults'
        enabled = $useResetZoomBeforeSend
        tried = $false
        success = $false
        reason = 'not-invoked'
        changed = $false
        settings_path = ''
        wait_ms = 0
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
        no_reset_zoom_before_send_switch = [bool]$NoResetZoomBeforeSend
        require_active_code_window_switch = [bool]$RequireActiveCodeWindow
        require_chat_caret_in_input_switch = [bool]$RequireChatCaretInInput
        allow_left_anchored_chat_caret_switch = [bool]$AllowLeftAnchoredChatCaret
        allow_inconclusive_submit_outcome_switch = [bool]$AllowInconclusiveSubmitOutcome
        no_clear_input_before_paste_switch = [bool]$NoClearInputBeforePaste
        clear_input_only_switch = [bool]$ClearInputOnly
        restore_previous_foreground_window_switch = [bool]$RestorePreviousForegroundWindow
        restore_previous_window_count_requested = $requestedRestoreCount
        enable_restore_activation_trace_switch = [bool]$EnableRestoreActivationTrace
        restore_previous_window_count_captured = 0
        restore_previous_window_handles = @()
        restore_previous_window_capture_trace = @()
        restore_previous_window_capture_summary = ''
        restore_previous_window_activation_trace = ''
        restore_previous_window_activation_count_attempted = 0
        restore_previous_window_activation_count_succeeded = 0
        restore_previous_window_activation_final_foreground_handle = 0
        restore_previous_window_activation_restore_executed = $false
        restore_previous_window_activation_skipped_reason = ''
        effective_chat_input_x_mode = $effectiveChatInputXMode
        effective_chat_input_right_offset_px = [Math]::Min(420, [Math]::Max(240, $ChatInputRightOffsetPx))
        effective_palette_focus = $usePaletteFocusCommand
        effective_click_fallback = $effectiveClickFocusFallback
        effective_maximize_window = $useMaximizeCodeWindow
        effective_clear_input_before_paste = $clearInputBeforePaste
        effective_clear_input_only = $clearInputOnly
        effective_chat_toggle_shortcut = $useChatToggleShortcut
        chat_toggle_shortcut_forced_disabled = $chatToggleShortcutForcedDisabled
        effective_esc_preflight = $useEscPreflight
        effective_allow_left_anchored_chat_caret = $allowLeftAnchoredChatCaret
        effective_allow_inconclusive_submit_outcome = $allowInconclusiveSubmitOutcome
        effective_auto_reconnect_resend = $useAutoReconnectResend
        effective_reset_zoom_before_send = $useResetZoomBeforeSend
        effective_restore_activation_trace = [bool]$EnableRestoreActivationTrace
        allowed = $shouldInvokeCodeChatFocus
        required = $requireCodeChatFocusSuccess
    }
    restore_previous_window_count_requested = $requestedRestoreCount
    restore_previous_window_count_captured = 0
    restore_previous_window_handles = @()
    restore_previous_window_capture_trace = @()
    restore_previous_window_capture_summary = ''
    restore_previous_window_activation_trace = ''
    restore_previous_window_activation_count_attempted = 0
    restore_previous_window_activation_count_succeeded = 0
    restore_previous_window_activation_final_foreground_handle = 0
    restore_previous_window_activation_restore_executed = $false
    restore_previous_window_activation_skipped_reason = ''
    restore_previous_window_activation_trace_path = $restoreTracePath
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

    $restorePreviousWindowHandle = 0
    $restorePreviousWindowHandles = @()
    $restorePreviousWindowHandlesForRestore = @()
    $restorePreviousWindowActivationLimit = 0
    $restorePreviousWindowCaptureTrace = @()
    $preferredRestoreHandles = @()
    if (-not [string]::IsNullOrWhiteSpace($RestorePreviousWindowHandlesCsv)) {
        $preferredRestoreHandles = @(
            $RestorePreviousWindowHandlesCsv -split ',' |
                ForEach-Object {
                    $token = ([string]$_).Trim()
                    if ($token -match '^\d+$') {
                        [Int64]$token
                    }
                } |
                Where-Object { $null -ne $_ -and [Int64]$_ -gt 0 } |
                Select-Object -Unique
        )
    }
    if ($RestorePreviousForegroundWindow.IsPresent) {
        $effectiveRestoreCount = $requestedRestoreCount
        if ($preferredRestoreHandles.Count -gt 0) {
            $restorePreviousWindowHandlesForRestore = @($preferredRestoreHandles)
            $captureRows = New-Object 'System.Collections.Generic.List[object]'
            for ($captureIndex = 0; $captureIndex -lt $restorePreviousWindowHandlesForRestore.Count; $captureIndex++) {
                $captureHandle = [Int64]$restorePreviousWindowHandlesForRestore[$captureIndex]
                [void]$captureRows.Add([pscustomobject]@{
                    scan_index = (2000 + $captureIndex)
                    handle = $captureHandle
                    process_id = 0
                    process_name = '-'
                    class_name = ''
                    title = 'preferred-restore-handle'
                    visible = $true
                    enabled = $true
                    alt_tab_main = $true
                    ex_style_hex = '0x00000000'
                    owner_handle = 0
                    accepted = $true
                    reason = 'accept:provided-restore-handle'
                })
            }
            $restorePreviousWindowCaptureTrace = @($captureRows.ToArray())
            $restorePreviousWindowActivationLimit = [Math]::Min($effectiveRestoreCount, $restorePreviousWindowHandlesForRestore.Count)
            if ($restorePreviousWindowActivationLimit -le 0 -and $restorePreviousWindowHandlesForRestore.Count -gt 0) {
                $restorePreviousWindowActivationLimit = 1
            }
            $restorePreviousWindowHandles = @($restorePreviousWindowHandlesForRestore | Select-Object -First $restorePreviousWindowActivationLimit)
            if ($restorePreviousWindowHandlesForRestore.Count -gt 0) {
                $restorePreviousWindowHandle = [Int64]$restorePreviousWindowHandlesForRestore[0]
            }
        }
        else {
            $rawPreviousForegroundHandle = [Int64](Get-ForegroundWindowHandleBestEffort)
            $rawPreviousForegroundProcessName = ''
            $rawPreviousForegroundIsCodeWindow = $false
            if ($rawPreviousForegroundHandle -gt 0) {
                $rawPreviousForegroundProcessName = Get-WindowProcessNameBestEffort -Handle $rawPreviousForegroundHandle
                $rawPreviousForegroundIsCodeWindow = ($rawPreviousForegroundProcessName -ieq 'Code')
            }
            # Capture more candidates so stale handles can be replaced later while
            # still honoring the requested activation count.
            $restoreCaptureCount = [Math]::Min(30, [Math]::Max($effectiveRestoreCount + 18, $effectiveRestoreCount))
            $restorePreviousWindowHandlesForRestore = @(Get-ForegroundWindowHandleStackBestEffort -MaxCount $restoreCaptureCount)
            $restorePreviousWindowCaptureTrace = @($script:LastForegroundWindowCaptureTrace)

            if ($rawPreviousForegroundHandle -gt 0) {
                if ($rawPreviousForegroundIsCodeWindow) {
                    $restorePreviousWindowCaptureTrace += [pscustomobject]@{
                        scan_index = 997
                        handle = [Int64]$rawPreviousForegroundHandle
                        process_id = 0
                        process_name = if ([string]::IsNullOrWhiteSpace($rawPreviousForegroundProcessName)) { '-' } else { $rawPreviousForegroundProcessName }
                        class_name = ''
                        title = 'raw-foreground'
                        visible = $true
                        enabled = $true
                        alt_tab_main = $false
                        ex_style_hex = '0x00000000'
                        owner_handle = 0
                        accepted = $false
                        reason = 'skip:raw-foreground-code-window'
                    }
                }
                elseif ($restorePreviousWindowHandlesForRestore.Count -le 0) {
                    $restorePreviousWindowHandlesForRestore = @([Int64]$rawPreviousForegroundHandle)
                    $restorePreviousWindowCaptureTrace += [pscustomobject]@{
                        scan_index = 999
                        handle = [Int64]$rawPreviousForegroundHandle
                        process_id = 0
                        process_name = if ([string]::IsNullOrWhiteSpace($rawPreviousForegroundProcessName)) { '-' } else { $rawPreviousForegroundProcessName }
                        class_name = ''
                        title = 'fallback-current-foreground'
                        visible = $true
                        enabled = $true
                        alt_tab_main = $false
                        ex_style_hex = '0x00000000'
                        owner_handle = 0
                        accepted = $true
                        reason = 'accept:fallback-foreground-handle'
                    }
                }
                elseif (-not @($restorePreviousWindowHandlesForRestore | Where-Object { [Int64]$_ -eq $rawPreviousForegroundHandle })) {
                    $restorePreviousWindowHandlesForRestore = @([Int64]$rawPreviousForegroundHandle) + @($restorePreviousWindowHandlesForRestore)
                    $restorePreviousWindowCaptureTrace += [pscustomobject]@{
                        scan_index = 998
                        handle = [Int64]$rawPreviousForegroundHandle
                        process_id = 0
                        process_name = if ([string]::IsNullOrWhiteSpace($rawPreviousForegroundProcessName)) { '-' } else { $rawPreviousForegroundProcessName }
                        class_name = ''
                        title = 'raw-foreground-prepend'
                        visible = $true
                        enabled = $true
                        alt_tab_main = $false
                        ex_style_hex = '0x00000000'
                        owner_handle = 0
                        accepted = $true
                        reason = 'accept:raw-foreground-prepend'
                    }
                }
            }

            $restorePreviousWindowActivationLimit = $effectiveRestoreCount
            $restorePreviousWindowHandles = @($restorePreviousWindowHandlesForRestore | Select-Object -First $effectiveRestoreCount)

            if ($rawPreviousForegroundHandle -gt 0 -and (-not $rawPreviousForegroundIsCodeWindow)) {
                $restorePreviousWindowHandle = $rawPreviousForegroundHandle
            }
            elseif ($restorePreviousWindowHandlesForRestore.Count -gt 0) {
                $restorePreviousWindowHandle = [Int64]$restorePreviousWindowHandlesForRestore[0]
            }
        }

        $result.restore_previous_window_count_captured = $restorePreviousWindowHandles.Count
        $result.restore_previous_window_handles = @($restorePreviousWindowHandles)
        $result.restore_previous_window_capture_trace = @($restorePreviousWindowCaptureTrace)
        $result.restore_previous_window_capture_summary = Convert-WindowCaptureTraceToSummary -TraceRows $restorePreviousWindowCaptureTrace

        $result.code_focus_policy.restore_previous_window_count_captured = $restorePreviousWindowHandles.Count
        $result.code_focus_policy.restore_previous_window_handles = @($restorePreviousWindowHandles)
        $result.code_focus_policy.restore_previous_window_capture_trace = @($restorePreviousWindowCaptureTrace)
        $result.code_focus_policy.restore_previous_window_capture_summary = Convert-WindowCaptureTraceToSummary -TraceRows $restorePreviousWindowCaptureTrace
    }

    if ($useResetZoomBeforeSend) {
        $result.reset_zoom_before_send = Invoke-SettingsZoomResetBestEffort -PostApplyDelayMs 400
    }
    else {
        $result.reset_zoom_before_send.reason = if ($NoResetZoomBeforeSend.IsPresent) {
            'disabled-by-switch'
        }
        elseif ($activeCodeWindowRequired) {
            'disabled-by-active-window-only-policy'
        }
        else {
            'disabled-by-no-focus-mode'
        }
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
    $allowLeftAnchoredCaretFlag = if ($allowLeftAnchoredChatCaret) { '1' } else { '0' }
    $allowInconclusiveSubmitOutcomeFlag = if ($allowInconclusiveSubmitOutcome) { '1' } else { '0' }
    $clearInputOnlyFlag = if ($clearInputOnly) { '1' } else { '0' }
    $ticketFingerprintToken = ([string](Convert-ToSingleLineText -Text $TicketId)).Trim()
    $ticketFingerprintTokenArg = if ([string]::IsNullOrWhiteSpace($ticketFingerprintToken)) { $emptyArgSentinel } else { $ticketFingerprintToken }
    $chatToggleShortcutArg = if ([string]::IsNullOrWhiteSpace($ChatToggleShortcut)) { $emptyArgSentinel } else { $ChatToggleShortcut }
    $restoreTracePathArg = if ([string]::IsNullOrWhiteSpace($restoreTracePath)) { $emptyArgSentinel } else { $restoreTracePath }
    $restorePreviousWindowFlag = if ($RestorePreviousForegroundWindow.IsPresent) { '1' } else { '0' }
    $restorePreviousWindowHandleText = [string][Int64]$restorePreviousWindowHandle
    $restorePreviousWindowStackText = '0'
    if ($restorePreviousWindowHandlesForRestore.Count -gt 1) {
        $restorePreviousWindowStackText = (($restorePreviousWindowHandlesForRestore | ForEach-Object { [string][Int64]$_ }) -join ',')
    }
    $restorePreviousWindowLimitText = [string][int]$restorePreviousWindowActivationLimit
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
        $chatToggleShortcutArg,
        $escPreflightFlag,
        $strictFocusRequiredFlag,
        $requireChatCaretFlag,
        $clearInputBeforePasteFlag,
        $restorePreviousWindowFlag,
        $restorePreviousWindowHandleText,
        $restorePreviousWindowStackText,
        $restorePreviousWindowLimitText,
        $allowLeftAnchoredCaretFlag,
        $allowInconclusiveSubmitOutcomeFlag,
        $restoreTracePathArg,
        $ticketFingerprintTokenArg,
        $clearInputOnlyFlag
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
            $maxAttemptCount = 2
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

    $restoreActivationSummary = ''
    $restoreActivationMetrics = [pscustomobject]@{
        attempted = 0
        succeeded = 0
        final_foreground_handle = 0
        restore_executed = $false
        restore_skipped_reason = ''
    }
    if ($EnableRestoreActivationTrace.IsPresent -and -not [string]::IsNullOrWhiteSpace($restoreTracePath)) {
        $restoreActivationTraceLines = @()
        if (Test-Path -LiteralPath $restoreTracePath) {
            try {
                $restoreActivationTraceLines = @(Get-Content -LiteralPath $restoreTracePath -Encoding utf8)
            }
            catch {
                $restoreActivationTraceLines = @()
            }
        }

        $restoreActivationSummary = Convert-RestoreActivationTraceToSummary -TraceLines $restoreActivationTraceLines -MaxLength 1600
        $restoreActivationMetrics = Get-RestoreActivationTraceMetricSet -TraceLines $restoreActivationTraceLines
    }

    $result.restore_previous_window_activation_trace = $restoreActivationSummary
    $result.restore_previous_window_activation_count_attempted = [int]$restoreActivationMetrics.attempted
    $result.restore_previous_window_activation_count_succeeded = [int]$restoreActivationMetrics.succeeded
    $result.restore_previous_window_activation_final_foreground_handle = [Int64]$restoreActivationMetrics.final_foreground_handle
    $result.restore_previous_window_activation_restore_executed = [bool]$restoreActivationMetrics.restore_executed
    $result.restore_previous_window_activation_skipped_reason = [string]$restoreActivationMetrics.restore_skipped_reason

    $result.code_focus_policy.restore_previous_window_activation_trace = $restoreActivationSummary
    $result.code_focus_policy.restore_previous_window_activation_count_attempted = [int]$restoreActivationMetrics.attempted
    $result.code_focus_policy.restore_previous_window_activation_count_succeeded = [int]$restoreActivationMetrics.succeeded
    $result.code_focus_policy.restore_previous_window_activation_final_foreground_handle = [Int64]$restoreActivationMetrics.final_foreground_handle
    $result.code_focus_policy.restore_previous_window_activation_restore_executed = [bool]$restoreActivationMetrics.restore_executed
    $result.code_focus_policy.restore_previous_window_activation_skipped_reason = [string]$restoreActivationMetrics.restore_skipped_reason

    [pscustomobject]$result
}
finally {
    if (-not $KeepTempFiles.IsPresent) {
        foreach ($path in @($scriptPath, $messagePath, $restoreTracePath)) {
            if ([string]::IsNullOrWhiteSpace($path)) {
                continue
            }
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }
}