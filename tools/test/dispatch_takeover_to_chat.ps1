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
    [switch]$UsePythonSender,
    [switch]$UseIpcSender,
    [AllowEmptyString()][string]$AhkExePath = '',
    [AllowEmptyString()][string]$PythonExePath = '',
    [ValidateRange(1000, 60000)][int]$AhkTimeoutMs = 12000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'DISPATCH-TAKEOVER-TO-CHAT'

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Get-Utf8BomEncoding {
    return [System.Text.UTF8Encoding]::new($true)
}

function Convert-ToFileText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [string]) {
        return [string]$Value
    }

    if (-not ($Value -is [string]) -and $Value -is [System.Collections.IEnumerable]) {
        $lines = @($Value | ForEach-Object { [string]$_ })
        return ($lines -join "`r`n")
    }

    return [string]$Value
}

function Write-Utf8BomFile {
    param(
        [string]$Path,
        [AllowNull()][object]$Value
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    if ([string]::IsNullOrWhiteSpace($parent)) {
        $parent = (Get-Location).Path
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $fullPath
    $text = Convert-ToFileText -Value $Value
    $commitToken = ([guid]::NewGuid().ToString('N'))
    $tempPath = Join-Path $parent ('.{0}.{1}.{2}.tmp' -f (Split-Path -Leaf $fullPath), $PID, $commitToken)
    $backupPath = Join-Path $parent ('.{0}.{1}.{2}.bak' -f (Split-Path -Leaf $fullPath), $PID, $commitToken)
    try {
        [System.IO.File]::WriteAllText($tempPath, $text, (Get-Utf8BomEncoding))
        if ([System.IO.File]::Exists($fullPath)) {
            [System.IO.File]::Replace($tempPath, $fullPath, $backupPath)
        }
        else {
            [System.IO.File]::Move($tempPath, $fullPath)
        }
    }
    finally {
        if ([System.IO.File]::Exists($tempPath)) {
            [System.IO.File]::Delete($tempPath)
        }
        if ([System.IO.File]::Exists($backupPath)) {
            [System.IO.File]::Delete($backupPath)
        }
    }
}

function Add-Utf8Line {
    param(
        [string]$Path,
        [string]$Line
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Utf8BomFile -Path $Path -Value $Line
        return
    }

    $appendEncoding = [System.Text.UTF8Encoding]::new($false)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try {
        $writer = New-Object System.IO.StreamWriter($stream, $appendEncoding)
        try {
            $writer.WriteLine($Line)
            $writer.Flush()
        }
        finally {
            $writer.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Test-TextContainsNonAscii {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    return ($Text -match '[^\u0000-\u007F]')
}

function Test-FileHasUtf8Bom {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    return ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
}

function Assert-Ps51Utf8BomCompatibility {
    param(
        [string]$ScriptPath,
        [string]$ScriptRole
    )

    if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) {
        return
    }

    try {
        $raw = Get-Content -LiteralPath $ScriptPath -Raw -Encoding utf8 -ErrorAction Stop
    }
    catch {
        return
    }

    if ((Test-TextContainsNonAscii -Text $raw) -and -not (Test-FileHasUtf8Bom -Path $ScriptPath)) {
        Write-Warning ("[CHAT-DISPATCH] ps51_utf8_bom_recommended role={0} path={1}" -f $ScriptRole, $ScriptPath)
    }
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

function Convert-ToWindowHandleList {
    param([AllowNull()][object]$Value)

    $handles = New-Object 'System.Collections.Generic.List[string]'

    function Add-CandidateWindowHandle {
        param([AllowNull()][object]$Candidate)

        if ($null -eq $Candidate) {
            return
        }

        if ($Candidate -is [System.Collections.IDictionary]) {
            $nestedValue = $null
            if ($Candidate.Contains('handle')) {
                $nestedValue = $Candidate['handle']
            }
            elseif ($Candidate.Contains('hwnd')) {
                $nestedValue = $Candidate['hwnd']
            }

            if ($null -ne $nestedValue) {
                Add-CandidateWindowHandle -Candidate $nestedValue
            }
            return
        }

        if (-not ($Candidate -is [string]) -and $Candidate -is [System.Collections.IEnumerable]) {
            foreach ($item in $Candidate) {
                Add-CandidateWindowHandle -Candidate $item
            }
            return
        }

        $raw = Convert-ToSingleLineText -Text ([string]$Candidate)
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return
        }

        foreach ($token in ($raw -split '[,;\s|]+')) {
            $normalized = ([string]$token).Trim()
            if ($normalized -match '^\d+$' -and $normalized -ne '0') {
                [void]$handles.Add($normalized)
            }
        }
    }

    Add-CandidateWindowHandle -Candidate $Value
    return @($handles | Select-Object -Unique)
}

function Convert-ToWindowHandleCsv {
    param([AllowNull()][object]$Value)

    $normalized = @(Convert-ToWindowHandleList -Value $Value)
    if ($normalized.Count -le 0) {
        return ''
    }

    return ($normalized -join ',')
}

function Get-ForegroundWindowSnapshot {
    $nativeType = 'DispatchUser32Native' -as [type]
    if ($null -eq $nativeType) {
        try {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class DispatchUser32Native {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
}
"@ -ErrorAction Stop | Out-Null
            $nativeType = 'DispatchUser32Native' -as [type]
        }
        catch {
            return $null
        }
    }

    if ($null -eq $nativeType) {
        return $null
    }

    try {
        $hWnd = [DispatchUser32Native]::GetForegroundWindow()
        if ($hWnd -eq [System.IntPtr]::Zero) {
            return $null
        }

        $ownerPid = [uint32]0
        [void][DispatchUser32Native]::GetWindowThreadProcessId($hWnd, [ref]$ownerPid)

        $handleValue = [Int64]$hWnd.ToInt64()
        if ($handleValue -le 0 -or $ownerPid -le 0) {
            return $null
        }

        return [pscustomobject]@{
            handle = $handleValue
            pid = [int]$ownerPid
        }
    }
    catch {
        return $null
    }
}

function Test-IsCodeGuiProcessId {
    param([int]$ProcessId)

    if ($ProcessId -le 0) {
        return $false
    }

    try {
        $processInfo = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $ProcessId) -ErrorAction SilentlyContinue
        if ($null -eq $processInfo) {
            return $false
        }

        $name = (Convert-ToSingleLineText -Text ([string]$processInfo.Name)).ToLowerInvariant()
        if ($name -eq 'code.exe' -or $name -eq 'code-insiders.exe') {
            return $true
        }

        $exePath = Convert-ToSingleLineText -Text ([string]$processInfo.ExecutablePath)
        if (-not [string]::IsNullOrWhiteSpace($exePath) -and (Test-IsCodeGuiExecutablePath -Path $exePath)) {
            return $true
        }
    }
    catch {
        return $false
    }

    return $false
}

function Get-ForegroundCodeWindowHint {
    $snapshot = Get-ForegroundWindowSnapshot
    if ($null -eq $snapshot) {
        return $null
    }

    $windowPid = [int](Get-ObjectMemberValue -Container $snapshot -MemberName 'pid')
    if (-not (Test-IsCodeGuiProcessId -ProcessId $windowPid)) {
        return $null
    }

    $windowHandle = [Int64](Get-ObjectMemberValue -Container $snapshot -MemberName 'handle')
    if ($windowHandle -le 0) {
        return $null
    }

    return [pscustomobject]@{
        handle = $windowHandle
        pid = $windowPid
    }
}

function Get-ObjectMemberValue {
    param(
        [AllowNull()][object]$Container,
        [string]$MemberName
    )

    if ($null -eq $Container -or [string]::IsNullOrWhiteSpace($MemberName)) {
        return $null
    }

    if ($Container -is [System.Collections.IDictionary]) {
        if ($Container.Contains($MemberName)) {
            return $Container[$MemberName]
        }

        return $null
    }

    $prop = $Container.PSObject.Properties[$MemberName]
    if ($null -ne $prop) {
        return $prop.Value
    }

    return $null
}

function ConvertFrom-JsonObjectText {
    param([AllowEmptyString()][string]$Text)

    $raw = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }

    try {
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        $start = $raw.IndexOf('{')
        $end = $raw.LastIndexOf('}')
        if ($start -lt 0 -or $end -le $start) {
            return $null
        }

        $candidate = $raw.Substring($start, ($end - $start + 1))
        try {
            return ($candidate | ConvertFrom-Json -ErrorAction Stop)
        }
        catch {
            return $null
        }
    }
}

function Invoke-RouteGuardLiveClassification {
    param([AllowEmptyString()][string]$RouteGuardCommand)

    $result = [ordered]@{
        success = $false
        classification = ''
        reason = ''
    }

    $commandText = Convert-ToSingleLineText -Text $RouteGuardCommand
    if ([string]::IsNullOrWhiteSpace($commandText)) {
        $result.reason = 'command-missing'
        return [pscustomobject]$result
    }

    $rawOutput = @()
    $invokeExitCode = 0
    try {
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $rawOutput = @(Invoke-Expression $commandText 2>&1)
            $invokeExitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
    }
    catch {
        $result.reason = ('invoke-failed:{0}' -f (Convert-ToSingleLineText -Text $_.Exception.Message))
        return [pscustomobject]$result
    }

    $outputText = (@($rawOutput) | ForEach-Object { [string]$_ }) -join "`n"
    $payload = ConvertFrom-JsonObjectText -Text $outputText
    if ($null -eq $payload) {
        if ($invokeExitCode -ne 0) {
            $result.reason = ('non-json-exit-{0}' -f $invokeExitCode)
        }
        else {
            $result.reason = 'non-json-output'
        }
        return [pscustomobject]$result
    }

    $liveClassification = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container (Get-ObjectMemberValue -Container $payload -MemberName 'route') -MemberName 'classification'))
    if ([string]::IsNullOrWhiteSpace($liveClassification)) {
        $result.reason = 'classification-missing'
        return [pscustomobject]$result
    }

    $result.success = $true
    $result.classification = $liveClassification.ToLowerInvariant()
    $result.reason = 'ok'
    return [pscustomobject]$result
}

function Get-CompactStatusToken {
    param([AllowEmptyString()][string]$Value)

    $token = (Convert-ToSingleLineText -Text $Value).ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($token)) {
        return 'UNKNOWN'
    }

    return $token
}

function Get-StatusValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'NOT_RUN'
    }

    return $Value.Trim().ToUpperInvariant()
}

function Resolve-BusinessResumePlan {
    param(
        [string]$StartFileRel,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$PreferredStage = '',
        [bool]$DisableResume = $false
    )

    $normalizedSession = Get-StatusValue -Value $SessionStatus
    $normalizedA = Get-StatusValue -Value $AStatus
    $normalizedB = Get-StatusValue -Value $BStatus
    $stageHint = (Convert-ToSingleLineText -Text $PreferredStage).ToUpperInvariant()

    if ($DisableResume) {
        return [pscustomobject]@{
            command = ''
            stage = 'none'
            reason = 'resume-disabled'
            session_status = $normalizedSession
            a_status = $normalizedA
            b_status = $normalizedB
        }
    }

    $targetStage = 'A'
    $reason = 'default-a-resume'
    if ($stageHint -eq 'B') {
        $targetStage = 'B'
        $reason = 'ticket-hint-b'
    }
    elseif ($stageHint -eq 'A') {
        $targetStage = 'A'
        $reason = 'ticket-hint-a'
    }
    elseif ($normalizedA -eq 'PASS' -and $normalizedB -in @('FAIL', 'BLOCKED', 'NOT_RUN')) {
        $targetStage = 'B'
        $reason = 'a-pass-b-pending'
    }
    elseif ($normalizedA -in @('FAIL', 'BLOCKED', 'NOT_RUN')) {
        $targetStage = 'A'
        $reason = 'a-needs-recovery'
    }

    $command = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage {0} -StartFile "{1}" -StartMonitors' -f $targetStage, $StartFileRel

    return [pscustomobject]@{
        command = $command
        stage = $targetStage
        reason = $reason
        session_status = $normalizedSession
        a_status = $normalizedA
        b_status = $normalizedB
    }
}

function Format-DispatchMessage {
    param(
        [AllowEmptyString()][string]$Message,
        [bool]$AppendAdvisory = $true,
        [bool]$UseChinese = $false,
        [ValidateRange(20, 1000)][int]$MaxLines = 120,
        [ValidateRange(200, 20000)][int]$MaxChars = 4000
    )

    $result = [ordered]@{
        message = ''
        sanitized = $false
        removed_lines = 0
        inline_replacements = 0
        deduped_lines = 0
        transcript_blocks_removed = 0
        transcript_lines_removed = 0
        truncated = $false
        rule_summary = ''
    }

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return [pscustomobject]$result
    }

    $blockedLinePattern = '(?i)^\s*>?\s*workbench\.action\.chat\.[A-Za-z0-9._-]+.*$'
    $blockedGeneralPattern = '(?i)^\s*>\s*workbench\.action\.[A-Za-z0-9._-]+.*$'
    $inlinePattern = '(?i)>\s*workbench\.action\.chat\.[A-Za-z0-9._-]+'
    $terminalMetaHeaderPattern = '(?i)^\s*(Terminal|Last Command|Cwd|Exit Code)\s*:\s*.*$'
    $terminalToolNarrationPattern = '(?i)^\s*(Note:\s*The tool simplified the command to|This is the output of running that command instead:)\b.*$'
    $terminalPromptPattern = '(?i)^\s*(PS\s+[A-Za-z]:\\.*?>|[A-Za-z]:\\.*?>)\s*.*$'
    $terminalCommandEchoPattern = '(?i)^\s*(powershell(\.exe)?\b|pwsh\b|git\b|cmd(\.exe)?\b|bash\b|&\s*\{\s*try\s*\{).*$'
    $separatorPattern = '^\s*[-=]{5,}\s*$'
    $businessAnchorPattern = '(?i)^\s*(ticket_id|event|severity|summary|recommended_command)\s*[:=]'

    $ruleHits = [ordered]@{
        workbench_line = 0
        workbench_general = 0
        terminal_meta_header = 0
        terminal_tool_narration = 0
        transcript_prompt = 0
        transcript_command_echo = 0
        transcript_body = 0
        separator = 0
        inline_replacements = 0
        repeat_collapse = 0
        length_cap_lines = 0
        length_cap_chars = 0
    }

    $filteredLines = New-Object 'System.Collections.Generic.List[string]'
    $inTranscript = $false
    foreach ($line in @($Message -split "`r?`n")) {
        $currentLine = [string]$line
        $trimmedLine = $currentLine.Trim()

        if ($currentLine -match $blockedLinePattern) {
            $ruleHits.workbench_line = [int]$ruleHits.workbench_line + 1
            $result.removed_lines = [int]$result.removed_lines + 1
            continue
        }

        if ($currentLine -match $blockedGeneralPattern) {
            $ruleHits.workbench_general = [int]$ruleHits.workbench_general + 1
            $result.removed_lines = [int]$result.removed_lines + 1
            continue
        }

        if ($currentLine -match $terminalMetaHeaderPattern) {
            $ruleHits.terminal_meta_header = [int]$ruleHits.terminal_meta_header + 1
            $result.removed_lines = [int]$result.removed_lines + 1
            $result.transcript_lines_removed = [int]$result.transcript_lines_removed + 1
            if (-not $inTranscript) {
                $result.transcript_blocks_removed = [int]$result.transcript_blocks_removed + 1
            }

            $inTranscript = $true
            continue
        }

        if ($currentLine -match $terminalToolNarrationPattern) {
            $ruleHits.terminal_tool_narration = [int]$ruleHits.terminal_tool_narration + 1
            $result.removed_lines = [int]$result.removed_lines + 1
            $result.transcript_lines_removed = [int]$result.transcript_lines_removed + 1
            if (-not $inTranscript) {
                $result.transcript_blocks_removed = [int]$result.transcript_blocks_removed + 1
            }

            $inTranscript = $true
            continue
        }

        if ($inTranscript) {
            if ([string]::IsNullOrWhiteSpace($trimmedLine)) {
                $result.removed_lines = [int]$result.removed_lines + 1
                $result.transcript_lines_removed = [int]$result.transcript_lines_removed + 1
                $inTranscript = $false
                continue
            }

            if ($currentLine -match $businessAnchorPattern) {
                $inTranscript = $false
            }
            else {
                if ($currentLine -match $terminalPromptPattern) {
                    $ruleHits.transcript_prompt = [int]$ruleHits.transcript_prompt + 1
                }
                elseif ($currentLine -match $terminalCommandEchoPattern) {
                    $ruleHits.transcript_command_echo = [int]$ruleHits.transcript_command_echo + 1
                }
                else {
                    $ruleHits.transcript_body = [int]$ruleHits.transcript_body + 1
                }

                $result.removed_lines = [int]$result.removed_lines + 1
                $result.transcript_lines_removed = [int]$result.transcript_lines_removed + 1
                continue
            }
        }

        if ($currentLine -match $separatorPattern) {
            $ruleHits.separator = [int]$ruleHits.separator + 1
            $result.removed_lines = [int]$result.removed_lines + 1
            continue
        }

        $updatedLine = [regex]::Replace($currentLine, $inlinePattern, '[filtered-chat-command]')
        if ($updatedLine -ne $currentLine) {
            $result.inline_replacements = [int]$result.inline_replacements + 1
            $ruleHits.inline_replacements = [int]$ruleHits.inline_replacements + 1
        }

        [void]$filteredLines.Add($updatedLine)
    }

    $dedupedLines = New-Object 'System.Collections.Generic.List[string]'
    $hasPrevious = $false
    $previousLine = ''
    $runCount = 0

    foreach ($candidate in @($filteredLines.ToArray())) {
        if (-not $hasPrevious) {
            $previousLine = [string]$candidate
            $runCount = 1
            $hasPrevious = $true
            continue
        }

        if ([string]$candidate -eq $previousLine) {
            $runCount = [int]$runCount + 1
            continue
        }

        if ($runCount -ge 3) {
            [void]$dedupedLines.Add($previousLine)
            $collapsed = [int]$runCount - 1
            $result.deduped_lines = [int]$result.deduped_lines + $collapsed
            $ruleHits.repeat_collapse = [int]$ruleHits.repeat_collapse + $collapsed
        }
        else {
            for ($index = 0; $index -lt $runCount; $index++) {
                [void]$dedupedLines.Add($previousLine)
            }
        }

        $previousLine = [string]$candidate
        $runCount = 1
    }

    if ($hasPrevious) {
        if ($runCount -ge 3) {
            [void]$dedupedLines.Add($previousLine)
            $collapsed = [int]$runCount - 1
            $result.deduped_lines = [int]$result.deduped_lines + $collapsed
            $ruleHits.repeat_collapse = [int]$ruleHits.repeat_collapse + $collapsed
        }
        else {
            for ($index = 0; $index -lt $runCount; $index++) {
                [void]$dedupedLines.Add($previousLine)
            }
        }
    }

    $lineArray = @($dedupedLines.ToArray())
    if ($lineArray.Length -gt $MaxLines) {
        $headCount = [Math]::Max(1, [int][Math]::Floor([double]$MaxLines * 0.65))
        $tailCount = [Math]::Max(1, $MaxLines - $headCount - 1)
        $headPart = @($lineArray | Select-Object -First $headCount)
        $tailPart = @($lineArray | Select-Object -Last $tailCount)
        $omittedLineCount = [Math]::Max(0, $lineArray.Length - $headPart.Length - $tailPart.Length)
        $lineArray = @($headPart + ("[filtered-transcript-truncated-lines omitted={0}]" -f $omittedLineCount) + $tailPart)
        $ruleHits.length_cap_lines = [int]$ruleHits.length_cap_lines + 1
        $result.removed_lines = [int]$result.removed_lines + [int]$omittedLineCount
        $result.truncated = $true
    }

    $sanitizedMessage = (($lineArray -join "`n").Trim())
    if ($sanitizedMessage.Length -gt $MaxChars) {
        $marker = '[filtered-transcript-truncated-chars]'
        $contentBudget = [Math]::Max(64, $MaxChars - $marker.Length - 20)
        $headChars = [Math]::Max(32, [int][Math]::Floor([double]$contentBudget * 0.65))
        $tailChars = [Math]::Max(16, $contentBudget - $headChars)
        $prefixLength = [Math]::Min($headChars, $sanitizedMessage.Length)
        $suffixStart = [Math]::Max(0, $sanitizedMessage.Length - $tailChars)
        $prefix = $sanitizedMessage.Substring(0, $prefixLength)
        $suffix = $sanitizedMessage.Substring($suffixStart)
        $omittedCharCount = [Math]::Max(0, $sanitizedMessage.Length - $prefix.Length - $suffix.Length)
        $sanitizedMessage = ($prefix + "`n" + ("{0} omitted={1}" -f $marker, $omittedCharCount) + "`n" + $suffix).Trim()
        $ruleHits.length_cap_chars = [int]$ruleHits.length_cap_chars + 1
        $result.truncated = $true
    }

    $result.message = $sanitizedMessage
    $result.sanitized = (($result.removed_lines -gt 0) -or ($result.inline_replacements -gt 0) -or ($result.deduped_lines -gt 0) -or [bool]$result.truncated)

    $ruleSummaryParts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in $ruleHits.GetEnumerator()) {
        if ([int]$entry.Value -gt 0) {
            [void]$ruleSummaryParts.Add(("{0}={1}" -f [string]$entry.Key, [int]$entry.Value))
        }
    }
    $result.rule_summary = ($ruleSummaryParts.ToArray() -join ';')

    if ([bool]$result.sanitized -and $AppendAdvisory) {
        $advisory = if ($UseChinese) {
            '注意：检测到命令面板或终端日志噪声，已自动过滤/截断。不得尝试修复或重试；失败即关闭，按当前结果如实上报。'
        }
        else {
            'Note: command palette or terminal transcript noise was detected and auto-filtered/truncated. Do not attempt recovery or retry; fail-closed and report the outcome as-is.'
        }
        if ([string]::IsNullOrWhiteSpace($result.message)) {
            $result.message = $advisory
        }
        else {
            $result.message = ($result.message.TrimEnd() + "`n" + $advisory)
        }
    }

    return [pscustomobject]$result
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

function Get-LatestAnchorValueFromNote {
    param(
        [AllowEmptyString()][string]$Notes,
        [string]$Key
    )

    if ([string]::IsNullOrWhiteSpace($Notes) -or [string]::IsNullOrWhiteSpace($Key)) {
        return ''
    }

    $parts = @($Notes -split ';')
    $partCount = @($parts).Length
    for ($index = $partCount - 1; $index -ge 0; $index--) {
        $segment = [string]$parts[$index]
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        if ($segment -match ('^\s*' + [regex]::Escape($Key) + '=(.+)$')) {
            return $Matches[1].Trim()
        }
    }

    return ''
}

function Get-DispatchAnchorMap {
    param([System.Collections.IDictionary]$Settings)

    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) {
        [string]$Settings.SESSION_FINAL_NOTES
    }
    else {
        ''
    }

    $anchors = [ordered]@{}
    foreach ($key in @('run_dir', 'guard_log', 'guard_state', 'live_status')) {
        $anchors[$key] = Get-LatestAnchorValueFromNote -Notes $notes -Key $key
    }

    return $anchors
}

function Get-LatestArtifactFilePath {
    param(
        [string]$RootRelative,
        [string]$FileName
    )

    if ([string]::IsNullOrWhiteSpace($RootRelative) -or [string]::IsNullOrWhiteSpace($FileName)) {
        return ''
    }

    $rootPath = Join-Path $script:RepoRoot $RootRelative
    if (-not (Test-Path -LiteralPath $rootPath)) {
        return ''
    }

    $latestDir = $null
    try {
        $latestDir = Get-ChildItem -LiteralPath $rootPath -Directory -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
    }
    catch {
        return ''
    }

    if ($null -eq $latestDir) {
        return ''
    }

    $candidate = Join-Path $latestDir.FullName $FileName
    if (Test-Path -LiteralPath $candidate) {
        return $candidate
    }

    return ''
}

function Get-LineTimeToken {
    param([string]$Line)

    if ($Line -match 'timestamp=([0-9]{4}-[0-9]{2}-[0-9]{2}\s+([0-9]{2}:[0-9]{2}:[0-9]{2}))') {
        return $Matches[2]
    }

    return '--:--:--'
}

function Get-PathLeafToken {
    param([AllowEmptyString()][string]$Token)

    if ([string]::IsNullOrWhiteSpace($Token)) {
        return ''
    }

    $normalized = $Token.Trim().TrimEnd(',', ';').Replace('/', '\\')
    return [System.IO.Path]::GetFileName($normalized)
}

function Get-LatestGuardHeartbeatRunDir {
    param([AllowEmptyString()][string]$LogPath)

    if ([string]::IsNullOrWhiteSpace($LogPath) -or -not (Test-Path -LiteralPath $LogPath)) {
        return ''
    }

    try {
        $lines = @(Get-Content -LiteralPath $LogPath -Tail 300 -Encoding utf8 -ErrorAction Stop)
        for ($index = $lines.Length - 1; $index -ge 0; $index--) {
            $line = [string]$lines[$index]
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            if ($line -match 'heartbeat\s+session=([A-Z]+)\s+a=([A-Z]+)\s+b=([A-Z]+)\s+running=([A-Za-z]+)\s+run_dir=([^ ]+)') {
                return Convert-ToSingleLineText -Text ([string]$Matches[5])
            }
        }
    }
    catch {
        return ''
    }

    return ''
}

function Get-MainProcessRoundDigest {
    param(
        [AllowEmptyString()][string]$RunDirPath,
        [AllowEmptyString()][string]$LiveStatusPath
    )

    $stageToken = ''
    $roundToken = ''
    $startRoundToken = ''
    $artifactPathToken = ''

    if (-not [string]::IsNullOrWhiteSpace($LiveStatusPath) -and (Test-Path -LiteralPath $LiveStatusPath)) {
        try {
            $livePayload = Get-Content -LiteralPath $LiveStatusPath -Raw -Encoding utf8 | ConvertFrom-Json
            if ($null -ne $livePayload) {
                $stageToken = (Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $livePayload -MemberName 'current_stage'))).ToUpperInvariant()

                foreach ($roundKey in @('current_round', 'current_stage_round', 'current_d_round', 'current_work_round', 'round')) {
                    $candidateRound = (Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $livePayload -MemberName $roundKey))).ToUpperInvariant()
                    if (-not [string]::IsNullOrWhiteSpace($candidateRound)) {
                        $roundToken = $candidateRound
                        break
                    }
                }

                $startRoundToken = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $livePayload -MemberName 'current_stage_start_round'))
                $artifactPathToken = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $livePayload -MemberName 'artifact_latest_path'))
                if ([string]::IsNullOrWhiteSpace($artifactPathToken)) {
                    $artifactPathToken = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $livePayload -MemberName 'latest_path'))
                }

                if ([string]::IsNullOrWhiteSpace($roundToken) -and -not [string]::IsNullOrWhiteSpace($artifactPathToken)) {
                    if ($artifactPathToken -match '(^|[\\/])(V[0-9]{1,3})(?=($|[\\/_-]))') {
                        $roundToken = $Matches[2].ToUpperInvariant()
                    }
                    elseif ($artifactPathToken -match '(^|[\\/])(D[0-9]{1,3})(?=($|[\\/_-]))') {
                        $roundToken = $Matches[2].ToUpperInvariant()
                    }
                    elseif ($artifactPathToken -match '(^|[\\/])round([0-9]{1,3})(?=($|[\\/_\.-]))') {
                        $roundNo = [int]$Matches[2]
                        if ($roundNo -gt 0) {
                            if ($stageToken -eq 'A') {
                                $roundToken = ('V{0}' -f $roundNo)
                            }
                            else {
                                $roundToken = ('D{0}' -f $roundNo)
                            }
                        }
                    }
                }
            }
        }
        catch {
            $null = $_
        }
    }

    if ([string]::IsNullOrWhiteSpace($roundToken) -and -not [string]::IsNullOrWhiteSpace($RunDirPath) -and (Test-Path -LiteralPath $RunDirPath) -and $stageToken -ne 'A') {
        try {
            $roundFile = Get-ChildItem -LiteralPath $RunDirPath -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^D([0-9]{1,2})(?:_code_step)?\.log$' } |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1

            if ($null -ne $roundFile -and $roundFile.Name -match '^D([0-9]{1,2})') {
                $roundToken = ('D{0}' -f $Matches[1])
            }
        }
        catch {
            $null = $_
        }
    }

    if ([string]::IsNullOrWhiteSpace($roundToken) -and -not [string]::IsNullOrWhiteSpace($startRoundToken)) {
        $parsedStartRound = 0
        if ([int]::TryParse($startRoundToken, [ref]$parsedStartRound) -and $parsedStartRound -gt 0) {
            if ($stageToken -eq 'A') {
                $roundToken = ('V{0}' -f $parsedStartRound)
            }
            else {
                $roundToken = ('D{0}' -f $parsedStartRound)
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($stageToken) -and -not [string]::IsNullOrWhiteSpace($roundToken)) {
        return ('{0}/{1}' -f $stageToken, $roundToken)
    }

    if (-not [string]::IsNullOrWhiteSpace($roundToken)) {
        return $roundToken
    }

    if (-not [string]::IsNullOrWhiteSpace($stageToken)) {
        return ('{0}/unknown' -f $stageToken)
    }

    return 'unknown'
}

function Get-LatestHeartbeatDigest {
    param(
        [string]$Role,
        [AllowEmptyString()][string]$LogPath
    )

    $roleToken = (Convert-ToSingleLineText -Text $Role).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($roleToken)) {
        $roleToken = 'unknown'
    }

    if ([string]::IsNullOrWhiteSpace($LogPath) -or -not (Test-Path -LiteralPath $LogPath)) {
        return ('{0}=missing' -f $roleToken)
    }

    try {
        $lines = @(Get-Content -LiteralPath $LogPath -Tail 300 -Encoding utf8 -ErrorAction Stop)
        for ($index = $lines.Length - 1; $index -ge 0; $index--) {
            $line = [string]$lines[$index]
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $time = Get-LineTimeToken -Line $line
            if ($roleToken -eq 'guard' -and $line -match 'heartbeat\s+session=([A-Z]+)\s+a=([A-Z]+)\s+b=([A-Z]+)\s+running=([A-Za-z]+)\s+run_dir=([^ ]+)') {
                $runId = Get-PathLeafToken -Token $Matches[5]
                return ('guard={0} session={1} a={2} b={3} running={4} run={5}' -f $time, $Matches[1], $Matches[2], $Matches[3], $Matches[4], $runId)
            }
        }
    }
    catch {
        return ('{0}=read-error' -f $roleToken)
    }

    return ('{0}=unavailable' -f $roleToken)
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

function Resolve-TicketEventFromQueue {
    param(
        [AllowEmptyString()][string]$TicketId,
        [AllowEmptyString()][string]$QueuePath
    )

    $normalizedTicketId = Convert-ToSingleLineText -Text $TicketId
    if ([string]::IsNullOrWhiteSpace($normalizedTicketId)) {
        return ''
    }

    $normalizedQueuePath = Convert-ToSingleLineText -Text $QueuePath
    if ([string]::IsNullOrWhiteSpace($normalizedQueuePath) -or -not (Test-Path -LiteralPath $normalizedQueuePath)) {
        return ''
    }

    try {
        $lines = @(Get-Content -LiteralPath $normalizedQueuePath -Encoding utf8 -ErrorAction Stop)
        for ($idx = $lines.Count - 1; $idx -ge 0; $idx--) {
            $line = ([string]$lines[$idx]).Trim()
            if ([string]::IsNullOrWhiteSpace($line) -or -not $line.StartsWith('{')) {
                continue
            }

            try {
                $obj = $line | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                continue
            }

            if ($null -eq $obj) {
                continue
            }

            $rowTicketId = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $obj -MemberName 'ticket_id'))
            if ([string]::IsNullOrWhiteSpace($rowTicketId)) {
                continue
            }

            if (-not $rowTicketId.Equals($normalizedTicketId, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            $rowEvent = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $obj -MemberName 'event'))
            if (-not [string]::IsNullOrWhiteSpace($rowEvent)) {
                return $rowEvent
            }
        }
    }
    catch {
        return ''
    }

    return ''
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
                $null = $_
            }

            return ''
        }

        [void]$candidates.Add($resolvedConfigured)
    }

    $envPath = Convert-ToSingleLineText -Text $env:AUTOHOTKEY_EXE
    if (-not [string]::IsNullOrWhiteSpace($envPath)) {
        [void]$candidates.Add((Resolve-RepoPathAllowMissing -Path $envPath))
    }

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

function Resolve-PythonExecutablePath {
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
                $null = $_
            }

            return ''
        }

        [void]$candidates.Add($resolvedConfigured)
    }

    $envPath = Convert-ToSingleLineText -Text $env:AI_CHAT_DISPATCH_PYTHON_EXE
    if ([string]::IsNullOrWhiteSpace($envPath)) {
        $envPath = Convert-ToSingleLineText -Text $env:PYTHON_EXE
    }
    if (-not [string]::IsNullOrWhiteSpace($envPath)) {
        [void]$candidates.Add((Resolve-RepoPathAllowMissing -Path $envPath))
    }

    [void]$candidates.Add('C:\Program Files\Python313\python.exe')

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

    foreach ($name in @('python.exe', 'python', 'py.exe', 'py')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
            return [string]$command.Source
        }
    }

    return ''
}

function Select-JsonResultObject {
    param([object]$RawOutput)

    if ($null -eq $RawOutput) {
        return $null
    }

    $parsed = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in @($RawOutput)) {
        if ($null -eq $item) {
            continue
        }

        if ($item -isnot [string]) {
            if (@($item.PSObject.Properties.Name).Count -gt 0) {
                [void]$parsed.Add($item)
            }
            continue
        }

        $line = ([string]$item).Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or -not $line.StartsWith('{') -or -not $line.EndsWith('}')) {
            continue
        }

        try {
            $obj = $line | ConvertFrom-Json -ErrorAction Stop
            if ($null -ne $obj) {
                [void]$parsed.Add($obj)
            }
        }
        catch {
            continue
        }
    }

    if ($parsed.Count -lt 1) {
        return $null
    }

    return Select-AhkSendResultObject -RawResult $parsed.ToArray()
}

function Select-AhkSendResultObject {
    param([object]$RawResult)

    if ($null -eq $RawResult) {
        return $null
    }

    $items = @($RawResult)
    $candidates = New-Object 'System.Collections.Generic.List[object]'

    foreach ($item in $items) {
        if ($null -eq $item -or $item -is [string]) {
            continue
        }

        $props = @($item.PSObject.Properties.Name)
        if ($props.Count -eq 0) {
            continue
        }

        $schema = ''
        if ($item.PSObject.Properties['schema']) {
            $schema = Convert-ToSingleLineText -Text ([string]$item.schema)
        }

        if ($schema -eq 'AHK_CHAT_SEND_RESULT_V1' -or $item.PSObject.Properties['ahk_exit_code'] -or $item.PSObject.Properties['sent']) {
            [void]$candidates.Add($item)
        }
    }

    if ($candidates.Count -gt 0) {
        return $candidates[$candidates.Count - 1]
    }

    for ($idx = $items.Count - 1; $idx -ge 0; $idx--) {
        $item = $items[$idx]
        if ($null -eq $item -or $item -is [string]) {
            continue
        }

        if (@($item.PSObject.Properties.Name).Count -gt 0) {
            return $item
        }
    }

    return $null
}

function Invoke-AhkChatDispatch {
    param(
        [string]$AhkExecutable,
        [string]$Message,
        [AllowEmptyString()][string]$TicketId = '',
        [int]$TimeoutMs = 12000,
        [System.Collections.IDictionary]$Settings = $null,
        [AllowEmptyString()][string]$EventName = '',
        [bool]$HeartbeatTimeoutRequireCodeFocus = $true,
        [bool]$StatusReportAllowInconclusiveSubmit = $true,
        [bool]$RestorePreviousForegroundWindow = $true,
        [int]$RestorePreviousForegroundWindowCount = 12,
        [AllowEmptyString()][string]$PreferredRestoreWindowHandles = '',
        [bool]$ActiveWindowOnly = $false,
        [bool]$StatusReportForcePaletteFocus = $false,
        [bool]$StatusReportClickRecoveryOnly = $false,
        [bool]$ForceFocusRecovery = $false,
        [bool]$ClearInputOnly = $false
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
            restore_previous_window_count_requested = 0
            restore_previous_window_count_captured = 0
            restore_previous_window_handles = ''
            restore_previous_window_capture_summary = ''
            restore_previous_window_activation_trace = ''
            restore_previous_window_activation_count_attempted = 0
            restore_previous_window_activation_count_succeeded = 0
            restore_previous_window_activation_final_foreground_handle = 0
            restore_previous_window_activation_restore_executed = $false
            restore_previous_window_activation_skipped_reason = ''
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
            restore_previous_window_count_requested = 0
            restore_previous_window_count_captured = 0
            restore_previous_window_handles = ''
            restore_previous_window_capture_summary = ''
            restore_previous_window_activation_trace = ''
            restore_previous_window_activation_count_attempted = 0
            restore_previous_window_activation_count_succeeded = 0
            restore_previous_window_activation_final_foreground_handle = 0
            restore_previous_window_activation_restore_executed = $false
            restore_previous_window_activation_skipped_reason = ''
        }
    }

    $invokeParams = @{
        Message = $Message
        AhkExePath = $AhkExecutable
        TimeoutMs = ([Math]::Max(1000, $TimeoutMs))
    }

    if ($ClearInputOnly) {
        $invokeParams.ClearInputOnly = $true
        $invokeParams.NoAutoReconnectResend = $true
        $invokeParams.NoInvokeCodeChatFocus = $true
        $invokeParams.NoPaletteFocusCommand = $true
        $invokeParams.UseClickFocusFallback = $true
        $invokeParams.NoChatToggleShortcut = $true
        $invokeParams.NoResetZoomBeforeSend = $true
        $invokeParams.PreSendDelayMs = 0
    }

    $ticketToken = Convert-ToSingleLineText -Text $TicketId
    if (-not [string]::IsNullOrWhiteSpace($ticketToken)) {
        $invokeParams.TicketId = $ticketToken
    }

    if ($RestorePreviousForegroundWindow) {
        $invokeParams.RestorePreviousForegroundWindow = $true
        $invokeParams.RestorePreviousWindowCount = [Math]::Min(30, [Math]::Max(1, $RestorePreviousForegroundWindowCount))

        if (-not [string]::IsNullOrWhiteSpace($PreferredRestoreWindowHandles)) {
            $normalizedPreferredHandles = @(Convert-ToWindowHandleList -Value $PreferredRestoreWindowHandles)
            if ($normalizedPreferredHandles.Count -gt 0) {
                $invokeParams.RestorePreviousWindowHandlesCsv = ($normalizedPreferredHandles -join ',')
            }
        }
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
    if (-not $ClearInputOnly) {
        if ($eventNormalized -eq 'chat-session-heartbeat-timeout') {
            $invokeParams.NoPaletteFocusCommand = $true
        }

        if ($eventNormalized -eq 'running-status-report') {
            # Keep caret guard enabled across retries to fail-close on wrong focus.
            $invokeParams.RequireChatCaretInInput = $true
            # Empty chat inputs often place caret at far-left; allow that safe shape.
            $invokeParams.AllowLeftAnchoredChatCaret = $true
            # When pre-send focus checks pass but post-submit focus cannot be re-probed,
            # avoid false negatives for periodic status tickets.
            if ($StatusReportAllowInconclusiveSubmit) {
                $invokeParams.AllowInconclusiveSubmitOutcome = $true
            }

            # Patrol/status messages should never fall back to whatever currently has focus.
            if ($StatusReportClickRecoveryOnly) {
                $invokeParams.NoPaletteFocusCommand = $true
                $invokeParams.UseClickFocusFallback = $true
                $invokeParams.NoInvokeCodeChatFocus = $true
                if ($invokeParams.ContainsKey('EnablePaletteFocusCommand')) {
                    $invokeParams.Remove('EnablePaletteFocusCommand')
                }
                if ($invokeParams.ContainsKey('ForceInvokeCodeChatFocus')) {
                    $invokeParams.Remove('ForceInvokeCodeChatFocus')
                }
                if ($invokeParams.ContainsKey('RequireCodeChatFocusSuccess')) {
                    $invokeParams.Remove('RequireCodeChatFocusSuccess')
                }
            }
            elseif ($StatusReportForcePaletteFocus) {
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
            elseif ((-not $StatusReportForcePaletteFocus) -and (-not $StatusReportClickRecoveryOnly)) {
                $invokeParams.ForceInvokeCodeChatFocus = $true
                # Best-effort code focus for running-status; do not hard-fail on
                # unavailable code-focus command because caret/focus guards and
                # follow-up recovery retries provide safer reliability.
                if ($invokeParams.ContainsKey('RequireCodeChatFocusSuccess')) {
                    $invokeParams.Remove('RequireCodeChatFocusSuccess')
                }
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
            # For running-status-report, avoid palette command injection and use click-only recovery.
            if ($eventNormalized -eq 'running-status-report') {
                $invokeParams.NoPaletteFocusCommand = $true
                $invokeParams.UseClickFocusFallback = $true
                $invokeParams.NoInvokeCodeChatFocus = $true
                if ($invokeParams.ContainsKey('EnablePaletteFocusCommand')) {
                    $invokeParams.Remove('EnablePaletteFocusCommand')
                }
                if ($invokeParams.ContainsKey('ForceInvokeCodeChatFocus')) {
                    $invokeParams.Remove('ForceInvokeCodeChatFocus')
                }
                if ($invokeParams.ContainsKey('RequireCodeChatFocusSuccess')) {
                    $invokeParams.Remove('RequireCodeChatFocusSuccess')
                }
            }
            else {
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
        }
    }

    if ($ClearInputOnly) {
        if ($invokeParams.ContainsKey('EnablePaletteFocusCommand')) {
            $invokeParams.Remove('EnablePaletteFocusCommand')
        }
        if ($invokeParams.ContainsKey('ForceInvokeCodeChatFocus')) {
            $invokeParams.Remove('ForceInvokeCodeChatFocus')
        }
        if ($invokeParams.ContainsKey('RequireCodeChatFocusSuccess')) {
            $invokeParams.Remove('RequireCodeChatFocusSuccess')
        }
        if ($invokeParams.ContainsKey('NoClickFocusFallback')) {
            $invokeParams.Remove('NoClickFocusFallback')
        }
        $invokeParams.ClearInputOnly = $true
        $invokeParams.NoAutoReconnectResend = $true
        $invokeParams.NoInvokeCodeChatFocus = $true
        $invokeParams.NoPaletteFocusCommand = $true
        $invokeParams.UseClickFocusFallback = $true
        $invokeParams.NoChatToggleShortcut = $true
        $invokeParams.NoResetZoomBeforeSend = $true
        $invokeParams.PreSendDelayMs = 0
    }

    try {
        $sendResultRaw = & $sendScriptPath @invokeParams
        $sendResult = Select-AhkSendResultObject -RawResult $sendResultRaw
        if ($null -eq $sendResult) {
            return [pscustomobject]@{
                started = $true
                sent = $false
                exit_code = -1
                reason = 'send-script-no-valid-result'
                attempt_count = 0
                auto_resend_triggered = $false
                auto_resend_reason = ''
                esc_preflight_enabled = $false
                restore_previous_window_count_requested = 0
                restore_previous_window_count_captured = 0
                restore_previous_window_handles = ''
                restore_previous_window_capture_summary = ''
                restore_previous_window_activation_trace = ''
                restore_previous_window_activation_count_attempted = 0
                restore_previous_window_activation_count_succeeded = 0
                restore_previous_window_activation_final_foreground_handle = 0
                restore_previous_window_activation_restore_executed = $false
                restore_previous_window_activation_skipped_reason = ''
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
            $escPreflightFromPolicy = Get-ObjectMemberValue -Container $sendResult.code_focus_policy -MemberName 'effective_esc_preflight'
            if ($null -ne $escPreflightFromPolicy) {
                $escPreflightEnabled = [bool]$escPreflightFromPolicy
            }
        }

        $restorePreviousWindowCountRequested = 0
        $restorePreviousWindowCountCaptured = 0
        $restorePreviousWindowHandles = ''
        $restorePreviousWindowCaptureSummary = ''
        $restorePreviousWindowActivationTrace = ''
        $restorePreviousWindowActivationCountAttempted = 0
        $restorePreviousWindowActivationCountSucceeded = 0
        $restorePreviousWindowActivationFinalForegroundHandle = 0
        $restorePreviousWindowActivationRestoreExecuted = $false
        $restorePreviousWindowActivationSkippedReason = ''
        $codeFocusPolicy = $null
        if ($sendResult.PSObject.Properties['code_focus_policy'] -and $null -ne $sendResult.code_focus_policy) {
            $codeFocusPolicy = $sendResult.code_focus_policy
        }

        if ($null -ne $codeFocusPolicy) {
            $requestedFromPolicy = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'restore_previous_window_count_requested'
            if ($null -ne $requestedFromPolicy) {
                $restorePreviousWindowCountRequested = Convert-ToIntRangeSetting -Value ([string]$requestedFromPolicy) -Default 0 -Min 0 -Max 30
            }

            $capturedFromPolicy = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'restore_previous_window_count_captured'
            if ($null -ne $capturedFromPolicy) {
                $restorePreviousWindowCountCaptured = Convert-ToIntRangeSetting -Value ([string]$capturedFromPolicy) -Default 0 -Min 0 -Max 30
            }

            $handlesFromPolicy = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'restore_previous_window_handles'
            if ($null -ne $handlesFromPolicy) {
                $handles = @($handlesFromPolicy)
                if ($handles.Count -gt 0) {
                    $restorePreviousWindowHandles = Convert-ToSingleLineText -Text (($handles | ForEach-Object { [string]$_ }) -join ',')
                }
            }

            $summaryFromPolicy = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'restore_previous_window_capture_summary'
            if ($null -ne $summaryFromPolicy) {
                $restorePreviousWindowCaptureSummary = Convert-ToSingleLineText -Text ([string]$summaryFromPolicy)
            }

            $activationTraceFromPolicy = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'restore_previous_window_activation_trace'
            if ($null -ne $activationTraceFromPolicy) {
                $restorePreviousWindowActivationTrace = Convert-ToSingleLineText -Text ([string]$activationTraceFromPolicy)
            }

            $activationAttemptedFromPolicy = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'restore_previous_window_activation_count_attempted'
            if ($null -ne $activationAttemptedFromPolicy) {
                $restorePreviousWindowActivationCountAttempted = Convert-ToIntRangeSetting -Value ([string]$activationAttemptedFromPolicy) -Default 0 -Min 0 -Max 30
            }

            $activationSucceededFromPolicy = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'restore_previous_window_activation_count_succeeded'
            if ($null -ne $activationSucceededFromPolicy) {
                $restorePreviousWindowActivationCountSucceeded = Convert-ToIntRangeSetting -Value ([string]$activationSucceededFromPolicy) -Default 0 -Min 0 -Max 30
            }

            $activationFinalFgFromPolicy = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'restore_previous_window_activation_final_foreground_handle'
            if ($null -ne $activationFinalFgFromPolicy) {
                $restorePreviousWindowActivationFinalForegroundHandle = [Int64]$activationFinalFgFromPolicy
            }

            $activationRestoreExecutedFromPolicy = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'restore_previous_window_activation_restore_executed'
            if ($null -ne $activationRestoreExecutedFromPolicy) {
                $restorePreviousWindowActivationRestoreExecuted = [bool]$activationRestoreExecutedFromPolicy
            }

            $activationSkippedReasonFromPolicy = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'restore_previous_window_activation_skipped_reason'
            if ($null -ne $activationSkippedReasonFromPolicy) {
                $restorePreviousWindowActivationSkippedReason = Convert-ToSingleLineText -Text ([string]$activationSkippedReasonFromPolicy)
            }
        }

        if ($restorePreviousWindowCountRequested -le 0 -and $sendResult.PSObject.Properties['restore_previous_window_count_requested']) {
            $restorePreviousWindowCountRequested = Convert-ToIntRangeSetting -Value ([string]$sendResult.restore_previous_window_count_requested) -Default 0 -Min 0 -Max 30
        }

        if ($restorePreviousWindowCountCaptured -le 0 -and $sendResult.PSObject.Properties['restore_previous_window_count_captured']) {
            $restorePreviousWindowCountCaptured = Convert-ToIntRangeSetting -Value ([string]$sendResult.restore_previous_window_count_captured) -Default 0 -Min 0 -Max 30
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
        if ([string]::IsNullOrWhiteSpace($restorePreviousWindowActivationTrace) -and $sendResult.PSObject.Properties['restore_previous_window_activation_trace']) {
            $restorePreviousWindowActivationTrace = Convert-ToSingleLineText -Text ([string]$sendResult.restore_previous_window_activation_trace)
        }
        if ($restorePreviousWindowActivationCountAttempted -le 0 -and $sendResult.PSObject.Properties['restore_previous_window_activation_count_attempted']) {
            $restorePreviousWindowActivationCountAttempted = Convert-ToIntRangeSetting -Value ([string]$sendResult.restore_previous_window_activation_count_attempted) -Default 0 -Min 0 -Max 30
        }
        if ($restorePreviousWindowActivationCountSucceeded -le 0 -and $sendResult.PSObject.Properties['restore_previous_window_activation_count_succeeded']) {
            $restorePreviousWindowActivationCountSucceeded = Convert-ToIntRangeSetting -Value ([string]$sendResult.restore_previous_window_activation_count_succeeded) -Default 0 -Min 0 -Max 30
        }
        if ($restorePreviousWindowActivationFinalForegroundHandle -eq 0 -and $sendResult.PSObject.Properties['restore_previous_window_activation_final_foreground_handle']) {
            $restorePreviousWindowActivationFinalForegroundHandle = [Int64]$sendResult.restore_previous_window_activation_final_foreground_handle
        }
        if (-not $restorePreviousWindowActivationRestoreExecuted -and $sendResult.PSObject.Properties['restore_previous_window_activation_restore_executed']) {
            $restorePreviousWindowActivationRestoreExecuted = [bool]$sendResult.restore_previous_window_activation_restore_executed
        }
        if ([string]::IsNullOrWhiteSpace($restorePreviousWindowActivationSkippedReason) -and $sendResult.PSObject.Properties['restore_previous_window_activation_skipped_reason']) {
            $restorePreviousWindowActivationSkippedReason = Convert-ToSingleLineText -Text ([string]$sendResult.restore_previous_window_activation_skipped_reason)
        }
        if ($restorePreviousWindowCaptureSummary.Length -gt 1200) {
            $restorePreviousWindowCaptureSummary = $restorePreviousWindowCaptureSummary.Substring(0, 1200).TrimEnd() + '...'
        }
        if ($restorePreviousWindowActivationTrace.Length -gt 1600) {
            $restorePreviousWindowActivationTrace = $restorePreviousWindowActivationTrace.Substring(0, 1600).TrimEnd() + '...'
        }

        if ($restorePreviousWindowCountCaptured -le 0 -and -not [string]::IsNullOrWhiteSpace($restorePreviousWindowHandles)) {
            $handleItems = @($restorePreviousWindowHandles -split ',' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $restorePreviousWindowCountCaptured = [Math]::Min(30, $handleItems.Count)
        }

        if ($restorePreviousWindowCountRequested -le 0 -and $RestorePreviousForegroundWindow) {
            $restorePreviousWindowCountRequested = [Math]::Min(30, [Math]::Max(1, $RestorePreviousForegroundWindowCount))
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
            restore_previous_window_activation_trace = $restorePreviousWindowActivationTrace
            restore_previous_window_activation_count_attempted = $restorePreviousWindowActivationCountAttempted
            restore_previous_window_activation_count_succeeded = $restorePreviousWindowActivationCountSucceeded
            restore_previous_window_activation_final_foreground_handle = $restorePreviousWindowActivationFinalForegroundHandle
            restore_previous_window_activation_restore_executed = $restorePreviousWindowActivationRestoreExecuted
            restore_previous_window_activation_skipped_reason = $restorePreviousWindowActivationSkippedReason
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
            restore_previous_window_activation_trace = ''
            restore_previous_window_activation_count_attempted = 0
            restore_previous_window_activation_count_succeeded = 0
            restore_previous_window_activation_final_foreground_handle = 0
            restore_previous_window_activation_restore_executed = $false
            restore_previous_window_activation_skipped_reason = ''
        }
    }
}

function Invoke-PythonChatDispatch {
    param(
        [string]$PythonExecutable,
        [string]$Message,
        [AllowEmptyString()][string]$TicketId = '',
        [int]$TimeoutMs = 12000,
        [System.Collections.IDictionary]$Settings = $null,
        [AllowEmptyString()][string]$EventName = '',
        [bool]$StatusReportAllowInconclusiveSubmit = $true,
        [bool]$RestorePreviousForegroundWindow = $true,
        [int]$RestorePreviousForegroundWindowCount = 12,
        [AllowEmptyString()][string]$PreferredRestoreWindowHandles = '',
        [bool]$ActiveWindowOnly = $false,
        [bool]$StatusReportForcePaletteFocus = $false,
        [bool]$StatusReportClickRecoveryOnly = $false,
        [bool]$ForceFocusRecovery = $false
    )

    if ([string]::IsNullOrWhiteSpace($PythonExecutable) -or -not (Test-Path -LiteralPath $PythonExecutable)) {
        return [pscustomobject]@{
            started = $false
            sent = $false
            exit_code = -1
            reason = 'python-executable-missing'
            attempt_count = 0
            auto_resend_triggered = $false
            auto_resend_reason = ''
            esc_preflight_enabled = $false
            restore_previous_window_count_requested = 0
            restore_previous_window_count_captured = 0
            restore_previous_window_handles = ''
            restore_previous_window_capture_summary = ''
            restore_previous_window_activation_trace = ''
            restore_previous_window_activation_count_attempted = 0
            restore_previous_window_activation_count_succeeded = 0
            restore_previous_window_activation_final_foreground_handle = 0
            restore_previous_window_activation_restore_executed = $false
            restore_previous_window_activation_skipped_reason = ''
        }
    }

    $sendScriptPath = Join-Path $script:RepoRoot 'tools\test\copilot_chat_sender.py'
    if (-not (Test-Path -LiteralPath $sendScriptPath)) {
        return [pscustomobject]@{
            started = $false
            sent = $false
            exit_code = -1
            reason = 'python-send-script-missing'
            attempt_count = 0
            auto_resend_triggered = $false
            auto_resend_reason = ''
            esc_preflight_enabled = $false
            restore_previous_window_count_requested = 0
            restore_previous_window_count_captured = 0
            restore_previous_window_handles = ''
            restore_previous_window_capture_summary = ''
            restore_previous_window_activation_trace = ''
            restore_previous_window_activation_count_attempted = 0
            restore_previous_window_activation_count_succeeded = 0
            restore_previous_window_activation_final_foreground_handle = 0
            restore_previous_window_activation_restore_executed = $false
            restore_previous_window_activation_skipped_reason = ''
        }
    }

    $invokeArgs = New-Object 'System.Collections.Generic.List[string]'
    [void]$invokeArgs.Add($sendScriptPath)
    [void]$invokeArgs.Add('--Message')
    [void]$invokeArgs.Add($Message)

    $ticketToken = Convert-ToSingleLineText -Text $TicketId
    if (-not [string]::IsNullOrWhiteSpace($ticketToken)) {
        [void]$invokeArgs.Add('--ticket-id')
        [void]$invokeArgs.Add($ticketToken)
    }

    [void]$invokeArgs.Add('--json-output')
    [void]$invokeArgs.Add('--TimeoutMs')
    [void]$invokeArgs.Add(([Math]::Max(1000, $TimeoutMs)).ToString())
    [void]$invokeArgs.Add('--MaxRetries')
    [void]$invokeArgs.Add('3')

    $preSendDelayMs = 0
    $watchdogToken = ('dispatch-watchdog-{0}' -f ([Guid]::NewGuid().ToString('N')))
    [void]$invokeArgs.Add('--dedupe-token')
    [void]$invokeArgs.Add($watchdogToken)

    if ($RestorePreviousForegroundWindow) {
        [void]$invokeArgs.Add('--RestorePreviousForegroundWindow')
        [void]$invokeArgs.Add('--RestorePreviousWindowCount')
        [void]$invokeArgs.Add(([Math]::Min(30, [Math]::Max(1, $RestorePreviousForegroundWindowCount))).ToString())

        $preferredHandlesCsv = Convert-ToWindowHandleCsv -Value $PreferredRestoreWindowHandles
        if (-not [string]::IsNullOrWhiteSpace($preferredHandlesCsv)) {
            [void]$invokeArgs.Add('--restore-previous-window-handles-csv')
            [void]$invokeArgs.Add($preferredHandlesCsv)
        }
    }
    else {
        [void]$invokeArgs.Add('--NoRestorePreviousForegroundWindow')
    }

    if ($ActiveWindowOnly) {
        [void]$invokeArgs.Add('--NoActivateWindow')
        [void]$invokeArgs.Add('--RequireActiveCodeWindow')
    }

    $eventNormalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($eventNormalized)) {
        [void]$invokeArgs.Add('--event')
        [void]$invokeArgs.Add($eventNormalized)
    }

    if ($eventNormalized -eq 'running-status-report') {
        $foregroundCodeWindowHint = Get-ForegroundCodeWindowHint
        if ($null -ne $foregroundCodeWindowHint) {
            [void]$invokeArgs.Add('--window-handle')
            [void]$invokeArgs.Add(([Int64](Get-ObjectMemberValue -Container $foregroundCodeWindowHint -MemberName 'handle')).ToString())
            [void]$invokeArgs.Add('--vscode-pid')
            [void]$invokeArgs.Add(([int](Get-ObjectMemberValue -Container $foregroundCodeWindowHint -MemberName 'pid')).ToString())
        }
    }

    if ($eventNormalized -eq 'running-status-report' -and $StatusReportAllowInconclusiveSubmit) {
        [void]$invokeArgs.Add('--AllowInconclusiveSubmitOutcome')
    }

    if ($StatusReportForcePaletteFocus) {
        [void]$invokeArgs.Add('--EnablePaletteFocusCommand')
        [void]$invokeArgs.Add('--UseClickFocusFallback')
    }

    if ($StatusReportClickRecoveryOnly) {
        [void]$invokeArgs.Add('--UseClickFocusFallback')
        [void]$invokeArgs.Add('--NoPaletteFocusCommand')
    }

    if ($ForceFocusRecovery) {
        [void]$invokeArgs.Add('--UseClickFocusFallback')
    }

    $circuitBreakerThreshold = 5
    $circuitBreakerCooldownSec = 900

    if ($null -ne $Settings) {
        if ($Settings.Contains('AI_CHAT_DISPATCH_PY_CIRCUIT_BREAKER_THRESHOLD')) {
            $circuitBreakerThreshold = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_PY_CIRCUIT_BREAKER_THRESHOLD) -Default $circuitBreakerThreshold -Min 1 -Max 100
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_PY_CIRCUIT_BREAKER_COOLDOWN_SEC')) {
            $circuitBreakerCooldownSec = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_PY_CIRCUIT_BREAKER_COOLDOWN_SEC) -Default $circuitBreakerCooldownSec -Min 0 -Max 86400
        }

        if ($eventNormalized -eq 'running-status-report') {
            if ($Settings.Contains('AI_CHAT_DISPATCH_STATUS_REPORT_PY_CIRCUIT_BREAKER_THRESHOLD')) {
                $circuitBreakerThreshold = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_STATUS_REPORT_PY_CIRCUIT_BREAKER_THRESHOLD) -Default $circuitBreakerThreshold -Min 1 -Max 100
            }
            if ($Settings.Contains('AI_CHAT_DISPATCH_STATUS_REPORT_PY_CIRCUIT_BREAKER_COOLDOWN_SEC')) {
                $circuitBreakerCooldownSec = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_STATUS_REPORT_PY_CIRCUIT_BREAKER_COOLDOWN_SEC) -Default $circuitBreakerCooldownSec -Min 0 -Max 86400
            }
        }

        if ($Settings.Contains('AI_CHAT_DISPATCH_PRESEND_DELAY_MS')) {
            $preSendDelayMs = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_PRESEND_DELAY_MS) -Default 700 -Min 0 -Max 60000
            [void]$invokeArgs.Add('--PreSendDelayMs')
            [void]$invokeArgs.Add($preSendDelayMs.ToString())
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_ESC_PREFLIGHT')) {
            $escPreflightEnabled = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_ESC_PREFLIGHT) -Default $false
            if ($escPreflightEnabled) {
                [void]$invokeArgs.Add('--EnableEscPreflight')
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_RESET_ZOOM_BEFORE_SEND')) {
            $resetZoomBeforeSend = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_RESET_ZOOM_BEFORE_SEND) -Default $true
            if (-not $resetZoomBeforeSend) {
                [void]$invokeArgs.Add('--NoResetZoomBeforeSend')
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_MAXIMIZE_WINDOW')) {
            $maximizeWindow = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_MAXIMIZE_WINDOW) -Default $true
            if (-not $maximizeWindow) {
                [void]$invokeArgs.Add('--NoMaximizeCodeWindow')
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_BOTTOM_AVOID_PX')) {
            [void]$invokeArgs.Add('--ChatBottomAvoidPx')
            [void]$invokeArgs.Add((Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_BOTTOM_AVOID_PX) -Default 170 -Min 0 -Max 400).ToString())
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_RIGHT_OFFSET_PX')) {
            [void]$invokeArgs.Add('--ChatInputRightOffsetPx')
            [void]$invokeArgs.Add((Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_RIGHT_OFFSET_PX) -Default 300 -Min 0 -Max 2400).ToString())
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_X_MODE')) {
            $xMode = (Convert-ToSingleLineText -Text ([string]$Settings.AI_CHAT_DISPATCH_X_MODE)).ToLowerInvariant()
            if ($xMode -in @('ratio', 'right-offset')) {
                [void]$invokeArgs.Add('--ChatInputXMode')
                [void]$invokeArgs.Add($xMode)
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_RECONNECT_DELAY_MS')) {
            [void]$invokeArgs.Add('--ReconnectResendDelayMs')
            [void]$invokeArgs.Add((Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_RECONNECT_DELAY_MS) -Default 1800 -Min 200 -Max 30000).ToString())
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_RECONNECT_WINDOW_SEC')) {
            [void]$invokeArgs.Add('--ReconnectDetectWindowSec')
            [void]$invokeArgs.Add((Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_RECONNECT_WINDOW_SEC) -Default 300 -Min 60 -Max 1800).ToString())
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_AUTO_RECONNECT_RESEND')) {
            $autoResendEnabled = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_AUTO_RECONNECT_RESEND) -Default $true
            if ($autoResendEnabled) {
                [void]$invokeArgs.Add('--EnableAutoReconnectResend')
            }
            else {
                [void]$invokeArgs.Add('--NoAutoReconnectResend')
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT_ENABLED')) {
            $toggleEnabled = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT_ENABLED) -Default $false
            if ($toggleEnabled) {
                [void]$invokeArgs.Add('--EnableChatToggleShortcut')
            }
            else {
                [void]$invokeArgs.Add('--NoChatToggleShortcut')
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT')) {
            $toggleShortcut = Convert-ToSingleLineText -Text ([string]$Settings.AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT)
            if (-not [string]::IsNullOrWhiteSpace($toggleShortcut)) {
                [void]$invokeArgs.Add('--ChatToggleShortcut')
                [void]$invokeArgs.Add($toggleShortcut)
            }
        }

        if ($Settings.Contains('AI_CHAT_DISPATCH_ADAPTIVE_LOAD_ENABLED')) {
            $adaptiveLoadEnabled = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_ADAPTIVE_LOAD_ENABLED) -Default $true
            if (-not $adaptiveLoadEnabled) {
                [void]$invokeArgs.Add('--disable-adaptive-load')
            }
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_ADAPTIVE_HIGH_LOAD_MEMORY_PERCENT')) {
            [void]$invokeArgs.Add('--adaptive-high-load-memory-percent')
            [void]$invokeArgs.Add((Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_ADAPTIVE_HIGH_LOAD_MEMORY_PERCENT) -Default 88 -Min 50 -Max 99).ToString())
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_ADAPTIVE_HIGH_LOAD_AVAILABLE_MB')) {
            [void]$invokeArgs.Add('--adaptive-high-load-available-mb')
            [void]$invokeArgs.Add((Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_ADAPTIVE_HIGH_LOAD_AVAILABLE_MB) -Default 768 -Min 128 -Max 16384).ToString())
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_ADAPTIVE_LOW_LOAD_MEMORY_PERCENT')) {
            [void]$invokeArgs.Add('--adaptive-low-load-memory-percent')
            [void]$invokeArgs.Add((Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_ADAPTIVE_LOW_LOAD_MEMORY_PERCENT) -Default 72 -Min 30 -Max 95).ToString())
        }
        if ($Settings.Contains('AI_CHAT_DISPATCH_ADAPTIVE_LOW_LOAD_AVAILABLE_MB')) {
            [void]$invokeArgs.Add('--adaptive-low-load-available-mb')
            [void]$invokeArgs.Add((Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_ADAPTIVE_LOW_LOAD_AVAILABLE_MB) -Default 1536 -Min 256 -Max 32768).ToString())
        }
    }

    [void]$invokeArgs.Add('--circuit-breaker-threshold')
    [void]$invokeArgs.Add($circuitBreakerThreshold.ToString())
    [void]$invokeArgs.Add('--circuit-breaker-cooldown-sec')
    [void]$invokeArgs.Add($circuitBreakerCooldownSec.ToString())

    $pythonWatchdogTimeoutMs = [Math]::Max(30000, ([Math]::Max(1000, $TimeoutMs) + $preSendDelayMs + 15000))
    $pythonWatchdogTimeoutMs = [Math]::Min(300000, $pythonWatchdogTimeoutMs)
    if ($null -ne $Settings -and $Settings.Contains('AI_CHAT_DISPATCH_PY_WATCHDOG_TIMEOUT_MS')) {
        $pythonWatchdogTimeoutMs = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_PY_WATCHDOG_TIMEOUT_MS) -Default $pythonWatchdogTimeoutMs -Min 5000 -Max 300000
    }

    try {
        $sendResultRaw = @()
        $watchdogTimedOut = $false
        $watchdogKilledPids = New-Object 'System.Collections.Generic.List[int]'
        $dispatchJob = $null

        try {
            $invokeArgsArray = [string[]]$invokeArgs.ToArray()
            $dispatchJob = Start-Job -ScriptBlock {
                & $using:PythonExecutable @using:invokeArgsArray 2>&1
            }

            $watchdogWaitSec = [Math]::Max(5, [int][Math]::Ceiling([double]$pythonWatchdogTimeoutMs / 1000.0))
            $completedJob = Wait-Job -Job $dispatchJob -Timeout $watchdogWaitSec

            if ($null -eq $completedJob) {
                $watchdogTimedOut = $true
                try {
                    Stop-Job -Job $dispatchJob -Force -ErrorAction SilentlyContinue | Out-Null
                }
                catch {
                    Write-Verbose ("Stop-Job cleanup failed: {0}" -f $_.Exception.Message)
                }

                $escapedWatchdogToken = [regex]::Escape($watchdogToken)
                $pythonProcesses = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.CommandLine -and ([string]$_.CommandLine -match $escapedWatchdogToken)
                    }

                foreach ($processItem in @($pythonProcesses)) {
                    $targetPid = [int]$processItem.ProcessId
                    if ($targetPid -le 0) {
                        continue
                    }

                    try {
                        Stop-Process -Id $targetPid -Force -ErrorAction Stop
                        [void]$watchdogKilledPids.Add($targetPid)
                    }
                    catch {
                        Write-Verbose ("Watchdog failed to stop pid={0}: {1}" -f $targetPid, $_.Exception.Message)
                    }
                }
            }
            else {
                $sendResultRaw = @(
                    Receive-Job -Job $dispatchJob -ErrorAction SilentlyContinue
                )
            }
        }
        finally {
            if ($null -ne $dispatchJob) {
                try {
                    Remove-Job -Job $dispatchJob -Force -ErrorAction SilentlyContinue | Out-Null
                }
                catch {
                    Write-Verbose ("Remove-Job cleanup failed: {0}" -f $_.Exception.Message)
                }
            }
        }

        if ($watchdogTimedOut) {
            $killedPidText = ''
            if ($watchdogKilledPids.Count -gt 0) {
                $killedPidText = (($watchdogKilledPids.ToArray() | ForEach-Object { [string]$_ }) -join ',')
            }

            $timeoutReason = "python-watchdog-timeout timeout_ms={0} token={1}" -f $pythonWatchdogTimeoutMs, $watchdogToken
            if (-not [string]::IsNullOrWhiteSpace($killedPidText)) {
                $timeoutReason = "{0} killed_pids={1}" -f $timeoutReason, $killedPidText
            }

            return [pscustomobject]@{
                started = $true
                sent = $false
                exit_code = 124
                reason = $timeoutReason
                attempt_count = 0
                auto_resend_triggered = $false
                auto_resend_reason = ''
                esc_preflight_enabled = $false
                restore_previous_window_count_requested = 0
                restore_previous_window_count_captured = 0
                restore_previous_window_handles = ''
                restore_previous_window_capture_summary = ''
                restore_previous_window_activation_trace = ''
                restore_previous_window_activation_count_attempted = 0
                restore_previous_window_activation_count_succeeded = 0
                restore_previous_window_activation_final_foreground_handle = 0
                restore_previous_window_activation_restore_executed = $false
                restore_previous_window_activation_skipped_reason = ''
                watchdog_timeout = $true
                watchdog_timeout_ms = $pythonWatchdogTimeoutMs
                watchdog_token = $watchdogToken
                watchdog_killed_pids = $killedPidText
            }
        }

        $sendResult = Select-JsonResultObject -RawOutput $sendResultRaw
        if ($null -eq $sendResult) {
            return [pscustomobject]@{
                started = $true
                sent = $false
                exit_code = -1
                reason = 'python-send-no-valid-result'
                attempt_count = 0
                auto_resend_triggered = $false
                auto_resend_reason = ''
                esc_preflight_enabled = $false
                restore_previous_window_count_requested = 0
                restore_previous_window_count_captured = 0
                restore_previous_window_handles = ''
                restore_previous_window_capture_summary = ''
                restore_previous_window_activation_trace = ''
                restore_previous_window_activation_count_attempted = 0
                restore_previous_window_activation_count_succeeded = 0
                restore_previous_window_activation_final_foreground_handle = 0
                restore_previous_window_activation_restore_executed = $false
                restore_previous_window_activation_skipped_reason = ''
                watchdog_timeout = $false
                watchdog_timeout_ms = $pythonWatchdogTimeoutMs
                watchdog_token = $watchdogToken
                watchdog_killed_pids = ''
            }
        }

        $sentRaw = Get-ObjectMemberValue -Container $sendResult -MemberName 'sent'
        if ($null -eq $sentRaw) {
            $sentRaw = Get-ObjectMemberValue -Container $sendResult -MemberName 'success'
        }
        $sent = $false
        if ($null -ne $sentRaw) {
            $sent = [bool]$sentRaw
        }

        $exitCodeRaw = Get-ObjectMemberValue -Container $sendResult -MemberName 'ahk_exit_code'
        if ($null -eq $exitCodeRaw) {
            $exitCodeRaw = Get-ObjectMemberValue -Container $sendResult -MemberName 'exit_code'
        }
        $exitCode = Convert-ToIntRangeSetting -Value ([string]$exitCodeRaw) -Default -1 -Min -1 -Max 9999

        $dispatchAttemptsRaw = Get-ObjectMemberValue -Container $sendResult -MemberName 'dispatch_attempts'
        $dispatchAttempts = @()
        if ($null -ne $dispatchAttemptsRaw) {
            $dispatchAttempts = @($dispatchAttemptsRaw)
        }
        $attemptCount = $dispatchAttempts.Count

        $autoResendTriggered = $false
        $autoResendReason = ''
        $autoReconnectResend = Get-ObjectMemberValue -Container $sendResult -MemberName 'auto_reconnect_resend'
        if ($null -ne $autoReconnectResend) {
            $autoResendTriggeredRaw = Get-ObjectMemberValue -Container $autoReconnectResend -MemberName 'triggered'
            if ($null -ne $autoResendTriggeredRaw) {
                $autoResendTriggered = [bool]$autoResendTriggeredRaw
            }
            $autoResendReasonRaw = Get-ObjectMemberValue -Container $autoReconnectResend -MemberName 'trigger_reason'
            $autoResendReason = Convert-ToSingleLineText -Text ([string]$autoResendReasonRaw)
        }

        $escPreflightEnabled = $false
        $escPreflightRaw = Get-ObjectMemberValue -Container $sendResult -MemberName 'esc_preflight_enabled'
        if ($null -ne $escPreflightRaw) {
            $escPreflightEnabled = [bool]$escPreflightRaw
        }
        else {
            $codeFocusPolicy = Get-ObjectMemberValue -Container $sendResult -MemberName 'code_focus_policy'
            if ($null -ne $codeFocusPolicy) {
                $escPreflightFromPolicy = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'effective_esc_preflight'
                if ($null -ne $escPreflightFromPolicy) {
                    $escPreflightEnabled = [bool]$escPreflightFromPolicy
                }
            }
        }

        $restorePreviousWindowCountRequested = Convert-ToIntRangeSetting -Value ([string](Get-ObjectMemberValue -Container $sendResult -MemberName 'restore_previous_window_count_requested')) -Default 0 -Min 0 -Max 30
        $restorePreviousWindowCountCaptured = Convert-ToIntRangeSetting -Value ([string](Get-ObjectMemberValue -Container $sendResult -MemberName 'restore_previous_window_count_captured')) -Default 0 -Min 0 -Max 30
        $restorePreviousWindowCaptureSummary = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $sendResult -MemberName 'restore_previous_window_capture_summary'))
        $restorePreviousWindowActivationTrace = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $sendResult -MemberName 'restore_previous_window_activation_trace'))
        $restorePreviousWindowActivationCountAttempted = Convert-ToIntRangeSetting -Value ([string](Get-ObjectMemberValue -Container $sendResult -MemberName 'restore_previous_window_activation_count_attempted')) -Default 0 -Min 0 -Max 30
        $restorePreviousWindowActivationCountSucceeded = Convert-ToIntRangeSetting -Value ([string](Get-ObjectMemberValue -Container $sendResult -MemberName 'restore_previous_window_activation_count_succeeded')) -Default 0 -Min 0 -Max 30
        $restorePreviousWindowActivationFinalForegroundHandle = [Int64](Convert-ToIntRangeSetting -Value ([string](Get-ObjectMemberValue -Container $sendResult -MemberName 'restore_previous_window_activation_final_foreground_handle')) -Default 0 -Min 0 -Max 2147483647)
        $restorePreviousWindowActivationRestoreExecuted = [bool](Get-ObjectMemberValue -Container $sendResult -MemberName 'restore_previous_window_activation_restore_executed')
        $restorePreviousWindowActivationSkippedReason = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $sendResult -MemberName 'restore_previous_window_activation_skipped_reason'))

        $restorePreviousWindowHandlesRaw = Get-ObjectMemberValue -Container $sendResult -MemberName 'restore_previous_window_handles'
        $restorePreviousWindowHandles = Convert-ToWindowHandleCsv -Value $restorePreviousWindowHandlesRaw

        if ([string]::IsNullOrWhiteSpace($restorePreviousWindowHandles)) {
            $codeFocusPolicy = Get-ObjectMemberValue -Container $sendResult -MemberName 'code_focus_policy'
            if ($null -ne $codeFocusPolicy) {
                $policyHandles = Get-ObjectMemberValue -Container $codeFocusPolicy -MemberName 'restore_previous_window_handles'
                $restorePreviousWindowHandles = Convert-ToWindowHandleCsv -Value $policyHandles
            }
        }

        if ($restorePreviousWindowCountRequested -le 0 -and $RestorePreviousForegroundWindow) {
            $restorePreviousWindowCountRequested = [Math]::Min(30, [Math]::Max(1, $RestorePreviousForegroundWindowCount))
        }
        if ($restorePreviousWindowCountCaptured -le 0 -and -not [string]::IsNullOrWhiteSpace($restorePreviousWindowHandles)) {
            $handleItems = @($restorePreviousWindowHandles -split ',' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $restorePreviousWindowCountCaptured = [Math]::Min(30, $handleItems.Count)
        }

        $sendNote = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $sendResult -MemberName 'note'))

        $reason = 'ok'
        if ($sent -and $autoResendTriggered) {
            $reason = if ([string]::IsNullOrWhiteSpace($autoResendReason)) { 'ok-after-auto-resend' } else { ('ok-after-auto-resend:{0}' -f $autoResendReason) }
        }
        elseif (-not $sent) {
            $reason = ''
            if ($dispatchAttempts.Count -gt 0) {
                $lastAttempt = $dispatchAttempts[-1]
                $reason = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $lastAttempt -MemberName 'failure'))
            }

            if ([string]::IsNullOrWhiteSpace($reason)) {
                $reason = if ($exitCode -eq -1) { 'python-send-reported-unsent' } else { ('python-exit-{0}' -f $exitCode) }
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
            restore_previous_window_activation_trace = $restorePreviousWindowActivationTrace
            restore_previous_window_activation_count_attempted = $restorePreviousWindowActivationCountAttempted
            restore_previous_window_activation_count_succeeded = $restorePreviousWindowActivationCountSucceeded
            restore_previous_window_activation_final_foreground_handle = $restorePreviousWindowActivationFinalForegroundHandle
            restore_previous_window_activation_restore_executed = $restorePreviousWindowActivationRestoreExecuted
            restore_previous_window_activation_skipped_reason = $restorePreviousWindowActivationSkippedReason
            watchdog_timeout = $false
            watchdog_timeout_ms = $pythonWatchdogTimeoutMs
            watchdog_token = $watchdogToken
            watchdog_killed_pids = ''
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
            restore_previous_window_activation_trace = ''
            restore_previous_window_activation_count_attempted = 0
            restore_previous_window_activation_count_succeeded = 0
            restore_previous_window_activation_final_foreground_handle = 0
            restore_previous_window_activation_restore_executed = $false
            restore_previous_window_activation_skipped_reason = ''
            watchdog_timeout = $false
            watchdog_timeout_ms = $pythonWatchdogTimeoutMs
            watchdog_token = $watchdogToken
            watchdog_killed_pids = ''
        }
    }
}

function Invoke-IpcChatDispatch {
    param(
        [AllowEmptyString()][string]$Message,
        [AllowEmptyString()][string]$TicketId = '',
        [int]$TimeoutMs = 12000,
        [System.Collections.IDictionary]$Settings = $null,
        [AllowEmptyString()][string]$EventName = '',
        [AllowEmptyString()][string]$IpcMode = 'Visible'
    )

    $sendScriptPath = Join-Path $script:RepoRoot 'tools\test\Send-IpcChatMessage.ps1'
    if (-not (Test-Path -LiteralPath $sendScriptPath)) {
        return [pscustomobject]@{
            started = $false
            sent = $false
            exit_code = -1
            reason = 'ipc-send-script-missing'
            attempt_count = 0
            auto_resend_triggered = $false
            auto_resend_reason = ''
            esc_preflight_enabled = $false
            restore_previous_window_count_requested = 0
            restore_previous_window_count_captured = 0
            restore_previous_window_handles = ''
            restore_previous_window_capture_summary = ''
            restore_previous_window_activation_trace = ''
            restore_previous_window_activation_count_attempted = 0
            restore_previous_window_activation_count_succeeded = 0
            restore_previous_window_activation_final_foreground_handle = 0
            restore_previous_window_activation_restore_executed = $false
            restore_previous_window_activation_skipped_reason = ''
        }
    }

    $eventNormalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    $normalPriorityEvents = @('running-status-report', 'a-pass-conclusion-b-started')
    $ipcPriority = if ($eventNormalized -in $normalPriorityEvents) { 'normal' } else { 'high' }
    if ($null -ne $Settings -and $Settings.Contains('AI_CHAT_DISPATCH_IPC_PRIORITY')) {
        $configuredPriority = (Convert-ToSingleLineText -Text ([string]$Settings.AI_CHAT_DISPATCH_IPC_PRIORITY)).ToLowerInvariant()
        if ($configuredPriority -in @('normal', 'high') -and $eventNormalized -in $normalPriorityEvents) {
            $ipcPriority = $configuredPriority
        }
        elseif ($configuredPriority -eq 'normal' -and $eventNormalized -notin $normalPriorityEvents) {
            # Actionable recovery tickets stay high priority and are never downgraded by mode/settings.
            $ipcPriority = 'high'
        }
    }

    $modeToken = (Convert-ToSingleLineText -Text $IpcMode).ToLowerInvariant()
    $normalizedIpcMode = switch ($modeToken) {
        'silent' { 'Silent' }
        'auto' { 'Auto' }
        default { 'Visible' }
    }

    $timeoutSec = [Math]::Ceiling([Math]::Max(1000, $TimeoutMs) / 1000.0)
    $timeoutSec = [Math]::Min(300, [Math]::Max(1, [int]$timeoutSec))
    $pollIntervalMs = 200
    if ($null -ne $Settings -and $Settings.Contains('AI_CHAT_DISPATCH_IPC_POLL_INTERVAL_MS')) {
        $pollIntervalMs = Convert-ToIntRangeSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_IPC_POLL_INTERVAL_MS) -Default 200 -Min 50 -Max 2000
    }

    $autoEscalate = ($ipcPriority -eq 'normal')
    if ($null -ne $Settings -and $Settings.Contains('AI_CHAT_DISPATCH_IPC_AUTO_ESCALATE')) {
        $autoEscalate = Convert-ToBooleanSetting -Value ([string]$Settings.AI_CHAT_DISPATCH_IPC_AUTO_ESCALATE) -Default $autoEscalate
    }

    $invokeParams = @{
        Message = $Message
        Priority = $ipcPriority
        TimeoutSec = $timeoutSec
        PollIntervalMs = $pollIntervalMs
        Mode = $normalizedIpcMode
        JsonOutput = $true
    }

    if ($autoEscalate) {
        $invokeParams.AutoEscalate = $true
    }

    $requestId = Convert-ToSingleLineText -Text $TicketId
    if (-not [string]::IsNullOrWhiteSpace($requestId)) {
        $invokeParams.RequestId = $requestId
    }

    try {
        $previousErrorActionPreference = $ErrorActionPreference
        $rawResult = $null
        $invokeExitCode = -1
        try {
            $ErrorActionPreference = 'Continue'
            $rawResult = & $sendScriptPath @invokeParams 2>&1
            $invokeExitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }

        $lines = New-Object 'System.Collections.Generic.List[string]'
        foreach ($entry in @($rawResult)) {
            $line = Convert-ToSingleLineText -Text ([string]$entry)
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                [void]$lines.Add($line)
            }
        }

        $jsonText = ''
        for ($idx = $lines.Count - 1; $idx -ge 0; $idx--) {
            $candidate = [string]$lines[$idx]
            if ($candidate.StartsWith('{') -and $candidate.EndsWith('}')) {
                $jsonText = $candidate
                break
            }
        }

        $outcome = $null
        if (-not [string]::IsNullOrWhiteSpace($jsonText)) {
            try {
                $outcome = $jsonText | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                $outcome = $null
            }
        }

        $sent = $false
        $reason = ''
        $autoResendTriggered = $false
        $autoResendReason = ''

        if ($null -ne $outcome) {
            $sent = [bool](Get-ObjectMemberValue -Container $outcome -MemberName 'success')
            $reason = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $outcome -MemberName 'reason'))
            $autoResendTriggered = [bool](Get-ObjectMemberValue -Container $outcome -MemberName 'escalated')
            $autoResendReason = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $outcome -MemberName 'escalated_reason'))
        }

        if ([string]::IsNullOrWhiteSpace($reason)) {
            if ($sent) {
                $reason = 'sent_via_ipc'
            }
            elseif ($lines.Count -gt 0) {
                $reason = [string]$lines[$lines.Count - 1]
            }
            else {
                $reason = if ($invokeExitCode -eq 0) { 'unknown' } else { ('ipc-exit-{0}' -f $invokeExitCode) }
            }
        }

        $exitCode = 0
        if (-not $sent) {
            $reasonLower = $reason.ToLowerInvariant()
            if ($reasonLower -eq 'poll_timeout' -or $reasonLower.StartsWith('write_cmd_failed')) {
                $exitCode = 1
            }
            else {
                $exitCode = 2
            }
        }

        return [pscustomobject]@{
            started = $true
            sent = $sent
            exit_code = $exitCode
            reason = $reason
            attempt_count = 1
            auto_resend_triggered = $autoResendTriggered
            auto_resend_reason = $autoResendReason
            esc_preflight_enabled = $false
            restore_previous_window_count_requested = 0
            restore_previous_window_count_captured = 0
            restore_previous_window_handles = ''
            restore_previous_window_capture_summary = ''
            restore_previous_window_activation_trace = ''
            restore_previous_window_activation_count_attempted = 0
            restore_previous_window_activation_count_succeeded = 0
            restore_previous_window_activation_final_foreground_handle = 0
            restore_previous_window_activation_restore_executed = $false
            restore_previous_window_activation_skipped_reason = ''
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
            restore_previous_window_activation_trace = ''
            restore_previous_window_activation_count_attempted = 0
            restore_previous_window_activation_count_succeeded = 0
            restore_previous_window_activation_final_foreground_handle = 0
            restore_previous_window_activation_restore_executed = $false
            restore_previous_window_activation_skipped_reason = ''
        }
    }
}

function Invoke-ChatInputClearBestEffort {
    param(
        [AllowEmptyString()][string]$AhkExecutable,
        [AllowEmptyString()][string]$Message,
        [AllowEmptyString()][string]$TicketId = '',
        [int]$TimeoutMs = 12000,
        [System.Collections.IDictionary]$Settings = $null,
        [AllowEmptyString()][string]$EventName = '',
        [bool]$RestorePreviousForegroundWindow = $true,
        [int]$RestorePreviousForegroundWindowCount = 12,
        [AllowEmptyString()][string]$PreferredRestoreWindowHandles = '',
        [bool]$ActiveWindowOnly = $false,
        [bool]$StatusReportForcePaletteFocus = $false,
        [bool]$StatusReportClickRecoveryOnly = $false,
        [bool]$ForceFocusRecovery = $false
    )

    if ([string]::IsNullOrWhiteSpace($AhkExecutable) -or -not (Test-Path -LiteralPath $AhkExecutable)) {
        return [pscustomobject]@{
            attempted = $false
            cleared = $false
            started = $false
            exit_code = -1
            reason = 'clear-skip-ahk-unavailable'
        }
    }

    $clearMessage = Convert-ToSingleLineText -Text $Message
    if ([string]::IsNullOrWhiteSpace($clearMessage)) {
        $clearMessage = '[clear-input-only]'
    }

    $clearResult = Invoke-AhkChatDispatch -AhkExecutable $AhkExecutable -Message $clearMessage -TicketId $TicketId -TimeoutMs ([Math]::Min(12000, [Math]::Max(5000, $TimeoutMs))) -Settings $Settings -EventName $EventName -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -PreferredRestoreWindowHandles $PreferredRestoreWindowHandles -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $ForceFocusRecovery -ClearInputOnly $true

    if ($null -eq $clearResult) {
        return [pscustomobject]@{
            attempted = $true
            cleared = $false
            started = $false
            exit_code = -1
            reason = 'clear-no-result'
        }
    }

    $clearExitCode = Convert-ToIntRangeSetting -Value ([string]$clearResult.exit_code) -Default -1 -Min -1 -Max 9999
    $clearReason = Convert-ToSingleLineText -Text ([string]$clearResult.reason)
    $clearStarted = [bool]$clearResult.started
    $clearSucceeded = $clearStarted -and ($clearExitCode -eq 0)

    if ([string]::IsNullOrWhiteSpace($clearReason)) {
        $clearReason = if ($clearSucceeded) { 'clear-ok' } else { 'clear-failed' }
    }

    return [pscustomobject]@{
        attempted = $true
        cleared = $clearSucceeded
        started = $clearStarted
        exit_code = $clearExitCode
        reason = $clearReason
    }
}

function Invoke-ConfiguredChatDispatch {
    param(
        [ValidateSet('ahk', 'python', 'ipc')][string]$SenderMode,
        [AllowEmptyString()][string]$AhkExecutable,
        [AllowEmptyString()][string]$PythonExecutable,
        [string]$Message,
        [AllowEmptyString()][string]$TicketId = '',
        [int]$TimeoutMs = 12000,
        [System.Collections.IDictionary]$Settings = $null,
        [AllowEmptyString()][string]$EventName = '',
        [AllowEmptyString()][string]$IpcMode = 'Visible',
        [bool]$HeartbeatTimeoutRequireCodeFocus = $true,
        [bool]$StatusReportAllowInconclusiveSubmit = $true,
        [bool]$RestorePreviousForegroundWindow = $true,
        [int]$RestorePreviousForegroundWindowCount = 12,
        [bool]$ActiveWindowOnly = $false,
        [bool]$CrossSenderFallbackEnabled = $true,
        [bool]$ClearInputOnFailure = $true,
        [bool]$StatusReportForcePaletteFocus = $false,
        [bool]$StatusReportClickRecoveryOnly = $false,
        [bool]$ForceFocusRecovery = $false
    )

    if ($SenderMode -eq 'ipc') {
        return Invoke-IpcChatDispatch -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -IpcMode $IpcMode
    }

    if ($SenderMode -eq 'python') {
        $pythonResult = Invoke-PythonChatDispatch -PythonExecutable $PythonExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -StatusReportAllowInconclusiveSubmit $StatusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $ForceFocusRecovery

        if ($null -eq $pythonResult) {
            return $pythonResult
        }

        $pythonRestoreHandlesRaw = Get-ObjectMemberValue -Container $pythonResult -MemberName 'restore_previous_window_handles'
        $pythonRestoreHandlesForFallback = Convert-ToWindowHandleCsv -Value $pythonRestoreHandlesRaw
        if ([string]::IsNullOrWhiteSpace($pythonRestoreHandlesForFallback)) {
            $pythonCodeFocusPolicy = Get-ObjectMemberValue -Container $pythonResult -MemberName 'code_focus_policy'
            if ($null -ne $pythonCodeFocusPolicy) {
                $pythonPolicyHandlesRaw = Get-ObjectMemberValue -Container $pythonCodeFocusPolicy -MemberName 'restore_previous_window_handles'
                $pythonRestoreHandlesForFallback = Convert-ToWindowHandleCsv -Value $pythonPolicyHandlesRaw
            }
        }

        $pythonReason = Convert-ToSingleLineText -Text ([string]$pythonResult.reason)
        $eventNormalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
        $watchdogTimedOut = $false
        if ($pythonResult.PSObject.Properties['watchdog_timeout']) {
            $watchdogTimedOut = [bool]$pythonResult.watchdog_timeout
        }
        if (-not $watchdogTimedOut -and $pythonReason.ToLowerInvariant().StartsWith('python-watchdog-timeout')) {
            $watchdogTimedOut = $true
        }

        if ($watchdogTimedOut) {
            $clearBeforeWatchdogReason = 'clear-disabled'
            if ($ClearInputOnFailure) {
                $clearBeforeWatchdogFallback = Invoke-ChatInputClearBestEffort -AhkExecutable $AhkExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -PreferredRestoreWindowHandles $pythonRestoreHandlesForFallback -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $false
                $clearBeforeWatchdogReason = Convert-ToSingleLineText -Text ([string]$clearBeforeWatchdogFallback.reason)
                if ([string]::IsNullOrWhiteSpace($clearBeforeWatchdogReason)) {
                    $clearBeforeWatchdogReason = if ([bool]$clearBeforeWatchdogFallback.cleared) { 'clear-ok' } else { 'clear-unknown' }
                }
            }

            if ($CrossSenderFallbackEnabled) {
                $ahkReady = (-not [string]::IsNullOrWhiteSpace($AhkExecutable)) -and (Test-Path -LiteralPath $AhkExecutable)
                if ($ahkReady) {
                    $ahkFallback = Invoke-AhkChatDispatch -AhkExecutable $AhkExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -HeartbeatTimeoutRequireCodeFocus $HeartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $StatusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -PreferredRestoreWindowHandles $pythonRestoreHandlesForFallback -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $ForceFocusRecovery

                    $ahkReason = Convert-ToSingleLineText -Text ([string]$ahkFallback.reason)
                    if ([string]::IsNullOrWhiteSpace($pythonReason)) {
                        $pythonReason = 'python-watchdog-timeout'
                    }
                    if ([string]::IsNullOrWhiteSpace($ahkReason)) {
                        $ahkReason = 'fallback-unsent'
                    }

                    if (-not [bool]$ahkFallback.sent) {
                        if ($ClearInputOnFailure) {
                            $clearAfterWatchdogFallback = Invoke-ChatInputClearBestEffort -AhkExecutable $AhkExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -PreferredRestoreWindowHandles $pythonRestoreHandlesForFallback -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $true
                            $clearAfterWatchdogReason = Convert-ToSingleLineText -Text ([string]$clearAfterWatchdogFallback.reason)
                            if ([string]::IsNullOrWhiteSpace($clearAfterWatchdogReason)) {
                                $clearAfterWatchdogReason = if ([bool]$clearAfterWatchdogFallback.cleared) { 'clear-ok' } else { 'clear-unknown' }
                            }
                            $ahkFallback.reason = ('python-watchdog-fallback python_reason={0};ahk_reason={1};pre_clear={2};post_clear={3}' -f $pythonReason, $ahkReason, $clearBeforeWatchdogReason, $clearAfterWatchdogReason)
                        }
                        else {
                            $ahkFallback.reason = ('python-watchdog-fallback python_reason={0};ahk_reason={1};pre_clear={2}' -f $pythonReason, $ahkReason, $clearBeforeWatchdogReason)
                        }
                    }
                    else {
                        $ahkFallback.reason = ('python-watchdog-fallback python_reason={0};ahk_reason={1};pre_clear={2}' -f $pythonReason, $ahkReason, $clearBeforeWatchdogReason)
                    }
                    return $ahkFallback
                }

                $pythonResult.reason = if ([string]::IsNullOrWhiteSpace($pythonReason)) {
                    'python-watchdog-timeout;ahk-fallback-unavailable;pre_clear={0}' -f $clearBeforeWatchdogReason
                }
                else {
                    '{0};ahk-fallback-unavailable;pre_clear={1}' -f $pythonReason, $clearBeforeWatchdogReason
                }
            }
            else {
                $pythonResult.reason = if ([string]::IsNullOrWhiteSpace($pythonReason)) {
                    'python-watchdog-timeout;fallback-disabled;pre_clear={0}' -f $clearBeforeWatchdogReason
                }
                else {
                    '{0};fallback-disabled;pre_clear={1}' -f $pythonReason, $clearBeforeWatchdogReason
                }
            }
        }

        $pythonUnsentReason = $pythonReason.ToLowerInvariant()
        $shouldFallbackOnPythonUnsent = (-not [bool]$pythonResult.sent) -and ($eventNormalized -eq 'running-status-report') -and (
            $pythonUnsentReason.Contains('python-send-reported-unsent') -or
            $pythonUnsentReason.Contains('input_not_observed_after_set_text') -or
            $pythonUnsentReason.Contains('send_failed')
        )

        if ($shouldFallbackOnPythonUnsent) {
            $clearBeforePythonReason = 'clear-disabled'
            if ($ClearInputOnFailure) {
                $clearBeforePythonFallback = Invoke-ChatInputClearBestEffort -AhkExecutable $AhkExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -PreferredRestoreWindowHandles $pythonRestoreHandlesForFallback -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $false
                $clearBeforePythonReason = Convert-ToSingleLineText -Text ([string]$clearBeforePythonFallback.reason)
                if ([string]::IsNullOrWhiteSpace($clearBeforePythonReason)) {
                    $clearBeforePythonReason = if ([bool]$clearBeforePythonFallback.cleared) { 'clear-ok' } else { 'clear-unknown' }
                }
            }

            if ($CrossSenderFallbackEnabled) {
                $ahkReady = (-not [string]::IsNullOrWhiteSpace($AhkExecutable)) -and (Test-Path -LiteralPath $AhkExecutable)
                if ($ahkReady) {
                    $ahkFallback = Invoke-AhkChatDispatch -AhkExecutable $AhkExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -HeartbeatTimeoutRequireCodeFocus $HeartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $StatusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -PreferredRestoreWindowHandles $pythonRestoreHandlesForFallback -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $true

                    $ahkReason = Convert-ToSingleLineText -Text ([string]$ahkFallback.reason)
                    if ([string]::IsNullOrWhiteSpace($pythonReason)) {
                        $pythonReason = 'python-unsent'
                    }
                    if ([string]::IsNullOrWhiteSpace($ahkReason)) {
                        $ahkReason = 'fallback-unsent'
                    }

                    if (-not [bool]$ahkFallback.sent) {
                        if ($ClearInputOnFailure) {
                            $clearAfterPythonFallback = Invoke-ChatInputClearBestEffort -AhkExecutable $AhkExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -PreferredRestoreWindowHandles $pythonRestoreHandlesForFallback -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $true
                            $clearAfterPythonReason = Convert-ToSingleLineText -Text ([string]$clearAfterPythonFallback.reason)
                            if ([string]::IsNullOrWhiteSpace($clearAfterPythonReason)) {
                                $clearAfterPythonReason = if ([bool]$clearAfterPythonFallback.cleared) { 'clear-ok' } else { 'clear-unknown' }
                            }
                            $ahkFallback.reason = ('python-unsent-fallback python_reason={0};ahk_reason={1};pre_clear={2};post_clear={3}' -f $pythonReason, $ahkReason, $clearBeforePythonReason, $clearAfterPythonReason)
                        }
                        else {
                            $ahkFallback.reason = ('python-unsent-fallback python_reason={0};ahk_reason={1};pre_clear={2}' -f $pythonReason, $ahkReason, $clearBeforePythonReason)
                        }
                    }
                    else {
                        $ahkFallback.reason = ('python-unsent-fallback python_reason={0};ahk_reason={1};pre_clear={2}' -f $pythonReason, $ahkReason, $clearBeforePythonReason)
                    }
                    return $ahkFallback
                }

                $pythonResult.reason = if ([string]::IsNullOrWhiteSpace($pythonReason)) {
                    'python-unsent;ahk-fallback-unavailable;pre_clear={0}' -f $clearBeforePythonReason
                }
                else {
                    '{0};ahk-fallback-unavailable;pre_clear={1}' -f $pythonReason, $clearBeforePythonReason
                }
            }
            else {
                $pythonResult.reason = if ([string]::IsNullOrWhiteSpace($pythonReason)) {
                    'python-unsent;fallback-disabled;pre_clear={0}' -f $clearBeforePythonReason
                }
                else {
                    '{0};fallback-disabled;pre_clear={1}' -f $pythonReason, $clearBeforePythonReason
                }
            }
        }

        if ($ClearInputOnFailure -and -not [bool]$pythonResult.sent) {
            $pythonReasonForFinalClear = Convert-ToSingleLineText -Text ([string]$pythonResult.reason)
            if (-not $pythonReasonForFinalClear.ToLowerInvariant().Contains('pre_clear=')) {
                $clearFinalPython = Invoke-ChatInputClearBestEffort -AhkExecutable $AhkExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -PreferredRestoreWindowHandles $pythonRestoreHandlesForFallback -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $false
                $clearFinalPythonReason = Convert-ToSingleLineText -Text ([string]$clearFinalPython.reason)
                if ([string]::IsNullOrWhiteSpace($clearFinalPythonReason)) {
                    $clearFinalPythonReason = if ([bool]$clearFinalPython.cleared) { 'clear-ok' } else { 'clear-unknown' }
                }
                $pythonResult.reason = if ([string]::IsNullOrWhiteSpace($pythonReasonForFinalClear)) {
                    'python-unsent;final_clear={0}' -f $clearFinalPythonReason
                }
                else {
                    '{0};final_clear={1}' -f $pythonReasonForFinalClear, $clearFinalPythonReason
                }
            }
        }

        return $pythonResult
    }

    $ahkPrimary = Invoke-AhkChatDispatch -AhkExecutable $AhkExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -HeartbeatTimeoutRequireCodeFocus $HeartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $StatusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $ForceFocusRecovery

    if ([bool]$ahkPrimary.sent) {
        return $ahkPrimary
    }

    $ahkRestoreHandlesForFallback = Convert-ToWindowHandleCsv -Value (Get-ObjectMemberValue -Container $ahkPrimary -MemberName 'restore_previous_window_handles')
    if ([string]::IsNullOrWhiteSpace($ahkRestoreHandlesForFallback)) {
        $ahkCodeFocusPolicy = Get-ObjectMemberValue -Container $ahkPrimary -MemberName 'code_focus_policy'
        if ($null -ne $ahkCodeFocusPolicy) {
            $ahkRestoreHandlesForFallback = Convert-ToWindowHandleCsv -Value (Get-ObjectMemberValue -Container $ahkCodeFocusPolicy -MemberName 'restore_previous_window_handles')
        }
    }

    $clearBeforeAhkReason = 'clear-disabled'
    if ($ClearInputOnFailure) {
        $clearBeforeAhkFallback = Invoke-ChatInputClearBestEffort -AhkExecutable $AhkExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -PreferredRestoreWindowHandles $ahkRestoreHandlesForFallback -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $false
        $clearBeforeAhkReason = Convert-ToSingleLineText -Text ([string]$clearBeforeAhkFallback.reason)
        if ([string]::IsNullOrWhiteSpace($clearBeforeAhkReason)) {
            $clearBeforeAhkReason = if ([bool]$clearBeforeAhkFallback.cleared) { 'clear-ok' } else { 'clear-unknown' }
        }
    }

    $ahkReason = Convert-ToSingleLineText -Text ([string]$ahkPrimary.reason)
    if ([string]::IsNullOrWhiteSpace($ahkReason)) {
        $ahkReason = 'ahk-unsent'
    }

    if (-not $CrossSenderFallbackEnabled) {
        $ahkPrimary.reason = '{0};fallback-disabled;pre_clear={1}' -f $ahkReason, $clearBeforeAhkReason
        return $ahkPrimary
    }

    $pythonReady = (-not [string]::IsNullOrWhiteSpace($PythonExecutable)) -and (Test-Path -LiteralPath $PythonExecutable)
    if (-not $pythonReady) {
        $ahkPrimary.reason = '{0};python-fallback-unavailable;pre_clear={1}' -f $ahkReason, $clearBeforeAhkReason
        return $ahkPrimary
    }

    $eventNormalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    $shouldFallbackToPython = $eventNormalized -in @(
        'running-status-report',
        'chat-session-final-status',
        'incident-captured',
        'recovery-await-confirmation',
        'auto-fix-await-confirmation',
        'task-definition-fix-required',
        'main-process-exit-review',
        'manual-wait-paused',
        'budget-exhausted-stop',
        'known-infra-transient-stop',
        'a-pass-conclusion-b-started'
    )

    if (-not $shouldFallbackToPython) {
        $ahkPrimary.reason = '{0};python-fallback-not-applicable;pre_clear={1}' -f $ahkReason, $clearBeforeAhkReason
        return $ahkPrimary
    }

    $pythonFallback = Invoke-PythonChatDispatch -PythonExecutable $PythonExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -StatusReportAllowInconclusiveSubmit $StatusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -PreferredRestoreWindowHandles $ahkRestoreHandlesForFallback -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $true

    $pythonReason = Convert-ToSingleLineText -Text ([string]$pythonFallback.reason)
    if ([string]::IsNullOrWhiteSpace($pythonReason)) {
        $pythonReason = 'fallback-unsent'
    }

    if (-not [bool]$pythonFallback.sent) {
        if ($ClearInputOnFailure) {
            $clearAfterAhkFallback = Invoke-ChatInputClearBestEffort -AhkExecutable $AhkExecutable -Message $Message -TicketId $TicketId -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -PreferredRestoreWindowHandles $ahkRestoreHandlesForFallback -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $true
            $clearAfterAhkReason = Convert-ToSingleLineText -Text ([string]$clearAfterAhkFallback.reason)
            if ([string]::IsNullOrWhiteSpace($clearAfterAhkReason)) {
                $clearAfterAhkReason = if ([bool]$clearAfterAhkFallback.cleared) { 'clear-ok' } else { 'clear-unknown' }
            }
            $pythonFallback.reason = ('ahk-unsent-fallback ahk_reason={0};python_reason={1};pre_clear={2};post_clear={3}' -f $ahkReason, $pythonReason, $clearBeforeAhkReason, $clearAfterAhkReason)
        }
        else {
            $pythonFallback.reason = ('ahk-unsent-fallback ahk_reason={0};python_reason={1};pre_clear={2}' -f $ahkReason, $pythonReason, $clearBeforeAhkReason)
        }
    }
    else {
        $pythonFallback.reason = ('ahk-unsent-fallback ahk_reason={0};python_reason={1};pre_clear={2}' -f $ahkReason, $pythonReason, $clearBeforeAhkReason)
    }
    return $pythonFallback
}

function Write-DispatchLog {
    param([string]$Message)

    $line = "[CHAT-DISPATCH] timestamp={0} {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), (Convert-ToSingleLineText -Text $Message)
    Write-Information $line -InformationAction Continue

    try {
        Add-Utf8Line -Path $script:DispatchLogPath -Line $line
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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param([int[]]$ProcessIds)

    $stopped = New-Object 'System.Collections.Generic.List[int]'
    foreach ($processId in @($ProcessIds)) {
        if ($processId -le 0) {
            continue
        }

        try {
            if ($PSCmdlet.ShouldProcess(("PID {0}" -f $processId), 'Stop-Process -Force')) {
                Stop-Process -Id $processId -Force -ErrorAction Stop
                [void]$stopped.Add($processId)
            }
        }
        catch {
            Write-Verbose ("Stop-ProcessListBestEffort failed for pid={0}: {1}" -f $processId, $_.Exception.Message)
        }
    }

    return $stopped.ToArray()
}

try {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Assert-Ps51Utf8BomCompatibility -ScriptPath $MyInvocation.MyCommand.Path -ScriptRole 'dispatch_takeover_to_chat.ps1'
    $dispatchRoot = Join-Path $script:RepoRoot 'out\artifacts\ab_agent_queue\chat_dispatch'
    New-Item -ItemType Directory -Path $dispatchRoot -Force | Out-Null

$startFilePath = Resolve-RepoPathAllowMissing -Path $StartFile
$startToken = Get-StableStartFileToken -StartFilePath $startFilePath
$legacyStartToken = Get-LegacyStartFileToken -StartFilePath $startFilePath -PreserveCase
$script:DispatchLogPath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $dispatchRoot ("dispatch_{0}.log" -f $startToken)) -LegacyPath (Join-Path $dispatchRoot ("dispatch_{0}.log" -f $legacyStartToken))

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

$useIpcDispatch = $UseIpcSender.IsPresent
$usePythonDispatch = $UsePythonSender.IsPresent
$useAhkDispatch = $UseAhk.IsPresent

$senderPrimary = ''
if ($startSettings.Contains('AI_CHAT_DISPATCH_SENDER_PRIMARY')) {
    $senderPrimary = (Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_DISPATCH_SENDER_PRIMARY)).ToLowerInvariant()
}
elseif ($startSettings.Contains('AI_CHAT_POLICY_DELIVERY_PRIMARY')) {
    $senderPrimary = (Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_POLICY_DELIVERY_PRIMARY)).ToLowerInvariant()
}

if (-not $useIpcDispatch -and -not $usePythonDispatch -and -not $useAhkDispatch) {
    if ($senderPrimary -in @('ipc')) {
        $useIpcDispatch = $true
        $usePythonDispatch = $false
        $useAhkDispatch = $false
    }
    elseif ($senderPrimary -in @('python', 'py', 'pywinauto')) {
        $useIpcDispatch = $false
        $usePythonDispatch = $true
        $useAhkDispatch = $false
    }
    elseif ($senderPrimary -in @('ahk', 'autohotkey')) {
        $useIpcDispatch = $false
        $usePythonDispatch = $false
        $useAhkDispatch = $true
    }
}

if (-not $useIpcDispatch -and -not $usePythonDispatch -and -not $useAhkDispatch -and $startSettings.Contains('AI_CHAT_DISPATCH_USE_IPC')) {
    $useIpcDispatch = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_USE_IPC) -Default $false
}

if (-not $useIpcDispatch -and -not $usePythonDispatch -and -not $useAhkDispatch -and $startSettings.Contains('AI_CHAT_DISPATCH_USE_PY_SENDER')) {
    $usePythonDispatch = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_USE_PY_SENDER) -Default $false
}

if (-not $useIpcDispatch -and -not $usePythonDispatch -and -not $useAhkDispatch -and $startSettings.Contains('AI_CHAT_DISPATCH_USE_AHK')) {
    $useAhkDispatch = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_USE_AHK) -Default $false
}

if ($useIpcDispatch) {
    $usePythonDispatch = $false
    $useAhkDispatch = $false
}
elseif ($usePythonDispatch -and $useAhkDispatch) {
    $useAhkDispatch = $false
}

if (-not $useIpcDispatch -and -not $usePythonDispatch -and -not $useAhkDispatch) {
    if ($senderPrimary -in @('python', 'py', 'pywinauto')) {
        $useIpcDispatch = $false
        $usePythonDispatch = $true
        $useAhkDispatch = $false
    }
    elseif ($senderPrimary -in @('ahk', 'autohotkey')) {
        $useIpcDispatch = $false
        $usePythonDispatch = $false
        $useAhkDispatch = $true
    }
}

$senderFallbackEnabled = $true
if ($startSettings.Contains('AI_CHAT_DISPATCH_SENDER_FALLBACK_ENABLED')) {
    $senderFallbackEnabled = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_SENDER_FALLBACK_ENABLED) -Default $true
}
elseif ($startSettings.Contains('AI_CHAT_POLICY_DELIVERY_FALLBACK')) {
    $fallbackMode = (Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_POLICY_DELIVERY_FALLBACK)).ToLowerInvariant()
    if ($fallbackMode -in @('off', 'false', '0', 'disabled')) {
        $senderFallbackEnabled = $false
    }
}

$clearInputOnFailure = $true
if ($startSettings.Contains('AI_CHAT_DISPATCH_CLEAR_INPUT_ON_FAILURE')) {
    $clearInputOnFailure = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_CLEAR_INPUT_ON_FAILURE) -Default $true
}

$ipcDispatchMode = 'Visible'
if ($startSettings.Contains('AI_CHAT_DISPATCH_IPC_MODE')) {
    $ipcModeToken = (Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_DISPATCH_IPC_MODE)).ToLowerInvariant()
    switch ($ipcModeToken) {
        'silent' { $ipcDispatchMode = 'Silent' }
        'auto' { $ipcDispatchMode = 'Auto' }
        default { $ipcDispatchMode = 'Visible' }
    }
}

$configuredAhkPath = $AhkExePath
$strictConfiguredAhkPath = -not [string]::IsNullOrWhiteSpace((Convert-ToSingleLineText -Text $AhkExePath))
if ([string]::IsNullOrWhiteSpace($configuredAhkPath) -and $startSettings.Contains('AI_CHAT_DISPATCH_AHK_EXE')) {
    $configuredAhkPath = [string]$startSettings.AI_CHAT_DISPATCH_AHK_EXE
    $strictConfiguredAhkPath = $false
}

$configuredPythonPath = $PythonExePath
$strictConfiguredPythonPath = -not [string]::IsNullOrWhiteSpace((Convert-ToSingleLineText -Text $PythonExePath))
if ([string]::IsNullOrWhiteSpace($configuredPythonPath) -and $startSettings.Contains('AI_CHAT_DISPATCH_PYTHON_EXE')) {
    $configuredPythonPath = [string]$startSettings.AI_CHAT_DISPATCH_PYTHON_EXE
    $strictConfiguredPythonPath = $false
}

$ahkExecutable = ''
$resolveAhkExecutable = $useAhkDispatch -or $usePythonDispatch
if ($resolveAhkExecutable) {
    $ahkExecutable = Resolve-AhkExecutablePath -ConfiguredPath $configuredAhkPath -StrictConfiguredPath:$strictConfiguredAhkPath
    if ([string]::IsNullOrWhiteSpace($ahkExecutable)) {
        if ($strictConfiguredAhkPath) {
            if ($useAhkDispatch) {
                Write-DispatchLog ("ahk_dispatch_enabled_but_configured_executable_missing configured_path={0}" -f (Convert-ToSingleLineText -Text $configuredAhkPath))
            }
            else {
                Write-DispatchLog ("python_dispatch_ahk_fallback_configured_executable_missing configured_path={0}" -f (Convert-ToSingleLineText -Text $configuredAhkPath))
            }
        }
        else {
            if ($useAhkDispatch) {
                Write-DispatchLog 'ahk_dispatch_enabled_but_executable_missing'
            }
            else {
                Write-DispatchLog 'python_dispatch_ahk_fallback_executable_missing'
            }
        }
    }
}

$pythonExecutable = ''
$resolvePythonExecutable = $usePythonDispatch -or ($useAhkDispatch -and $senderFallbackEnabled)
if ($resolvePythonExecutable) {
    $pythonExecutable = Resolve-PythonExecutablePath -ConfiguredPath $configuredPythonPath -StrictConfiguredPath:$strictConfiguredPythonPath
    if ([string]::IsNullOrWhiteSpace($pythonExecutable)) {
        if ($strictConfiguredPythonPath) {
            Write-DispatchLog ("python_dispatch_enabled_but_configured_executable_missing configured_path={0}" -f (Convert-ToSingleLineText -Text $configuredPythonPath))
        }
        else {
            if ($usePythonDispatch) {
                Write-DispatchLog 'python_dispatch_enabled_but_executable_missing'
            }
            else {
                Write-DispatchLog 'ahk_dispatch_python_fallback_executable_missing'
            }
        }
    }
}

$dispatchSenderMode = if ($useIpcDispatch) { 'ipc' } elseif ($usePythonDispatch) { 'python' } elseif ($useAhkDispatch) { 'ahk' } else { 'none' }
$interactiveDispatchEnabled = $dispatchSenderMode -ne 'none'
Write-DispatchLog ("dispatch_sender_config mode={0} use_ipc={1} use_ahk={2} use_python={3} ipc_mode={4} sender_fallback_enabled={5} clear_input_on_failure={6} sender_primary_hint={7} ahk_exe={8} python_exe={9}" -f $dispatchSenderMode, $useIpcDispatch, $useAhkDispatch, $usePythonDispatch, $ipcDispatchMode, $senderFallbackEnabled, $clearInputOnFailure, $senderPrimary, (Convert-ToSingleLineText -Text $ahkExecutable), (Convert-ToSingleLineText -Text $pythonExecutable))

$queueFilePath = if ([string]::IsNullOrWhiteSpace($QueuePath)) {
    Resolve-RepoPathAllowMissing -Path 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
}
else {
    Resolve-RepoPathAllowMissing -Path $QueuePath
}

$briefFilePath = Resolve-RepoPathAllowMissing -Path $BriefPath
$briefExists = (-not [string]::IsNullOrWhiteSpace($briefFilePath)) -and (Test-Path -LiteralPath $briefFilePath)
$briefSettings = [ordered]@{}
if ($briefExists) {
    try {
        $briefSettings = Read-KeyValueFile -Path $briefFilePath
    }
    catch {
        Write-DispatchLog ("brief_file_parse_failed path={0} detail={1}" -f (Convert-ToRepoRelativePath -Path $briefFilePath), (Convert-ToSingleLineText -Text $_.Exception.Message))
    }
}

$atomicCloseoutCommand = ''
if ($briefSettings.Contains('atomic_closeout_command')) {
    $atomicCloseoutCommand = Convert-ToSingleLineText -Text ([string]$briefSettings.atomic_closeout_command)
}
$recoveryTransactionCommand = ''
if ($briefSettings.Contains('recovery_transaction_command')) {
    $recoveryTransactionCommand = Convert-ToSingleLineText -Text ([string]$briefSettings.recovery_transaction_command)
}

$ticketEventOriginal = Convert-ToSingleLineText -Text $TicketEvent
$ticketEventResolved = $ticketEventOriginal
$ticketEventSource = ''

if ([string]::IsNullOrWhiteSpace($ticketEventResolved) -and $briefSettings.Contains('event')) {
    $eventFromBrief = Convert-ToSingleLineText -Text ([string]$briefSettings.event)
    if (-not [string]::IsNullOrWhiteSpace($eventFromBrief)) {
        $ticketEventResolved = $eventFromBrief
        $ticketEventSource = 'brief'
    }
}

if ([string]::IsNullOrWhiteSpace($ticketEventResolved)) {
    $eventFromQueue = Resolve-TicketEventFromQueue -TicketId $TicketId -QueuePath $queueFilePath
    if (-not [string]::IsNullOrWhiteSpace($eventFromQueue)) {
        $ticketEventResolved = $eventFromQueue
        $ticketEventSource = 'queue'
    }
}

if (-not [string]::IsNullOrWhiteSpace($ticketEventResolved)) {
    $TicketEvent = $ticketEventResolved
    if (-not [string]::IsNullOrWhiteSpace($ticketEventSource) -and [string]::IsNullOrWhiteSpace($ticketEventOriginal)) {
        Write-DispatchLog ("ticket_event_autofilled ticket={0} source={1} event={2}" -f $TicketId, $ticketEventSource, $TicketEvent)
    }
}
else {
    Write-DispatchLog ("ticket_event_missing ticket={0} source=none" -f $TicketId)
}

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
$statusReportMessageMode = 'alternate'
if ($startSettings.Contains('AI_CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE')) {
    $statusReportMessageMode = Get-EnumSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE) -Allowed @('short', 'full', 'alternate') -Default 'alternate'
}
$statusReportSendFullOnFirst = $true
if ($startSettings.Contains('AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST')) {
    $statusReportSendFullOnFirst = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST) -Default $true
}
$statusReportAllowInconclusiveSubmit = $true
if ($startSettings.Contains('AI_CHAT_DISPATCH_STATUS_REPORT_ALLOW_INCONCLUSIVE_SUBMIT')) {
    $statusReportAllowInconclusiveSubmit = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_STATUS_REPORT_ALLOW_INCONCLUSIVE_SUBMIT) -Default $true
}
$allowRunningStatusMessageOverride = $false
if ($startSettings.Contains('AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE')) {
    $allowRunningStatusMessageOverride = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE) -Default $false
}
$dispatchMessageLocale = 'zh-cn'
if ($startSettings.Contains('AI_CHAT_DISPATCH_MESSAGE_LOCALE')) {
    $dispatchMessageLocale = Get-EnumSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_MESSAGE_LOCALE) -Allowed @('zh-cn', 'zh', 'en-us', 'en') -Default 'zh-cn'
}
$dispatchMessageLocale = if ($dispatchMessageLocale -eq 'zh') {
    'zh-cn'
}
elseif ($dispatchMessageLocale -eq 'en') {
    'en-us'
}
else {
    $dispatchMessageLocale
}
$useChineseDispatchMessage = $dispatchMessageLocale.StartsWith('zh', [System.StringComparison]::OrdinalIgnoreCase)
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
$restorePreviousForegroundWindowCount = 12
if ($startSettings.Contains('AI_CHAT_DISPATCH_RESTORE_PREVIOUS_WINDOW_COUNT')) {
    $restorePreviousForegroundWindowCount = Convert-ToIntRangeSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_RESTORE_PREVIOUS_WINDOW_COUNT) -Default 12 -Min 1 -Max 30
}
$statusReportMessageStatePath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $dispatchRoot ("status_report_message_state_{0}.json" -f $startToken)) -LegacyPath (Join-Path $dispatchRoot ("status_report_message_state_{0}.json" -f $legacyStartToken))
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

$interactivePreActionsEnabled = $true
if ($startSettings.Contains('AI_CHAT_DISPATCH_INTERACTIVE_PRE_ACTIONS_ENABLED')) {
    $interactivePreActionsEnabled = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_INTERACTIVE_PRE_ACTIONS_ENABLED) -Default $true
}
elseif ($dispatchSenderMode -eq 'ipc') {
    $interactivePreActionsEnabled = $false
}

$runInteractivePreActions = (-not $suppressInteractiveActions) -and $interactivePreActionsEnabled

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

$resumeSessionStatus = $sessionStatus
if ($briefSettings.Contains('session_final_status')) {
    $briefSessionStatus = (Convert-ToSingleLineText -Text ([string]$briefSettings.session_final_status)).ToUpperInvariant()
    if (-not [string]::IsNullOrWhiteSpace($briefSessionStatus)) {
        $resumeSessionStatus = $briefSessionStatus
    }
}

$resumeAStatus = $aStatus
if ($briefSettings.Contains('a_final_status')) {
    $briefAStatus = (Convert-ToSingleLineText -Text ([string]$briefSettings.a_final_status)).ToUpperInvariant()
    if (-not [string]::IsNullOrWhiteSpace($briefAStatus)) {
        $resumeAStatus = $briefAStatus
    }
}

$resumeBStatus = $bStatus
if ($briefSettings.Contains('b_final_status')) {
    $briefBStatus = (Convert-ToSingleLineText -Text ([string]$briefSettings.b_final_status)).ToUpperInvariant()
    if (-not [string]::IsNullOrWhiteSpace($briefBStatus)) {
        $resumeBStatus = $briefBStatus
    }
}

$resumePreferredStage = ''
if ($briefSettings.Contains('preferred_stage')) {
    $resumePreferredStage = (Convert-ToSingleLineText -Text ([string]$briefSettings.preferred_stage)).ToUpperInvariant()
}
$routeGuardExpected = ''
$routeGuardExpectedSource = 'fallback'
$routeGuardLiveClassification = ''
$routeGuardLiveProbeReason = ''
$routeGuardCommand = ''
if ($briefSettings.Contains('route_guard_command')) {
    $routeGuardCommand = Convert-ToSingleLineText -Text ([string]$briefSettings.route_guard_command)
}
if ($briefSettings.Contains('route_guard_expected')) {
    $routeGuardExpected = (Convert-ToSingleLineText -Text ([string]$briefSettings.route_guard_expected)).ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($routeGuardExpected)) {
        $routeGuardExpectedSource = 'brief'
    }
}
if (-not [string]::IsNullOrWhiteSpace($routeGuardCommand)) {
    $routeGuardLiveResult = Invoke-RouteGuardLiveClassification -RouteGuardCommand $routeGuardCommand
    $routeGuardLiveProbeReason = Convert-ToSingleLineText -Text ([string]$routeGuardLiveResult.reason)
    if ([bool]$routeGuardLiveResult.success) {
        $routeGuardLiveClassification = Convert-ToSingleLineText -Text ([string]$routeGuardLiveResult.classification)
        if (-not [string]::IsNullOrWhiteSpace($routeGuardLiveClassification)) {
            if (-not [string]::IsNullOrWhiteSpace($routeGuardExpected) -and $routeGuardExpected -ne $routeGuardLiveClassification) {
                Write-DispatchLog ("route_guard_expected_overridden ticket={0} brief={1} live={2}" -f $TicketId, $routeGuardExpected, $routeGuardLiveClassification)
            }
            $routeGuardExpected = $routeGuardLiveClassification
            $routeGuardExpectedSource = 'live'
        }
    }
    else {
        Write-DispatchLog ("route_guard_live_probe_failed ticket={0} reason={1}" -f $TicketId, $routeGuardLiveProbeReason)
    }
}
$scriptSelfHealEnabled = $false
if ($startSettings.Contains('LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED')) {
    $scriptSelfHealEnabled = Convert-ToBooleanSetting -Value ([string]$startSettings.LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED) -Default $false
}
$taskStaticCrossRoundRepairEnabled = $false
if ($startSettings.Contains('TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED')) {
    $taskStaticCrossRoundRepairEnabled = Convert-ToBooleanSetting -Value ([string]$startSettings.TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED) -Default $false
}
if ($briefSettings.Contains('task_static_cross_round_repair_enabled')) {
    $briefTaskStaticCrossRoundRepairEnabled = Convert-ToBooleanSetting -Value ([string]$briefSettings.task_static_cross_round_repair_enabled) -Default $false
    $taskStaticCrossRoundRepairEnabled = $briefTaskStaticCrossRoundRepairEnabled
}
else {
    $taskStaticCrossRoundRepairEnabled = $false
}
if (-not $scriptSelfHealEnabled -and $routeGuardExpected -in @('incident-auto-resume-script-fix', 'incident-manual-script-fix')) {
    Write-DispatchLog ("route_guard_expected_fail_closed ticket={0} previous={1} current=incident-script-diagnose-only source=start-file-policy" -f $TicketId, $routeGuardExpected)
    $routeGuardExpected = 'incident-script-diagnose-only'
    $routeGuardExpectedSource = 'start-file-policy'
}
$eventQueueIdempotentPolicy = ''
if ($briefSettings.Contains('event_queue_idempotent_policy')) {
    $eventQueueIdempotentPolicy = Convert-ToSingleLineText -Text ([string]$briefSettings.event_queue_idempotent_policy)
}
$eventQueueScopeRule = ''
if ($briefSettings.Contains('event_queue_scope_rule')) {
    $eventQueueScopeRule = Convert-ToSingleLineText -Text ([string]$briefSettings.event_queue_scope_rule)
}
$briefMainRound = ''
if ($briefSettings.Contains('main_round')) {
    $briefMainRound = Convert-ToSingleLineText -Text ([string]$briefSettings.main_round)
}
$briefFailurePhase = ''
if ($briefSettings.Contains('failure_phase')) {
    $briefFailurePhase = Convert-ToSingleLineText -Text ([string]$briefSettings.failure_phase)
}
$briefFailureKind = ''
if ($briefSettings.Contains('failure_kind')) {
    $briefFailureKind = Convert-ToSingleLineText -Text ([string]$briefSettings.failure_kind)
}
$modeRestorePolicy = ''
if ($briefSettings.Contains('mode_restore_policy')) {
    $modeRestorePolicy = Convert-ToSingleLineText -Text ([string]$briefSettings.mode_restore_policy)
}
$briefDetail = ''
if ($briefSettings.Contains('detail')) {
    $briefDetail = Convert-ToSingleLineText -Text ([string]$briefSettings.detail)
}
$reviewContentRequirements = if ($briefSettings.Contains('review_content_requirements')) { Convert-ToSingleLineText -Text ([string]$briefSettings.review_content_requirements) } else { '' }
$summaryContentRequirements = if ($briefSettings.Contains('summary_content_requirements')) { Convert-ToSingleLineText -Text ([string]$briefSettings.summary_content_requirements) } else { '' }
$sessionInitialLaunchAt = if ($briefSettings.Contains('session_initial_launch_at')) { Convert-ToSingleLineText -Text ([string]$briefSettings.session_initial_launch_at) } else { '' }
$aStageCompletedAt = if ($briefSettings.Contains('a_stage_completed_at')) { Convert-ToSingleLineText -Text ([string]$briefSettings.a_stage_completed_at) } else { '' }
$aStageElapsed = if ($briefSettings.Contains('a_stage_elapsed')) { Convert-ToSingleLineText -Text ([string]$briefSettings.a_stage_elapsed) } else { '' }
$bStageFirstStartAt = if ($briefSettings.Contains('b_stage_first_start_at')) { Convert-ToSingleLineText -Text ([string]$briefSettings.b_stage_first_start_at) } else { '' }
$bStageCompletedAt = if ($briefSettings.Contains('b_stage_completed_at')) { Convert-ToSingleLineText -Text ([string]$briefSettings.b_stage_completed_at) } else { '' }
$bStageElapsed = if ($briefSettings.Contains('b_stage_elapsed')) { Convert-ToSingleLineText -Text ([string]$briefSettings.b_stage_elapsed) } else { '' }
$abTotalElapsed = if ($briefSettings.Contains('ab_total_elapsed')) { Convert-ToSingleLineText -Text ([string]$briefSettings.ab_total_elapsed) } else { '' }
$briefDetailLower = $briefDetail.ToLowerInvariant()
$retryBudgetOneTimeOnly = ($briefDetail.ToLowerInvariant().Contains('one_time_retry_only=true'))
$retryBudgetExhausted = ($briefDetail.ToLowerInvariant().Contains('retry_budget_exhausted=true'))
$fingerprintDuplicateDetected = ($briefDetailLower.Contains('fingerprint_duplicate=true'))
$retryRequiresEvidence = ($briefDetailLower.Contains('retry_requires_evidence=true'))

$retryCountValue = ''
$retryLimitValue = ''
if (-not [string]::IsNullOrWhiteSpace($briefDetail)) {
    $retryCountMatch = [regex]::Match($briefDetail, '(?i)\bretry_count\s*=\s*([0-9]+)')
    if ($retryCountMatch.Success) {
        $retryCountValue = Convert-ToSingleLineText -Text $retryCountMatch.Groups[1].Value
    }
    $retryLimitMatch = [regex]::Match($briefDetail, '(?i)\bretry_limit\s*=\s*([0-9]+)')
    if ($retryLimitMatch.Success) {
        $retryLimitValue = Convert-ToSingleLineText -Text $retryLimitMatch.Groups[1].Value
    }
}

$fingerprintHintEn = ''
$fingerprintHintZh = ''
if ($fingerprintDuplicateDetected) {
    $budgetHintEn = ''
    $budgetHintZh = ''
    if (-not [string]::IsNullOrWhiteSpace($retryCountValue) -and -not [string]::IsNullOrWhiteSpace($retryLimitValue)) {
        $budgetHintEn = (' Current retry budget: {0}/{1}.' -f $retryCountValue, $retryLimitValue)
        $budgetHintZh = (' 当前重试预算：{0}/{1}。' -f $retryCountValue, $retryLimitValue)
    }

    $evidenceHintEn = if ($retryRequiresEvidence) {
        ' Next retry requires evidence-changing edits (taskdef hash/round imprint/source summary change).'
    }
    else {
        ''
    }
    $evidenceHintZh = if ($retryRequiresEvidence) {
        ' 下一次重试必须给出“证据变化型”修改（taskdef 哈希/轮次印记/源码摘要变化）。'
    }
    else {
        ''
    }

    if ($retryBudgetExhausted) {
        $fingerprintHintEn = ('Fingerprint duplicate reached retry hard-block. Do NOT repeat prior patch shape; switch repair strategy (rewrite round op anchors/order or append-mode patch), pass static check, then relaunch manually only when gate allows.{0}{1}' -f $budgetHintEn, $evidenceHintEn)
        $fingerprintHintZh = ('检测到相同指纹且已进入重试硬阻断。禁止重复上一轮补丁形态；必须切换修复策略（重写轮次 op 锚点/顺序或采用追加补丁），静态检查通过后再按门禁允许进行人工重启。{0}{1}' -f $budgetHintZh, $evidenceHintZh)
    }
    else {
        $fingerprintHintEn = ('Fingerprint duplicate detected (same failure point). AI must improve repair method instead of repeating similar edits; prefer anchor/order redesign or append-mode patch with verifiable evidence change.{0}{1}' -f $budgetHintEn, $evidenceHintEn)
        $fingerprintHintZh = ('检测到相同指纹（同一故障点重复）。AI 必须改进修复方法，不能重复相似改动；优先采用锚点/顺序重设计或追加式补丁，并确保产生可验证证据变化。{0}{1}' -f $budgetHintZh, $evidenceHintZh)
    }
}
$sessionClosedByFlagRaw = $false
if ($startSettings.Contains('SESSION_CLOSED')) {
    $sessionClosedByFlagRaw = Convert-ToBooleanSetting -Value ([string]$startSettings.SESSION_CLOSED) -Default $false
}
$sessionClosedByPassFinal = ($sessionStatus -eq 'PASS') -or ($aStatus -eq 'PASS' -and $bStatus -eq 'PASS')
$sessionClosedByFlag = $sessionClosedByFlagRaw -and $sessionClosedByPassFinal

$dispatchAnchors = Get-DispatchAnchorMap -Settings $startSettings

$guardLogPath = Resolve-RepoPathAllowMissing -Path ([string]$dispatchAnchors.guard_log)
if ([string]::IsNullOrWhiteSpace($guardLogPath) -or -not (Test-Path -LiteralPath $guardLogPath)) {
    $guardLogPath = Get-LatestArtifactFilePath -RootRelative 'out\artifacts\ab_session_guard' -FileName 'guard.log'
}

$guardStatePath = Resolve-RepoPathAllowMissing -Path ([string]$dispatchAnchors.guard_state)
if ([string]::IsNullOrWhiteSpace($guardStatePath) -or -not (Test-Path -LiteralPath $guardStatePath)) {
    $guardStatePath = Get-LatestArtifactFilePath -RootRelative 'out\artifacts\ab_session_guard' -FileName 'guard_state.json'
}

$liveStatusPath = Resolve-RepoPathAllowMissing -Path ([string]$dispatchAnchors.live_status)
if ([string]::IsNullOrWhiteSpace($liveStatusPath) -or -not (Test-Path -LiteralPath $liveStatusPath)) {
    $liveStatusPath = Get-LatestArtifactFilePath -RootRelative 'out\artifacts\ab_session_guard' -FileName 'live_status.json'
}

$runningStatusRunDirRaw = Convert-ToSingleLineText -Text ([string]$dispatchAnchors.run_dir)
if ([string]::IsNullOrWhiteSpace($runningStatusRunDirRaw) -and -not [string]::IsNullOrWhiteSpace($guardStatePath) -and (Test-Path -LiteralPath $guardStatePath)) {
    try {
        $guardStatePayload = Get-Content -LiteralPath $guardStatePath -Raw -Encoding utf8 | ConvertFrom-Json
        if ($null -ne $guardStatePayload) {
            $runDirFromState = Convert-ToSingleLineText -Text ([string](Get-ObjectMemberValue -Container $guardStatePayload -MemberName 'run_dir'))
            if (-not [string]::IsNullOrWhiteSpace($runDirFromState)) {
                $runningStatusRunDirRaw = $runDirFromState
            }
        }
    }
    catch {
        $null = $_
    }
}
if ([string]::IsNullOrWhiteSpace($runningStatusRunDirRaw)) {
    $runningStatusRunDirRaw = Get-LatestGuardHeartbeatRunDir -LogPath $guardLogPath
}

$runningStatusRunDirPath = Resolve-RepoPathAllowMissing -Path $runningStatusRunDirRaw
$runningStatusRunDirDisplay = if ([string]::IsNullOrWhiteSpace($runningStatusRunDirPath)) {
    if ([string]::IsNullOrWhiteSpace($runningStatusRunDirRaw)) {
        'unknown'
    }
    else {
        $runningStatusRunDirRaw
    }
}
else {
    Convert-ToRepoRelativePath -Path $runningStatusRunDirPath
}

$runningStatusMainRound = Get-MainProcessRoundDigest -RunDirPath $runningStatusRunDirPath -LiveStatusPath $liveStatusPath

$runningStatusGuardHeartbeat = Get-LatestHeartbeatDigest -Role 'guard' -LogPath $guardLogPath

$runningStatusStateSummary = "SESSION={0}, A={1}, B={2}" -f (Get-CompactStatusToken -Value $sessionStatus), (Get-CompactStatusToken -Value $aStatus), (Get-CompactStatusToken -Value $bStatus)
$runningStatusBExitDigest = Get-StageExitDigest -StageName 'B'
$runningStatusBExitDigestRequired = if ([string]::IsNullOrWhiteSpace($runningStatusBExitDigest)) {
    'B_EXIT=unknown'
}
else {
    $runningStatusBExitDigest
}
$runningStatusHeartbeatSummary = $runningStatusGuardHeartbeat
$runningStatusSummaryParts = New-Object 'System.Collections.Generic.List[string]'
[void]$runningStatusSummaryParts.Add($runningStatusStateSummary)
[void]$runningStatusSummaryParts.Add(("run_dir={0}" -f $runningStatusRunDirDisplay))
[void]$runningStatusSummaryParts.Add(("main_round={0}" -f $runningStatusMainRound))
[void]$runningStatusSummaryParts.Add(("hb={0}" -f $runningStatusHeartbeatSummary))
[void]$runningStatusSummaryParts.Add($runningStatusBExitDigestRequired)
$runningStatusShortSummary = $runningStatusSummaryParts -join '; '

$dispatchReadContextPath = if (-not [string]::IsNullOrWhiteSpace($briefRel)) {
    $briefRel
}
elseif (-not [string]::IsNullOrWhiteSpace($startFileRel)) {
    $startFileRel
}
else {
    'start_file'
}
$dispatchReadContextText = if ([string]::IsNullOrWhiteSpace($queueRel)) {
    $dispatchReadContextPath
}
else {
    '{0} and {1}' -f $dispatchReadContextPath, $queueRel
}

$defaultAhkEventAllowList = @(
    'incident-captured',
    'recovery-await-confirmation',
    'auto-fix-await-confirmation',
    'task-definition-fix-required',
    'main-process-exit-review',
    'manual-wait-paused',
    'budget-exhausted-stop',
    'known-infra-transient-stop',
    'a-pass-conclusion-b-started',
    'chat-session-final-status',
    'running-status-report'
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

$runningStatusFullMessageEn = '[FULL-RUNBOOK][STATUS-REPORT-ONLY] This scheduled running-status-report is observation-only. Use only read-only status commands supplied by the ticket and report current SESSION/A/B state, run_dir, main_round, process/monitor liveness, heartbeat, and pending incident summary. Do not perform self-heal, fault handling, main-process or guard restart, business_resume, source/script/task-definition edits, environment stabilization, or any recovery action. If an abnormal condition is observed, report it and wait for a separate incident ticket. Return handled_at after reporting; return session_closed_at only when stop monitoring is requested or A/B are terminal. Do not commit or push without explicit same-turn authorization. Status: {3}.'
$runningStatusShortMessageEn = '[SHORT-CARD][STATUS-REPORT-ONLY] Scheduled status report only. Report observed SESSION/A/B, main_round, process/monitor liveness, heartbeat, and pending incident summary using read-only checks. Do not self-heal, handle faults, restart processes/guard, run business_resume, edit files, stabilize the environment, or recover anything from this ticket. Report anomalies and wait for a separate incident ticket. Return handled_at. Status: {3}.'
$finalStatusSummaryMessageEn = 'A/B tasks are complete. Please take over ticket {0} (event={1}), read {2} first, then summarize unattended execution and completion (execution window, status-ticket handling, root cause/remediation, key recovery actions, chat_heartbeat, ACK receipts, final conclusion). Include the explicit session end date/time in the final closure message. Status summary: {3}.'
$taskDefinitionFixMessageEn = 'Please take over ticket {0} (event={1}) and read {2} first. Diagnose whether the root cause is a task-static mismatch between the task definition and current source shape, then provide the minimal fix. Only task-static faults and compile/verify faults classified as code may enter this flow; every code-step fault is noncode. Modify only task definition files under testdata with the VS Code apply_patch editing tool; do not change business source code directly. Never use inline Python/PowerShell, redirection, generic string replacement, or a formatter to change task-definition semantics. After editing a task-static fault, run SyntaxOnly, a focused failing-op check when available, and the current failing D round. Then follow task_static_cross_round_repair_enabled from the brief: false stops after the failing round passes; true checks and repairs each later D round in order through D4 before recovery. If the target round is known, name the stage / round / file explicitly (for example, B D4).

Fix placement rules:
    [D1-D4 task-static phase failed: task-definition-mismatch]
        Only forward D rounds are editable: D1 -> D1-D4, D2 -> D2-D4, D3 -> D3-D4, D4 -> D4. Never edit an earlier D round. The source has NOT yet been changed by the failing round. In that round, ops before the failing op are read-only; modify, delete, insert, or append only from the failing op onward. Later allowed D rounds may be adjusted within this forward boundary.
  [D1-D4 code-step phase PASSED, but compile/verify phase failed]
      Only forward D rounds are editable: D1 -> D1-D4, D2 -> D2-D4, D3 -> D3-D4, D4 -> D4. The source HAS already been changed by the failing round: its existing ops are read-only, so append one or more new ops consecutively at the END of that round. Never edit an earlier D round.
  [V1-V4 verify phase (NOT JSON round keys — only D1-D4 exist as rounds)]
      Append the fix as one or more new ops consecutively at the END of D4''s operations array; never create V1-V4 round entries, edit D1-D3, or modify/delete existing D4 content.

{4}

For a task-static fault, run SyntaxOnly first, then validate the current failing op with `tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce -RoundTag <Dn> -OperationIndex <n>` when it is locatable; the checker simulates read-only preceding ops in order. Then run the same current round without -OperationIndex. The independent checker validates one round at a time and stops at the first failed op; code-step only validates and atomically applies the bound artifact. Rerun checker as often as diagnostics require within this repair ticket; these local checks do not consume the identical-fingerprint main-process relaunch budget. For helper forward-declaration repairs, preserve the helper definition, leave exactly one prototype before the first caller, and remove prototypes after the caller or duplicates. Treat single-instance conflict or any regex/worker timeout as a hard restart block. Restart/resume only after every round selected by task_static_cross_round_repair_enabled passes. Restart only the correct stage main process for this ticket by procedure (A issue -> restart A, B issue -> restart B; never guess or switch stages), continue monitoring, and return chat_heartbeat plus a fix conclusion.'
$runningStatusFullWrapMessageEn = 'Please take over ticket {0} (event={1}) and read {2} first. {3} Current status summary: {4}.'
$genericRecoveryMessageEn = 'Please take over ticket {0} (event={1}) and execute recovery by {2}: read {3} first, run route_guard_command from the brief and follow its classification before any action, and execute only commands whose mapped action is in route.allowed_actions (hard whitelist); treat route.blocked_actions as forbidden. Report root cause plus remediation method, and if self-healable without budget/cooldown exhaustion or nonrecoverable environment, trigger business_resume immediately. If the recovery changes a task-definition file, `tools/test/check_task_definition_static.ps1` must pass before any restart/resume. Any stage restart must target only the correct stage main process for this ticket (A issue -> A main process, B issue -> B main process); do not guess, swap stages, or bypass the stage-window entry. After handling, return to read-only monitoring driven by incoming status/incident tickets, and execute only existing repo commands from brief/poll output. Do not create non-tmp scripts, ad-hoc monitoring loops, or extra out-of-band watchdog jobs.'
$eventReviewMessageEn = 'Please take over ticket {0} (event={1}) in EVENT-REVIEW flow: read {3} first, run route_guard_command, and execute only route.allowed_actions. This is not an incident recovery ticket; do not run business_resume/stage restart unless route explicitly allows. Produce contract-aligned review conclusion for this event, return handled_at immediately, then continue read-only ticket-driven watch.'
$eventReviewLowDisturbMessageEn = 'Please take over ticket {0} (event={1}) in EVENT-REVIEW low-disturb text-receipt flow: read {3} first, run route_guard_command, and stop at concise text receipt plus handled_at. Do not run business_command, continue_watch_command, recovery, or restart unless route_guard classification explicitly allows and requires it.'
$scriptFixRecoveryMessageEn = 'Please take over ticket {0} (event={1}) in SCRIPT-FIX dedicated flow: read {3} first, run route_guard_command, and execute only route.allowed_actions. Focus on unattended script self-heal path (guard/trigger/dispatch/poll scripts), keep business source unchanged unless explicitly required by route. After the bounded script fix verification passes, do not stop at local validation: run pre_restart_launch_ready_command when present, then execute recovery_transaction_command exactly once when present; otherwise execute the single allowed atomic closeout path. Keep evidence concise and deterministic.'
$scriptDiagnoseOnlyMessageEn = 'Please take over ticket {0} (event={1}) in SCRIPT-DIAGNOSE-ONLY flow: read {3} first and run route_guard_command. This ticket authorizes investigation and reporting only. Read the incident package, failure logs, start-file, related scripts, and relevant recent changes. Use only read-only inspection, parser/static checks, or side-effect-free dry runs. Do not edit any file, create a script, kill or restart any process, run business_resume or continue_watch_command, mutate the environment, or perform recovery. A PowerShell wrapper stack frame alone is not enough for script-fault when a structured child result or exit_code exists; inherit the child compile/verify/noncode classification instead. Report: observed symptom, first error, call chain, root cause with evidence paths, impact, confidence, proposed minimal file changes, validation commands, risks, and rollback approach. Explicitly state that no file or process was changed, then execute atomic_closeout_command exactly once and wait for the user decision.'
$codeFixRecoveryMessageEn = 'Please take over ticket {0} (event={1}) in CODE-FIX dedicated flow: read {3} first, run route_guard_command, and execute only route.allowed_actions. Focus on source/task-definition mismatch or compile/verify failures; structured validation failures from preflight/check/golden/selftest/matrix/verify/smoke/preclass flows inherit the child result and stay in code-fix when no environment marker is present, even if a PowerShell wrapper stack frame is present. When the fix belongs to self-heal-generated output, modify the matching task-definition round under testdata (for example, B D4) instead of directly editing business source code. Task-definition JSON semantic edits must use the VS Code `apply_patch` editing tool; never use inline Python/PowerShell, redirection, generic string replacement, or a formatter. Validate in order: SyntaxOnly load check, focused failing-op check when available, then progressive strict check for the current failing D round. After those checks pass, do not stop at local validation: run pre_restart_launch_ready_command when present, then execute recovery_transaction_command exactly once when present; otherwise execute the single allowed atomic closeout path. If a true script fault is discovered while handling this code-fix ticket, stop the code-fix flow and reclassify it through the script policy: enter SCRIPT-FIX only when LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED is explicitly true; otherwise enter SCRIPT-DIAGNOSE-ONLY and do not edit files or control processes.

Fix placement rules:
    [D1-D4 task-static phase failed: task-definition-mismatch]
        Only forward D rounds are editable: D1 -> D1-D4, D2 -> D2-D4, D3 -> D3-D4, D4 -> D4. Never edit an earlier D round. Source NOT yet changed by the failing round. In that round, ops before the failing op are read-only; modify/delete/insert/append only from the failing op onward. Later allowed D rounds may be adjusted within this forward boundary.
  [D1-D4 code-step phase PASSED, but compile/verify phase failed]
      Only forward D rounds are editable: D1 -> D1-D4, D2 -> D2-D4, D3 -> D3-D4, D4 -> D4. Source HAS been changed by the failing round: its existing ops are read-only, so append one or more new ops consecutively at the END of that round. Never edit an earlier D round.
  [V1-V4 verify phase (NOT JSON round keys — only D1-D4 exist as rounds)]
      Append the fix as one or more new ops consecutively at the END of D4''s operations array; never create V1-V4 round entries, edit D1-D3, or modify/delete existing D4 content.

{4}

Do not mix with script-only remediation. This flow is authorized only for task-static failures and compile/verify failures classified as code faults; every code-step failure is noncode and must never edit source or task definition. After fixing a task-static fault, run SyntaxOnly first, then use `-RoundTag <Dn> -OperationIndex <n>` when the failed op is locatable, and finally check the current failing round without -OperationIndex. The independent task-static checker sequentially advances only after each op passes, stops at the first failure, and validates operations/replay/postApplyAssertions one round at a time. Follow task_static_cross_round_repair_enabled from the brief to stop after the failing round or continue in order through D4. Code-step only reads, validates, atomically writes, and validates the bound artifact. Rerun checker as often as diagnostics require within this repair ticket; these local checks do not consume the identical-fingerprint main-process relaunch budget. For helper forward-declaration repairs, preserve the helper definition, leave exactly one prototype before the first caller, and remove prototypes after the caller or duplicates. Treat single-instance conflict or regex/worker timeout as a hard restart block. Restart/resume is allowed only after every round selected by the brief passes. Restart only the correct stage main process for the ticketed phase (A issue -> restart A, B issue -> restart B); do not guess or switch phases. Complete bounded fix -> verify -> resume chain, then return handled_at with exact fix scope and validation evidence.'
$nonCodeRecoveryMessageEn = 'Please take over ticket {0} (event={1}) in NON-CODE dedicated flow: read {3} first, run route_guard_command, and execute only route.allowed_actions. All code-step failures belong here because code-step only reads, validates, atomically writes, and validates again; never edit source or task definition for a code-step fault. Compile/verify failures classified as environment, permission, disk, network, lock, toolchain, or test-infrastructure faults also stay here. Structured child exit_code evidence should be used to distinguish validation contract failures from wrapper script propagation. Stabilize the noncode cause first; when route allows recovery, run pre_restart_launch_ready_command when present, then execute recovery_transaction_command exactly once when present; otherwise execute the single allowed atomic closeout path and return handled_at.'
$noticeManualWaitMessageEn = 'Please take over ticket {0} (event={1}) in MANUAL-WAIT notice flow: read {3} first, run route_guard_command, report blockers and a recovery decision, then execute atomic_closeout_command exactly once and return its handled_at. This notice does not authorize edits, environment changes, business_resume, continue_watch, or restart; wait for a separate authorized incident ticket or explicit user authorization.'
$noticeBudgetMessageEn = 'Please take over ticket {0} (event={1}) in BUDGET-EXHAUSTED notice flow: read {3} first, run route_guard_command, produce a rerun-scope decision with budget/cooldown constraints, then execute atomic_closeout_command exactly once and return its handled_at. This notice grants no new repair or restart authority; an already-authorized pending repair ticket retains its documented priority.'
$noticeInfraMessageEn = 'Please take over ticket {0} (event={1}) in KNOWN-INFRA-TRANSIENT notice flow: read {3} first, run route_guard_command, assess infrastructure stability and report a stabilization decision, then execute atomic_closeout_command exactly once and return its handled_at. Do not mutate the environment, resume, continue-watch, or restart from this notice; wait for a separate authorized noncode incident ticket or explicit user authorization.'

$runningStatusFullMessageZh = '[FULL-RUNBOOK][STATUS-REPORT-ONLY] 本定时 running-status-report 只汇报运行状态。仅执行票据提供的只读状态查询，汇报 SESSION/A/B、run_dir、main_round、主进程与监控链存活、heartbeat 及待处理事故票摘要。不得执行自愈修复、故障处理、主进程或 guard 重启、business_resume、源码/脚本/任务定义修改、环境稳定化或任何恢复动作。发现异常只汇报并等待独立事故票，不得在本状态票内处置。汇报后回传 handled_at；仅在 stop monitoring 或 A/B 终态时回传 session_closed_at。未经用户同轮明确授权不得 commit/push。状态：{3}。'
$runningStatusShortMessageZh = '[SHORT-CARD][STATUS-REPORT-ONLY] 本定时状态票只汇报运行状态。仅用只读检查汇报 SESSION/A/B、main_round、主进程/监控链存活、heartbeat 和待处理事故票摘要。不得执行自愈修复、故障处理、主进程或 guard 重启、business_resume、文件修改、环境稳定化或任何恢复动作；发现异常只汇报并等待独立事故票。回传 handled_at。状态：{3}。'
$runningStatusLowDisturbMessageEn = '[LOW-DISTURB][STATUS-REPORT-ONLY] Report observed runtime status in two lines using read-only checks: "Running normal" or a concise anomaly summary, then "handled_at: YYYY-MM-DD HH:mm:ss". Never self-heal, handle faults, restart processes/guard, run business_resume, edit files, stabilize the environment, or recover from this status ticket. Wait for a separate incident ticket for any action.'
$runningStatusLowDisturbMessageZh = '[LOW-DISTURB][STATUS-REPORT-ONLY] 仅用只读检查汇报运行状态：正常时只回“运行正常”与 handled_at，异常时只回异常摘要与 handled_at。不得执行自愈修复、故障处理、主进程或 guard 重启、business_resume、文件修改、环境稳定化或任何恢复动作；任何处置均等待独立事故票。'
$finalStatusSummaryMessageZh = 'A/B 任务已完成。请接管票据 {0}（event={1}），先阅读 {2}，然后总结本次无人值守执行与收尾（执行窗口、状态票处理、根因与修复、关键恢复动作、chat_heartbeat、ACK 回执、最终结论）。最终收尾消息中必须显式写出会话结束日期时间。状态摘要：{3}。'
$taskDefinitionFixMessageZh = '请接管票据 {0}（event={1}），先阅读 {2}。请诊断根因是否为 task-static 阶段中 task-definition 与当前源码形态不匹配，并给出最小修复。只有 task-static 故障和经分类确认为代码故障的编译/验证故障可进入本流程；所有 code-step 故障均属于 noncode。仅允许使用 VS Code `apply_patch` 编辑工具修改 testdata 下任务定义 JSON，不直接修改业务源码；禁止用终端内联 Python/PowerShell、重定向、通用字符串替换或格式化器修改任务定义语义。修复 task-static 故障后，依次执行 SyntaxOnly、故障目标 op 快检（可定位时）和当前故障 D 轮递进严格检查，再遵循 brief 中的 task_static_cross_round_repair_enabled：false 时当前轮通过即停止，true 时按顺序逐轮检查并修复后续 D 轮到 D4，全部通过后才恢复。若已知是某个阶段某一轮（例如 B D4），要把目标 stage / round / 文件名写清楚。

修复位置规则：
    [D1-D4 task-static 阶段失败：task-definition-mismatch]
        仅可前向修改 D 轮次：D1 -> D1-D4，D2 -> D2-D4，D3 -> D3-D4，D4 -> D4；禁止修改前置 D 轮。源码尚未被当前故障轮修改；该轮故障 op 之前的 op 为只读，仅可从故障 op 起修改、删除、插入或追加。后续允许的 D 轮可在此前向边界内调整。
  [D1-D4 code-step 阶段已通过，但编译/验证阶段失败]
      仅可前向修改 D 轮次：D1 -> D1-D4，D2 -> D2-D4，D3 -> D3-D4，D4 -> D4；禁止修改前置 D 轮。源码已被当前故障轮修改，该轮既有 op 均为只读，只能在该轮 operations 数组末尾连续追加一个或多个新 op。
  [V1-V4 验证阶段（不是 JSON 轮次键名——只有 D1-D4 是轮次条目）]
      仅可将修复作为一个或多个新 op 连续追加到 D4 operations 数组末尾；不得创建 V1-V4 轮次条目，不得改 D1-D3，也不得修改或删除 D4 既有内容。

{4}

本流程只授权处理 task-static 故障，以及经分类确认为代码故障的编译/验证故障；任何 code-step 故障均属于 noncode，绝不允许修改源码或任务定义。修复 task-static 故障后，先运行 SyntaxOnly；可定位时检查当前 op：`tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce -RoundTag <Dn> -OperationIndex <n>`，再对当前故障轮运行不带 -OperationIndex 的递进严格检查。独立 task-static checker 只在当前 op 通过后推进内存副本，首错即停，不检查后续 op 或后续轮；operations、replay 与 postApplyAssertions 全部通过后生成哈希绑定的有效源码产物。code-step 只读取、验证、原子写入并写后验证该产物。可在同一修复工单内按诊断反复调用 checker，这些本地检查不消耗相同指纹主进程重启预算。修复 helper 前向声明时必须保留 helper definition，在首次 caller 前仅保留一个 prototype，并删除 caller 后或重复的 prototype。单实例冲突、正则或 worker 超时均硬阻断重启。只有当前故障轮通过才允许重启或 resume；重启时只能按本票目标阶段启动正确的主进程（A 问题重启 A，B 问题重启 B，禁止猜阶段、串阶段），然后继续监控，最后回传 chat_heartbeat 与修复结论。'
$runningStatusFullWrapMessageZh = '请接管票据 {0}（event={1}），先阅读 {2}。{3} 当前状态摘要：{4}。'
$genericRecoveryMessageZh = '请接管票据 {0}（event={1}），按 {2} 执行恢复：先阅读 {3}，并先执行 brief 中的 route_guard_command，必须按其 classification 决定分支后再执行动作；仅允许执行“动作映射在 route.allowed_actions 内”的命令（硬白名单），route.blocked_actions 视为禁止项。先汇报根因与修复方法；若可自愈且未触发预算/冷却耗尽且非不可恢复环境，立即触发 business_resume。处置后回到只读监控（票据驱动），改为由定时状态票/事件票驱动后续动作，并且只允许执行 brief/poll 输出中的现有仓库命令。禁止创建非 tmp 新脚本、临时后台监控循环或额外 out-of-band 看门任务。'
$eventReviewMessageZh = '请接管票据 {0}（event={1}），进入“事件评审流程”：先阅读 {3}，执行 route_guard_command，并严格按 route.allowed_actions 执行。本票不是故障恢复票，除非路由明确允许，不得执行 business_resume 或阶段重启。输出与该事件一致的评审结论，立即回传 handled_at，然后继续只读票据监控。'
$eventReviewLowDisturbMessageZh = '请接管票据 {0}（event={1}），进入“事件评审-低干扰文本回执流程”：先阅读 {3}，执行 route_guard_command 后即止于“简短文本结论 + handled_at”。除非 route_guard 分类明确允许且要求，否则不得执行 business_command、continue_watch_command、恢复或重启动作。'
$scriptFixRecoveryMessageZh = '请接管票据 {0}（event={1}），进入“脚本自愈专用流程”：先阅读 {3}，执行 route_guard_command，并严格按 route.allowed_actions 执行。仅处理无人值守脚本链路（guard/trigger/dispatch/poll）问题，除非路由明确允许，不要混入业务源码改动。脚本修复有界验证通过后不得停在本地验证：brief 提供 pre_restart_launch_ready_command 时先执行它；brief 提供 recovery_transaction_command 时必须只执行一次；否则只执行唯一允许的 atomic closeout 路径。'
$scriptDiagnoseOnlyMessageZh = '请接管票据 {0}（event={1}），进入“脚本故障排查专用流程”：先阅读 {3} 并执行 route_guard_command。本票只授权排查与汇报。只读检查事故包、失败日志、start-file、相关脚本及近期相关变更；仅允许无副作用的语法解析、静态检查或 dry-run。禁止修改任何文件、创建脚本、停止或重启任何进程、执行 business_resume/continue_watch_command、改变环境或实施恢复。聊天报告必须包含：故障现象、首次错误、调用链、根因及证据路径、影响范围、置信度、建议修改文件与最小方案、验证命令、风险和回滚方法；并明确声明“本票未修改任何文件，未停止或重启任何进程”。最后只执行一次 atomic_closeout_command，然后等待用户决定下一步。'
$codeFixRecoveryMessageZh = '请接管票据 {0}（event={1}），进入“代码修复专用流程”：先阅读 {3}，执行 route_guard_command，并严格按 route.allowed_actions 执行。仅处理源码/任务定义不匹配、编译或校验失败，不与脚本修复流程混用；如果这是自愈生成物修复，就修改 testdata 下对应阶段任务定义的对应轮次（例如 B D4），不要直接改业务源码。任务定义 JSON 的语义修改必须使用 VS Code `apply_patch` 编辑工具；禁止终端内联 Python/PowerShell、重定向、通用字符串替换或格式化器代改。验证顺序固定为 SyntaxOnly 装载检查、故障目标 op 快检（可定位时）、当前故障 D 轮递进严格检查。上述本地验证通过后不得停下：brief 提供 pre_restart_launch_ready_command 时先执行它；brief 提供 recovery_transaction_command 时必须只执行一次；否则只执行唯一允许的 atomic closeout 路径。若处理本代码修复票时发现脚本故障，必须停止代码修复流程并按脚本策略重新分类：仅当 LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED 显式为 true 时进入“脚本自愈专用流程”，否则进入“脚本故障排查专用流程”，不得修改文件或控制进程。

修复位置规则：
    [D1-D4 task-static 阶段失败：task-definition-mismatch]
        仅可前向修改 D 轮次：D1 -> D1-D4，D2 -> D2-D4，D3 -> D3-D4，D4 -> D4；禁止修改前置 D 轮。源码尚未被当前故障轮修改；该轮故障 op 之前的 op 为只读，仅可从故障 op 起修改、删除、插入或追加。后续允许的 D 轮可在此前向边界内调整。
  [D1-D4 code-step 阶段已通过，但编译/验证阶段失败]
      仅可前向修改 D 轮次：D1 -> D1-D4，D2 -> D2-D4，D3 -> D3-D4，D4 -> D4；禁止修改前置 D 轮。源码已被当前故障轮修改，该轮既有 op 均为只读，只能在该轮 operations 数组末尾连续追加一个或多个新 op。
  [V1-V4 验证阶段（不是 JSON 轮次键名——只有 D1-D4 是轮次条目）]
      仅可将修复作为一个或多个新 op 连续追加到 D4 operations 数组末尾；不得创建 V1-V4 轮次条目，不得改 D1-D3，也不得修改或删除 D4 既有内容。

{4}

本流程只授权处理 task-static 故障，以及经分类确认为代码故障的编译/验证故障；任何 code-step 故障均属于 noncode，绝不允许修改源码或任务定义。修复 task-static 故障后，先运行 SyntaxOnly；可定位时用 -OperationIndex 快检当前 op，再对当前故障轮运行不带 -OperationIndex 的递进严格检查。独立 task-static checker 负责 operations、replay 与 postApplyAssertions，首错即停，不检查后续 op 或轮；完整通过后生成哈希绑定产物。code-step 只读取、验证、原子写入并写后验证该产物。可在同一修复工单内按诊断反复调用 checker，这些本地检查不消耗相同指纹主进程重启预算。单实例冲突、正则或 worker 超时均硬阻断。只有当前故障轮通过才允许重启或 resume。完成 fix -> verify -> resume 的闭环后回传 handled_at，并说明修复范围与验证证据。'
$nonCodeRecoveryMessageZh = '请接管票据 {0}（event={1}），进入“非代码故障专用流程”：先阅读 {3}，执行 route_guard_command，并严格按 route.allowed_actions 执行。所有 code-step 故障都属于本流程，因为 code-step 只执行读取、验证、原子写入和写后验证；code-step 故障绝不允许修改源码或任务定义。编译/验证阶段经分类为环境、权限、磁盘、网络、锁、工具链或测试基础设施的故障也留在本流程。先稳定非代码原因；路由允许恢复时，brief 提供 pre_restart_launch_ready_command 时先执行它，brief 提供 recovery_transaction_command 时必须只执行一次，否则只执行唯一允许的 atomic closeout 路径，并回传 handled_at。'
$noticeManualWaitMessageZh = '请接管票据 {0}（event={1}），进入“manual-wait 通告流程”：先阅读 {3}，执行 route_guard_command，报告阻塞项与恢复决策，然后只执行一次 atomic_closeout_command 并回传其 handled_at。本通告不授权修改文件、改变环境、business_resume、continue_watch 或重启；等待独立的已授权事故票或用户明确授权。'
$noticeBudgetMessageZh = '请接管票据 {0}（event={1}），进入“budget-exhausted 通告流程”：先阅读 {3}，执行 route_guard_command，给出受预算/冷却约束的 rerun 范围决策，然后只执行一次 atomic_closeout_command 并回传其 handled_at。本通告不新增修复或重启权限；此前已授权且尚未完成的修复票仍按既定优先级处理。'
$noticeInfraMessageZh = '请接管票据 {0}（event={1}），进入“known-infra-transient 通告流程”：先阅读 {3}，执行 route_guard_command，只评估基础设施稳定状态并给出稳定化决策，然后只执行一次 atomic_closeout_command 并回传其 handled_at。本通告禁止改变环境、resume、continue_watch 或重启；等待独立的已授权 noncode 事故票或用户明确授权。'

$selfHealRuleSuffixEn = ''
$selfHealRuleSuffixZh = ''
$crossRoundRepairStatusEn = if ($taskStaticCrossRoundRepairEnabled) {
    '[Cross-round repair enabled] For task-static faults and compile/verify faults classified as code faults, check and repair each later D round in order through D4 after the failing round passes; restart only after all scoped rounds pass.'
}
else {
    '[Cross-round repair disabled] For task-static faults and compile/verify faults classified as code faults, check and repair only the failing D round; later rounds remain runtime-gated.'
}
$crossRoundRepairStatusZh = if ($taskStaticCrossRoundRepairEnabled) {
    '[跨轮次修复已开启] 对 task-static 故障，以及经分类确认为代码故障的编译/验证故障，当前故障轮通过后按顺序逐轮检查并修复后续 D 轮直到 D4；范围内全部轮次通过后才允许重启或 resume。'
}
else {
    '[跨轮次修复已关闭] 对 task-static 故障，以及经分类确认为代码故障的编译/验证故障，只检查并修复当前故障 D 轮，不得预演后续轮；后续轮仍由运行时门禁处理。'
}
$taskDefinitionSafetySuffixEn = "`n`n" + '[Task-definition safety] Change task-definition JSON semantics only with the VS Code `apply_patch` editing tool. After editing a task-static fault, run SyntaxOnly, optionally a focused -OperationIndex check, then follow task_static_cross_round_repair_enabled from the brief: false checks only the failing D round; true checks the failing round and each later D round through D4 in order. The independent task-static checker validates one round at a time, advances in-memory text only after each op passes, stops at the first failure, and validates operations, replay, and postApplyAssertions. Code-step only reads, validates, atomically writes, and validates the current round artifact; every code-step failure is noncode. Rerun checker as needed within one repair ticket; local checker calls do not consume the identical-fingerprint main-process relaunch budget. Keep qualityPolicy.operationSafetyPolicy=enforce. Use minimal type=noop only for a design-time empty round; reject pattern-equals-replacement self-replacement and keep runtime absorbed rounds as regex-patch with absorbed-by-prior-round/idempotent-replay evidence. Every op owns a replacement-produced marker and must converge. Update same-round postApplyAssertions only when operation results change. Preserve helper definitions, prototypes before first callers, and real call sites. Single-instance conflict and regex/worker timeout are hard failures.'
$taskDefinitionSafetySuffixZh = "`n`n" + '[任务定义安全] 任务定义 JSON 的语义修改只允许使用 VS Code `apply_patch` 编辑工具。修复 task-static 故障后先运行 SyntaxOnly，可定位时运行 -OperationIndex 快检，再遵循 brief 中的 task_static_cross_round_repair_enabled：false 时只检查故障 D 轮，true 时从故障轮开始按顺序逐轮检查到 D4。独立 task-static checker 每次只验证一轮，仅在当前 op 通过后推进内存文本，首错即停，并验证 operations、replay 与 postApplyAssertions。code-step 只读取、验证、原子写入并写后验证当前轮绑定产物；任何 code-step 故障均属于 noncode。同一修复工单内可按需反复调用 checker，本地检查不消耗相同指纹主进程重启预算。保持 qualityPolicy.operationSafetyPolicy=enforce。最小 type=noop 仅用于设计时空轮，禁止 pattern 与 replacement 相同的自替换；运行时吸收必须保持 regex-patch，并以 absorbed-by-prior-round/idempotent-replay 证明。每个 op 使用 replacement 自产 marker 并保证收敛；仅当 operation 结果变化时同步更新同轮 postApplyAssertions。保留 helper definition、首次 caller 前 prototype 与真实 call site。单实例冲突、正则或 worker 超时均为硬失败。'
$boundArtifactCorrectionEn = "`n`n[Authoritative phase contract] Only task-static failures and compile/verify failures classified as code faults may enter code-fix. Structured validation failures from preflight/check/golden/selftest/matrix/verify/smoke/preclass flows inherit the child result; wrapper script stack frames are call-chain evidence, not script-fault by themselves when a child exit_code exists. The independent task-static checker owns operation, replay, assertion, and effective-source validation and produces a hash-bound artifact. Code-step is only read -> validate -> atomic write -> validate; every code-step failure is noncode and must never authorize source or task-definition edits. Compile/verify failures classified as noncode also stay in noncode recovery. This contract overrides any earlier inline-checker or code-step-fix wording."
$boundArtifactCorrectionZh = "`n`n[权威阶段契约] 只有 task-static 故障，以及经分类确认为代码故障的编译/验证故障，才允许进入代码修复。preflight/check/golden/selftest/matrix/verify/smoke/preclass 等结构化验证失败继承子流程结果；当存在子流程 exit_code 时，wrapper 脚本栈帧只是调用链证据，不能单独构成脚本故障。独立 task-static checker 负责 operation、replay、断言和有效源码检查并生成哈希绑定产物。code-step 仅执行 read -> validate -> atomic write -> validate；任何 code-step 故障都属于非代码故障，绝不授权修改源码或任务定义。编译/验证阶段经分类为非代码的故障也必须留在非代码恢复流程。本契约覆盖前文任何 inline-checker 或 code-step 修复旧表述。"
if ($routeGuardExpected -in @('incident-auto-resume-code-fix', 'incident-manual-code-fix')) {
    $roundTag = $briefMainRound.ToUpperInvariant()
    $kindTag = $briefFailureKind.ToLowerInvariant()
    $roundIsD = ($roundTag -match '^D[1-4]$')
    $roundIsV = ($roundTag -match '^V[1-4]$')
    $isCompileVerifyFault = (
        $kindTag -in @('compile-failure', 'compile-warning', 'verify-failure', 'compile-or-test-failure') -or
        $briefFailurePhase.ToLowerInvariant() -in @('compile', 'compile-or-test', 'verify', 'validation')
    )
    $isTaskStaticFault = ($briefFailurePhase.ToLowerInvariant() -eq 'task-static' -or $kindTag -eq 'task-definition-mismatch')

    if ($roundIsD -and $isCompileVerifyFault) {
        $selfHealRuleSuffixEn = "[Self-Heal Rule] Compile/verify phase fault in ${roundTag}: edit only this D round and later D rounds (D1 -> D1-D4, D2 -> D2-D4, D3 -> D3-D4, D4 -> D4); never edit an earlier D round. The source has already been changed by ${roundTag} (code-step PASSED), so its existing ops are read-only: append one or more new ops consecutively only at the END of ${roundTag} operations. After changing, run static check (tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce). A failure blocks restart/resume: repair within this allowed boundary using the diagnostics and rerun the check until it passes; if it cannot pass compliantly, report the blocker and do not restart."
        $selfHealRuleSuffixZh = "[自愈修复规则] ${roundTag} 编译/验证阶段故障：仅可修改当前 D 轮及后续 D 轮（D1 -> D1-D4，D2 -> D2-D4，D3 -> D3-D4，D4 -> D4），禁止改前置 D 轮。${roundTag} 源码已变更（code-step 已通过），其既有 op 均为只读，只能在 ${roundTag} operations 数组末尾连续追加一个或多个新 op。变更后运行静态检查（tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce）。检查失败即阻断重启：必须依据诊断在允许边界内继续修复并重新检查，直至通过；若无法合规通过，报告阻塞且不得重启。"
    }
    elseif ($roundIsD -and $isTaskStaticFault) {
        $selfHealRuleSuffixEn = "[Self-Heal Rule] Task-static phase fault in ${roundTag}: edit only this D round and later D rounds (D1 -> D1-D4, D2 -> D2-D4, D3 -> D3-D4, D4 -> D4); never edit an earlier D round. The source has NOT yet been changed by ${roundTag}. In ${roundTag}, ops before the current failing op are read-only; modify, delete, insert, or append only from the failing op onward. After changes, first check that failing op with -RoundTag ${roundTag} -OperationIndex <n>; the checker simulates preceding ops as read-only prerequisites. Preserve helper definitions and keep exactly one prototype before the first caller, removing later/duplicate prototypes. A failure blocks restart/resume: repair within this allowed boundary using the diagnostics and rerun the check until it passes; if it cannot pass compliantly, report the blocker and do not restart."
        $selfHealRuleSuffixZh = "[自愈修复规则] ${roundTag} task-static 阶段故障：仅可修改当前 D 轮及后续 D 轮（D1 -> D1-D4，D2 -> D2-D4，D3 -> D3-D4，D4 -> D4），禁止改前置 D 轮。${roundTag} 源码尚未变更；该轮故障 op 之前的 op 为只读，仅可从故障 op 位置起修改、删除、插入或追加 op。变更后先检查当前故障 op，使用 -RoundTag ${roundTag} -OperationIndex <n>；checker 将前置 op 作为只读前提顺序模拟。必须保留 helper definition，在首次 caller 前仅保留一个 prototype，并删除后置或重复 prototype。检查失败即阻断重启：必须依据诊断在允许边界内继续修复并重新检查，直至通过；若无法合规通过，报告阻塞且不得重启。"
        if ($taskStaticCrossRoundRepairEnabled) {
            $selfHealRuleSuffixEn += " After ${roundTag} passes, run the checker for each later D round in order through D4. At the first later-round failure, stop, repair only within that later round's allowed boundary, rerun that round, and continue."
            $selfHealRuleSuffixZh += " ${roundTag} 通过后，按顺序对后续 D 轮逐轮运行 checker，直到 D4；遇到首个后续轮故障立即停止，只在该后续轮允许边界内修复并重查，通过后再继续。"
        }
        else {
            $selfHealRuleSuffixEn += " Check and repair only ${roundTag}; do not preflight later rounds, which remain runtime-gated."
            $selfHealRuleSuffixZh += " 只检查并修复 ${roundTag}，不得预演后续轮；后续轮仍由运行时门禁处理。"
        }
    }
    elseif ($roundIsV) {
        $selfHealRuleSuffixEn = "[Self-Heal Rule] V1-V4 verify-phase fault: V1-V4 are compile/verify phase names, NOT round keys in the JSON. Append the incremental patch as one or more new operations consecutively at the END of the D4 operations array. Do NOT create V1-V4 round entries, edit D1-D3, or modify/delete any existing D4 content. After appending, run static check (tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce). A failure blocks restart/resume: repair within this allowed boundary using the diagnostics and rerun the check until it passes; if it cannot pass compliantly, report the blocker and do not restart."
        $selfHealRuleSuffixZh = "[自愈修复规则] V1-V4 纯验证阶段故障：V1-V4 是编译/验证阶段名称，不是 JSON 中的轮次键名。仅可将增量补丁作为一个或多个新 op 连续追加到 D4 operations 数组末尾；不得创建 V1-V4 轮次条目，不得改 D1-D3，也不得修改/删除 D4 既有内容。追加后运行静态检查（tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce）。检查失败即阻断重启：必须依据诊断在允许边界内继续修复并重新检查，直至通过；若无法合规通过，报告阻塞且不得重启。"
    }
    elseif ($roundIsD -and -not $isCompileVerifyFault -and -not $isTaskStaticFault) {
        $selfHealRuleSuffixEn = "[Self-Heal Rule] ${roundTag} code-fix classification is missing a permitted task-static or compile/verify code phase (type=$kindTag). Do not edit source or task definition. Report the route-contract mismatch and return the incident to noncode/manual classification."
        $selfHealRuleSuffixZh = "[自愈修复规则] ${roundTag} 的 code-fix 分类缺少被允许的 task-static 或编译/验证代码故障阶段（类型=$kindTag）。禁止修改源码或任务定义；报告路由契约冲突，并将事故退回非代码/人工分类。"
    }
    else {
        $selfHealRuleSuffixEn = "[Self-Heal Rule] Code-fix round unspecified.
    For D faults, only forward D rounds are editable: D1 -> D1-D4, D2 -> D2-D4, D3 -> D3-D4, D4 -> D4; never edit an earlier D round.
    If D1-D4 task-static phase failed (task-definition-mismatch): source NOT yet changed; in the failing round, ops before the failing op are read-only and changes start at that op.
    If D1-D4 code-step phase PASSED but compile/verify phase failed: source HAS been changed; existing ops in that round are read-only, so append one or more new ops consecutively only at its END.
    If V1-V4 (verify phase, NOT a JSON round key): append one or more new ops consecutively only at the END of D4 operations; never create V1-V4 round entries, edit D1-D3, or modify/delete existing D4 content.
Always run static check (tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce) before any restart/resume. A failure blocks restart/resume: repair within the allowed boundary using the diagnostics and rerun the check until it passes; if it cannot pass compliantly, report the blocker and do not restart."
        $selfHealRuleSuffixZh = "[自愈修复规则] 故障轮次未指定。
    D 轮故障仅可前向修改：D1 -> D1-D4，D2 -> D2-D4，D3 -> D3-D4，D4 -> D4；不得改前置 D 轮。
    若 D1-D4 task-static 阶段失败（task-definition-mismatch）：源码尚未变更；当前故障轮中，故障 op 之前只读，变更从故障 op 开始。
    若 D1-D4 code-step 阶段已通过但编译/验证阶段失败：源码已被当前故障轮修改；该轮既有 op 只读，只能在末尾连续追加一个或多个新 op。
    若 V1-V4（验证阶段，不是 JSON 轮次键名）：仅可在 D4 operations 末尾连续追加一个或多个新 op；不得创建 V1-V4 轮次条目，不得改 D1-D3，也不得修改/删除 D4 既有内容。
任何重启前必须运行静态检查（tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce）。检查失败即阻断重启：必须依据诊断在允许边界内继续修复并重新检查，直至通过；若无法合规通过，报告阻塞且不得重启。"
    }
    $selfHealRuleSuffixEn += $taskDefinitionSafetySuffixEn
    $selfHealRuleSuffixZh += $taskDefinitionSafetySuffixZh
    $selfHealRuleSuffixEn += $boundArtifactCorrectionEn
    $selfHealRuleSuffixZh += $boundArtifactCorrectionZh
}

$gitGuardSuffixEn = ' During unattended execution, do not run git commit or git push unless explicitly authorized by the user in the same turn.'
$gitGuardSuffixZh = ' 无人值守运行期间禁止执行 git commit / git push；仅在用户同轮明确授权后才可提交或推送。'
$passiveWaitSuffixEn = ' Follow every ticket step without omission. When recovery_transaction_command is present, execute it exactly once as the recovery and closeout transaction; otherwise execute atomic_closeout_command exactly once at the end of the event ticket. Do not execute either closeout path again after success or failure. Claim closure only from successful machine facts; split receipt fields are audit-only and must not be run one by one. The final chat reply for the ticket must end with a standalone line exactly in the form `handled_at: YYYY-MM-DD HH:mm:ss`, copied from the successful machine output. After this ticket is handled, wait silently for the next event/status ticket delivered by the existing guard/trigger/dispatch chain. Do not create or run scheduled monitoring scripts, polling loops, background jobs, watchers, persistent PowerShell commands, or long-running/cross-round monitoring commands; these can interrupt closure when the next ticket arrives. After restarting a main process, complete the transaction/atomic closeout and pass all machine-fact gates within 3 minutes, then return to silent passive waiting; this limit is not a monitoring window.'
$passiveWaitSuffixZh = ' 严格按票据流程执行，不遗漏任何操作；当 brief 提供 recovery_transaction_command 时，将它作为“恢复+闭环事务”只执行一次；否则在事件票处理结束时只执行一次 atomic_closeout_command。无论成功或失败，任一闭环路径都不得再次执行。仅凭成功的机器事实声称闭环，旧分步回执字段只作审计兼容、不得逐条执行。本票最终聊天回复必须以独立末行 `handled_at: YYYY-MM-DD HH:mm:ss` 结束，时间从成功机器输出原样复制。本票闭环后，静默等待现有 guard/trigger/dispatch 链投送下一张事件票或状态票；不得创建或运行定时巡检脚本、轮询循环、后台 job、watcher、常驻 PowerShell 命令或长时间跨轮次巡检命令，这些命令可能在下一张事件票到达时中断收尾。重启主进程后，必须在 3 分钟内完成事务/原子收尾并通过全部机器事实门禁，然后回到静默被动等待；该时限不是巡检窗口。'

function Add-GitGuardConstraint {
    param(
        [AllowEmptyString()][string]$Template,
        [AllowEmptyString()][string]$Suffix
    )

    if ([string]::IsNullOrWhiteSpace($Template) -or [string]::IsNullOrWhiteSpace($Suffix)) {
        return $Template
    }

    $normalized = $Template.ToLowerInvariant()
    if ($normalized.Contains('git commit') -and $normalized.Contains('git push')) {
        return $Template
    }

    return ($Template.TrimEnd() + $Suffix)
}

function Add-PassiveWaitConstraint {
    param(
        [AllowEmptyString()][string]$Template,
        [AllowEmptyString()][string]$Suffix
    )

    if ([string]::IsNullOrWhiteSpace($Template) -or [string]::IsNullOrWhiteSpace($Suffix)) {
        return $Template
    }

    if ($Template.Contains($Suffix.Trim())) {
        return $Template
    }

    return ($Template.TrimEnd() + $Suffix)
}

$runningStatusFullMessageEn = Add-GitGuardConstraint -Template $runningStatusFullMessageEn -Suffix $gitGuardSuffixEn
$runningStatusShortMessageEn = Add-GitGuardConstraint -Template $runningStatusShortMessageEn -Suffix $gitGuardSuffixEn
$finalStatusSummaryMessageEn = Add-GitGuardConstraint -Template $finalStatusSummaryMessageEn -Suffix $gitGuardSuffixEn
$taskDefinitionFixMessageEn = Add-GitGuardConstraint -Template $taskDefinitionFixMessageEn -Suffix $gitGuardSuffixEn
$runningStatusFullWrapMessageEn = Add-GitGuardConstraint -Template $runningStatusFullWrapMessageEn -Suffix $gitGuardSuffixEn
$genericRecoveryMessageEn = Add-GitGuardConstraint -Template $genericRecoveryMessageEn -Suffix $gitGuardSuffixEn
$eventReviewMessageEn = Add-GitGuardConstraint -Template $eventReviewMessageEn -Suffix $gitGuardSuffixEn
$eventReviewLowDisturbMessageEn = Add-GitGuardConstraint -Template $eventReviewLowDisturbMessageEn -Suffix $gitGuardSuffixEn
$scriptFixRecoveryMessageEn = Add-GitGuardConstraint -Template $scriptFixRecoveryMessageEn -Suffix $gitGuardSuffixEn
$scriptDiagnoseOnlyMessageEn = Add-GitGuardConstraint -Template $scriptDiagnoseOnlyMessageEn -Suffix $gitGuardSuffixEn
$codeFixRecoveryMessageEn = Add-GitGuardConstraint -Template $codeFixRecoveryMessageEn -Suffix $gitGuardSuffixEn
$nonCodeRecoveryMessageEn = Add-GitGuardConstraint -Template $nonCodeRecoveryMessageEn -Suffix $gitGuardSuffixEn
$noticeManualWaitMessageEn = Add-GitGuardConstraint -Template $noticeManualWaitMessageEn -Suffix $gitGuardSuffixEn
$noticeBudgetMessageEn = Add-GitGuardConstraint -Template $noticeBudgetMessageEn -Suffix $gitGuardSuffixEn
$noticeInfraMessageEn = Add-GitGuardConstraint -Template $noticeInfraMessageEn -Suffix $gitGuardSuffixEn
$runningStatusLowDisturbMessageEn = Add-GitGuardConstraint -Template $runningStatusLowDisturbMessageEn -Suffix $gitGuardSuffixEn

$runningStatusFullMessageZh = Add-GitGuardConstraint -Template $runningStatusFullMessageZh -Suffix $gitGuardSuffixZh
$runningStatusShortMessageZh = Add-GitGuardConstraint -Template $runningStatusShortMessageZh -Suffix $gitGuardSuffixZh
$finalStatusSummaryMessageZh = Add-GitGuardConstraint -Template $finalStatusSummaryMessageZh -Suffix $gitGuardSuffixZh
$taskDefinitionFixMessageZh = Add-GitGuardConstraint -Template $taskDefinitionFixMessageZh -Suffix $gitGuardSuffixZh
$runningStatusFullWrapMessageZh = Add-GitGuardConstraint -Template $runningStatusFullWrapMessageZh -Suffix $gitGuardSuffixZh
$genericRecoveryMessageZh = Add-GitGuardConstraint -Template $genericRecoveryMessageZh -Suffix $gitGuardSuffixZh
$eventReviewMessageZh = Add-GitGuardConstraint -Template $eventReviewMessageZh -Suffix $gitGuardSuffixZh
$eventReviewLowDisturbMessageZh = Add-GitGuardConstraint -Template $eventReviewLowDisturbMessageZh -Suffix $gitGuardSuffixZh
$scriptFixRecoveryMessageZh = Add-GitGuardConstraint -Template $scriptFixRecoveryMessageZh -Suffix $gitGuardSuffixZh
$scriptDiagnoseOnlyMessageZh = Add-GitGuardConstraint -Template $scriptDiagnoseOnlyMessageZh -Suffix $gitGuardSuffixZh
$codeFixRecoveryMessageZh = Add-GitGuardConstraint -Template $codeFixRecoveryMessageZh -Suffix $gitGuardSuffixZh
$nonCodeRecoveryMessageZh = Add-GitGuardConstraint -Template $nonCodeRecoveryMessageZh -Suffix $gitGuardSuffixZh
$noticeManualWaitMessageZh = Add-GitGuardConstraint -Template $noticeManualWaitMessageZh -Suffix $gitGuardSuffixZh
$noticeBudgetMessageZh = Add-GitGuardConstraint -Template $noticeBudgetMessageZh -Suffix $gitGuardSuffixZh
$noticeInfraMessageZh = Add-GitGuardConstraint -Template $noticeInfraMessageZh -Suffix $gitGuardSuffixZh
$runningStatusLowDisturbMessageZh = Add-GitGuardConstraint -Template $runningStatusLowDisturbMessageZh -Suffix $gitGuardSuffixZh

$runningStatusFullMessageEn = Add-PassiveWaitConstraint -Template $runningStatusFullMessageEn -Suffix $passiveWaitSuffixEn
$runningStatusShortMessageEn = Add-PassiveWaitConstraint -Template $runningStatusShortMessageEn -Suffix $passiveWaitSuffixEn
$taskDefinitionFixMessageEn = Add-PassiveWaitConstraint -Template $taskDefinitionFixMessageEn -Suffix $passiveWaitSuffixEn
$runningStatusFullWrapMessageEn = Add-PassiveWaitConstraint -Template $runningStatusFullWrapMessageEn -Suffix $passiveWaitSuffixEn
$genericRecoveryMessageEn = Add-PassiveWaitConstraint -Template $genericRecoveryMessageEn -Suffix $passiveWaitSuffixEn
$eventReviewMessageEn = Add-PassiveWaitConstraint -Template $eventReviewMessageEn -Suffix $passiveWaitSuffixEn
$eventReviewLowDisturbMessageEn = Add-PassiveWaitConstraint -Template $eventReviewLowDisturbMessageEn -Suffix $passiveWaitSuffixEn
$scriptFixRecoveryMessageEn = Add-PassiveWaitConstraint -Template $scriptFixRecoveryMessageEn -Suffix $passiveWaitSuffixEn
$scriptDiagnoseOnlyMessageEn = Add-PassiveWaitConstraint -Template $scriptDiagnoseOnlyMessageEn -Suffix $passiveWaitSuffixEn
$codeFixRecoveryMessageEn = Add-PassiveWaitConstraint -Template $codeFixRecoveryMessageEn -Suffix $passiveWaitSuffixEn
$nonCodeRecoveryMessageEn = Add-PassiveWaitConstraint -Template $nonCodeRecoveryMessageEn -Suffix $passiveWaitSuffixEn
$noticeManualWaitMessageEn = Add-PassiveWaitConstraint -Template $noticeManualWaitMessageEn -Suffix $passiveWaitSuffixEn
$noticeBudgetMessageEn = Add-PassiveWaitConstraint -Template $noticeBudgetMessageEn -Suffix $passiveWaitSuffixEn
$noticeInfraMessageEn = Add-PassiveWaitConstraint -Template $noticeInfraMessageEn -Suffix $passiveWaitSuffixEn
$runningStatusLowDisturbMessageEn = Add-PassiveWaitConstraint -Template $runningStatusLowDisturbMessageEn -Suffix $passiveWaitSuffixEn

$runningStatusFullMessageZh = Add-PassiveWaitConstraint -Template $runningStatusFullMessageZh -Suffix $passiveWaitSuffixZh
$runningStatusShortMessageZh = Add-PassiveWaitConstraint -Template $runningStatusShortMessageZh -Suffix $passiveWaitSuffixZh
$taskDefinitionFixMessageZh = Add-PassiveWaitConstraint -Template $taskDefinitionFixMessageZh -Suffix $passiveWaitSuffixZh
$runningStatusFullWrapMessageZh = Add-PassiveWaitConstraint -Template $runningStatusFullWrapMessageZh -Suffix $passiveWaitSuffixZh
$genericRecoveryMessageZh = Add-PassiveWaitConstraint -Template $genericRecoveryMessageZh -Suffix $passiveWaitSuffixZh
$eventReviewMessageZh = Add-PassiveWaitConstraint -Template $eventReviewMessageZh -Suffix $passiveWaitSuffixZh
$eventReviewLowDisturbMessageZh = Add-PassiveWaitConstraint -Template $eventReviewLowDisturbMessageZh -Suffix $passiveWaitSuffixZh
$scriptFixRecoveryMessageZh = Add-PassiveWaitConstraint -Template $scriptFixRecoveryMessageZh -Suffix $passiveWaitSuffixZh
$scriptDiagnoseOnlyMessageZh = Add-PassiveWaitConstraint -Template $scriptDiagnoseOnlyMessageZh -Suffix $passiveWaitSuffixZh
$codeFixRecoveryMessageZh = Add-PassiveWaitConstraint -Template $codeFixRecoveryMessageZh -Suffix $passiveWaitSuffixZh
$nonCodeRecoveryMessageZh = Add-PassiveWaitConstraint -Template $nonCodeRecoveryMessageZh -Suffix $passiveWaitSuffixZh
$noticeManualWaitMessageZh = Add-PassiveWaitConstraint -Template $noticeManualWaitMessageZh -Suffix $passiveWaitSuffixZh
$noticeBudgetMessageZh = Add-PassiveWaitConstraint -Template $noticeBudgetMessageZh -Suffix $passiveWaitSuffixZh
$noticeInfraMessageZh = Add-PassiveWaitConstraint -Template $noticeInfraMessageZh -Suffix $passiveWaitSuffixZh
$runningStatusLowDisturbMessageZh = Add-PassiveWaitConstraint -Template $runningStatusLowDisturbMessageZh -Suffix $passiveWaitSuffixZh

$runningStatusFullMessage = if ($useChineseDispatchMessage) { $runningStatusFullMessageZh } else { $runningStatusFullMessageEn }
$runningStatusShortMessage = if ($useChineseDispatchMessage) { $runningStatusShortMessageZh } else { $runningStatusShortMessageEn }
$runningStatusLowDisturbMessage = if ($useChineseDispatchMessage) { $runningStatusLowDisturbMessageZh } else { $runningStatusLowDisturbMessageEn }
$finalStatusSummaryMessage = if ($useChineseDispatchMessage) { $finalStatusSummaryMessageZh } else { $finalStatusSummaryMessageEn }
$taskDefinitionFixMessage = if ($useChineseDispatchMessage) { $taskDefinitionFixMessageZh } else { $taskDefinitionFixMessageEn }
$runningStatusFullWrapMessage = if ($useChineseDispatchMessage) { $runningStatusFullWrapMessageZh } else { $runningStatusFullWrapMessageEn }
$genericRecoveryMessage = if ($useChineseDispatchMessage) { $genericRecoveryMessageZh } else { $genericRecoveryMessageEn }
$eventReviewMessage = if ($useChineseDispatchMessage) { $eventReviewMessageZh } else { $eventReviewMessageEn }
$eventReviewLowDisturbMessage = if ($useChineseDispatchMessage) { $eventReviewLowDisturbMessageZh } else { $eventReviewLowDisturbMessageEn }
$scriptFixRecoveryMessage = if ($useChineseDispatchMessage) { $scriptFixRecoveryMessageZh } else { $scriptFixRecoveryMessageEn }
$scriptDiagnoseOnlyMessage = if ($useChineseDispatchMessage) { $scriptDiagnoseOnlyMessageZh } else { $scriptDiagnoseOnlyMessageEn }
$codeFixRecoveryMessage = if ($useChineseDispatchMessage) { $codeFixRecoveryMessageZh } else { $codeFixRecoveryMessageEn }
$nonCodeRecoveryMessage = if ($useChineseDispatchMessage) { $nonCodeRecoveryMessageZh } else { $nonCodeRecoveryMessageEn }
$noticeManualWaitMessage = if ($useChineseDispatchMessage) { $noticeManualWaitMessageZh } else { $noticeManualWaitMessageEn }
$noticeBudgetMessage = if ($useChineseDispatchMessage) { $noticeBudgetMessageZh } else { $noticeBudgetMessageEn }
$noticeInfraMessage = if ($useChineseDispatchMessage) { $noticeInfraMessageZh } else { $noticeInfraMessageEn }

if ($startSettings.Contains('AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_FULL')) {
    $overrideText = Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_FULL)
    if ($allowRunningStatusMessageOverride -and -not [string]::IsNullOrWhiteSpace($overrideText)) {
        $runningStatusFullMessage = $overrideText
    }
    elseif (-not [string]::IsNullOrWhiteSpace($overrideText)) {
        Write-DispatchLog 'running_status_message_override_ignored key=AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_FULL reason=override_disabled'
    }
}
if ($startSettings.Contains('AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_SHORT')) {
    $overrideText = Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_SHORT)
    if ($allowRunningStatusMessageOverride -and -not [string]::IsNullOrWhiteSpace($overrideText)) {
        $runningStatusShortMessage = $overrideText
    }
    elseif (-not [string]::IsNullOrWhiteSpace($overrideText)) {
        Write-DispatchLog 'running_status_message_override_ignored key=AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_SHORT reason=override_disabled'
    }
}
if ($startSettings.Contains('AI_CHAT_DISPATCH_MESSAGE_FINAL_STATUS')) {
    $overrideText = Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_DISPATCH_MESSAGE_FINAL_STATUS)
    if (-not [string]::IsNullOrWhiteSpace($overrideText)) {
        $finalStatusSummaryMessage = $overrideText
    }
}
if ($startSettings.Contains('AI_CHAT_DISPATCH_MESSAGE_TASK_DEFINITION_FIX')) {
    $overrideText = Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_DISPATCH_MESSAGE_TASK_DEFINITION_FIX)
    if (-not [string]::IsNullOrWhiteSpace($overrideText)) {
        $taskDefinitionFixMessage = $overrideText
    }
}
if ($startSettings.Contains('AI_CHAT_DISPATCH_MESSAGE_GENERIC_RECOVERY')) {
    $overrideText = Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_DISPATCH_MESSAGE_GENERIC_RECOVERY)
    if (-not [string]::IsNullOrWhiteSpace($overrideText)) {
        $genericRecoveryMessage = $overrideText
    }
}
$selectedPassiveWaitSuffix = if ($useChineseDispatchMessage) { $passiveWaitSuffixZh } else { $passiveWaitSuffixEn }
$runningStatusFullMessage = Add-PassiveWaitConstraint -Template $runningStatusFullMessage -Suffix $selectedPassiveWaitSuffix
$runningStatusShortMessage = Add-PassiveWaitConstraint -Template $runningStatusShortMessage -Suffix $selectedPassiveWaitSuffix
$taskDefinitionFixMessage = Add-PassiveWaitConstraint -Template $taskDefinitionFixMessage -Suffix $selectedPassiveWaitSuffix
$genericRecoveryMessage = Add-PassiveWaitConstraint -Template $genericRecoveryMessage -Suffix $selectedPassiveWaitSuffix
$runningStatusUseFullMessage = $false
$runningStatusEffectiveMode = 'n/a'
$policyWorkMode = ''
if ($startSettings.Contains('AI_CHAT_POLICY_WORK_MODE')) {
    $policyWorkMode = (Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_POLICY_WORK_MODE)).ToLowerInvariant()
}
$runningStatusFaultHandlingPhase = (
    $eventNormalized -eq 'running-status-report' -and
    -not [string]::IsNullOrWhiteSpace($routeGuardExpected) -and
    $routeGuardExpected -ne 'status-health-check-only'
)
$lowDisturbRunningStatus = ($eventNormalized -eq 'running-status-report' -and $policyWorkMode -eq 'low-disturb')
if ($eventNormalized -eq 'running-status-report') {
    if ($runningStatusFaultHandlingPhase) {
        # Fault/self-heal handling in status tickets always uses normal/full response standard.
        $runningStatusEffectiveMode = 'fault-normal'
        $runningStatusUseFullMessage = $true
    }
    elseif ($lowDisturbRunningStatus) {
        $runningStatusEffectiveMode = 'low-disturb'
        $runningStatusUseFullMessage = $false
    }
    elseif ($statusReportMessageMode -eq 'full') {
        $runningStatusEffectiveMode = 'full'
        $runningStatusUseFullMessage = $true
    }
    elseif ($statusReportMessageMode -eq 'alternate') {
        if ($statusReportSendFullOnFirst -and -not [bool]$statusReportState.full_sent_once) {
            $runningStatusUseFullMessage = $true
            $runningStatusEffectiveMode = 'full-first'
        }
        else {
            $lastModeNormalized = (Convert-ToSingleLineText -Text ([string]$statusReportState.last_mode)).ToLowerInvariant()
            $lastWasFull = $lastModeNormalized -in @('full', 'full-first', 'alternate-full')
            if ($lastWasFull) {
                $runningStatusUseFullMessage = $false
                $runningStatusEffectiveMode = 'alternate-short'
            }
            else {
                $runningStatusUseFullMessage = $true
                $runningStatusEffectiveMode = 'alternate-full'
            }
        }
    }
    elseif ($statusReportSendFullOnFirst -and -not [bool]$statusReportState.full_sent_once) {
        $runningStatusUseFullMessage = $true
        $runningStatusEffectiveMode = 'full-first'
    }
    else {
        $runningStatusEffectiveMode = 'short'
    }
}
if ($eventNormalized -eq 'running-status-report') {
    if ($runningStatusFaultHandlingPhase) {
        $firstMessage = $runningStatusFullWrapMessage -f $TicketId, $TicketEvent, $dispatchReadContextText, $runningStatusFullMessage, $runningStatusShortSummary
    }
    elseif ($lowDisturbRunningStatus) {
        $firstMessage = $runningStatusLowDisturbMessage -f $TicketId, $TicketEvent, $dispatchReadContextText
    }
    elseif ($runningStatusUseFullMessage) {
        $firstMessage = $runningStatusFullWrapMessage -f $TicketId, $TicketEvent, $dispatchReadContextText, $runningStatusFullMessage, $runningStatusShortSummary
    }
    else {
        $firstMessage = $runningStatusShortMessage -f $TicketId, $TicketEvent, $dispatchReadContextText, $runningStatusShortSummary
    }
}
elseif ($eventNormalized -eq 'chat-session-final-status') {
    $firstMessage = $finalStatusSummaryMessage -f $TicketId, $TicketEvent, $dispatchReadContextText, $runningStatusShortSummary
}
elseif ($eventNormalized -eq 'task-definition-fix-required') {
    $crossRoundRepairStatus = if ($useChineseDispatchMessage) { $crossRoundRepairStatusZh } else { $crossRoundRepairStatusEn }
    $firstMessage = $taskDefinitionFixMessage -f $TicketId, $TicketEvent, $dispatchReadContextText, '', $crossRoundRepairStatus

    $taskDefLocationParts = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace($resumePreferredStage)) {
        [void]$taskDefLocationParts.Add(('stage={0}' -f $resumePreferredStage))
    }
    if (-not [string]::IsNullOrWhiteSpace($briefMainRound)) {
        [void]$taskDefLocationParts.Add(('round={0}' -f $briefMainRound.ToUpperInvariant()))
    }
    if (-not [string]::IsNullOrWhiteSpace($briefFailurePhase)) {
        [void]$taskDefLocationParts.Add(('failure_phase={0}' -f $briefFailurePhase.ToLowerInvariant()))
    }
    if ($briefSettings.Contains('task_definition') -and -not [string]::IsNullOrWhiteSpace((Convert-ToSingleLineText -Text ([string]$briefSettings.task_definition)))) {
        [void]$taskDefLocationParts.Add(('task_definition={0}' -f (Convert-ToSingleLineText -Text ([string]$briefSettings.task_definition))))
    }

    if (-not [string]::IsNullOrWhiteSpace($briefDetail)) {
        $stageInDetail = [regex]::Match($briefDetail, '(?i)\bstage\s*=\s*([AB])\b')
        if ($stageInDetail.Success -and -not ($taskDefLocationParts -contains ('stage={0}' -f $stageInDetail.Groups[1].Value.ToUpperInvariant()))) {
            [void]$taskDefLocationParts.Add(('stage={0}' -f $stageInDetail.Groups[1].Value.ToUpperInvariant()))
        }

        $roundInDetail = [regex]::Match($briefDetail, '(?i)\bround\s*=\s*([DV][0-9]+)\b')
        if ($roundInDetail.Success -and -not ($taskDefLocationParts -contains ('round={0}' -f $roundInDetail.Groups[1].Value.ToUpperInvariant()))) {
            [void]$taskDefLocationParts.Add(('round={0}' -f $roundInDetail.Groups[1].Value.ToUpperInvariant()))
        }

        $scopeInDetail = [regex]::Match($briefDetail, '(?i)\bscope\s*=\s*([^\s]+)')
        if ($scopeInDetail.Success) {
            [void]$taskDefLocationParts.Add(('scope={0}' -f (Convert-ToSingleLineText -Text $scopeInDetail.Groups[1].Value)))
        }

        $taskDefInDetail = [regex]::Match($briefDetail, '(?i)\btask_definition\s*=\s*([^\s]+)')
        if ($taskDefInDetail.Success) {
            $taskDefToken = (Convert-ToSingleLineText -Text $taskDefInDetail.Groups[1].Value)
            $taskDefAlreadyIncluded = $false
            foreach ($part in @($taskDefLocationParts.ToArray())) {
                if ($part -eq ('task_definition={0}' -f $taskDefToken)) {
                    $taskDefAlreadyIncluded = $true
                    break
                }
            }
            if (-not $taskDefAlreadyIncluded) {
                [void]$taskDefLocationParts.Add(('task_definition={0}' -f $taskDefToken))
            }
        }
    }

    if ($taskDefLocationParts.Count -gt 0) {
        $locationLine = if ($useChineseDispatchMessage) {
            '已知故障位置：{0}' -f (($taskDefLocationParts.ToArray()) -join ' ')
        }
        else {
            'Known failure location: {0}' -f (($taskDefLocationParts.ToArray()) -join ' ')
        }
        $firstMessage = ("{0}`n`n{1}" -f $firstMessage.TrimEnd(), $locationLine)
    }

    if (-not [string]::IsNullOrWhiteSpace($fingerprintHintEn) -or -not [string]::IsNullOrWhiteSpace($fingerprintHintZh)) {
        $fingerprintHint = if ($useChineseDispatchMessage) { $fingerprintHintZh } else { $fingerprintHintEn }
        if (-not [string]::IsNullOrWhiteSpace($fingerprintHint)) {
            $firstMessage = ("{0}`n`n{1}" -f $firstMessage.TrimEnd(), $fingerprintHint)
        }
    }
}
else {
    $crossRoundRepairStatus = if ($useChineseDispatchMessage) {
        $crossRoundRepairStatusZh
    }
    else {
        $crossRoundRepairStatusEn
    }

    switch ($routeGuardExpected) {
        'incident-script-diagnose-only' { $firstMessage = $scriptDiagnoseOnlyMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText; break }
        'incident-auto-resume-script-fix' { $firstMessage = $scriptFixRecoveryMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText; break }
        'incident-manual-script-fix' { $firstMessage = $scriptFixRecoveryMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText; break }
        'incident-auto-resume-code-fix' { $firstMessage = $codeFixRecoveryMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText, $crossRoundRepairStatus; break }
        'incident-manual-code-fix' { $firstMessage = $codeFixRecoveryMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText, $crossRoundRepairStatus; break }
        'incident-auto-resume-noncode' { $firstMessage = $nonCodeRecoveryMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText; break }
        'incident-manual-noncode' { $firstMessage = $nonCodeRecoveryMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText; break }
        'notice-manual-wait' { $firstMessage = $noticeManualWaitMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText; break }
        'notice-budget-exhausted' { $firstMessage = $noticeBudgetMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText; break }
        'notice-known-infra-transient' { $firstMessage = $noticeInfraMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText; break }
        'event-review' { $firstMessage = $eventReviewMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText; break }
        'event-review-low-disturb-text-only' { $firstMessage = $eventReviewLowDisturbMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText; break }
        default { $firstMessage = $genericRecoveryMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText; break }
    }


if ($eventNormalized -eq 'a-pass-conclusion-b-started') {
    $aTimingText = 'A elapsed={0}; start={1}; end={2}' -f $aStageElapsed, $sessionInitialLaunchAt, $aStageCompletedAt
    if ($useChineseDispatchMessage) {
        $firstMessage += ("`n`n最低评审内容：{0}。回复中必须原样包含 A 阶段总用时及起止锚点：{1}。" -f $reviewContentRequirements, $aTimingText)
    }
    else {
        $firstMessage += ("`n`nMinimum review content: {0}. The reply must reproduce the A-stage elapsed time and anchors exactly: {1}." -f $reviewContentRequirements, $aTimingText)
    }
}
elseif ($eventNormalized -eq 'chat-session-final-status') {
    $finalTimingText = 'B elapsed={0}; B start={1}; B end={2}; A/B total elapsed={3}; session start={4}' -f $bStageElapsed, $bStageFirstStartAt, $bStageCompletedAt, $abTotalElapsed, $sessionInitialLaunchAt
    if ($useChineseDispatchMessage) {
        $firstMessage += ("`n`n最低总结内容：{0}。回复中必须原样包含 B 阶段总用时、A/B 合计总用时及起止锚点：{1}。" -f $summaryContentRequirements, $finalTimingText)
    }
    else {
        $firstMessage += ("`n`nMinimum summary content: {0}. The reply must reproduce the B-stage elapsed time, combined A/B elapsed time, and anchors exactly: {1}." -f $summaryContentRequirements, $finalTimingText)
    }
}
    if ($routeGuardExpected -in @('incident-auto-resume-code-fix', 'incident-manual-code-fix')) {
        $ruleSuffix = if ($useChineseDispatchMessage) { $selfHealRuleSuffixZh } else { $selfHealRuleSuffixEn }
        if (-not [string]::IsNullOrWhiteSpace($ruleSuffix)) {
            $firstMessage = ("{0}`n`n{1}" -f $firstMessage.TrimEnd(), $ruleSuffix)
        }

        $fingerprintHint = if ($useChineseDispatchMessage) { $fingerprintHintZh } else { $fingerprintHintEn }
        if (-not [string]::IsNullOrWhiteSpace($fingerprintHint)) {
            $firstMessage = ("{0}`n`n{1}" -f $firstMessage.TrimEnd(), $fingerprintHint)
        }
    }

    # Resume-rule suffix for all business-resume-capable scenarios
    if ($routeGuardExpected -in @('incident-auto-resume-code-fix','incident-manual-code-fix','incident-auto-resume-script-fix','incident-manual-script-fix','incident-auto-resume-noncode','incident-manual-noncode')) {
        $resumeRuleSuffix = if ($useChineseDispatchMessage) {
            'Resume 规则：使用 business_command 中预置的 open_unattended_ab_stage_window.ps1 重启主进程；禁止使用 open_unattended_ab_resume_window.ps1。重启时不会杀掉正在运行的监控链进程（监控链已实现自管理：guard/trigger 自动绑定新主进程，guard 启动时自动清理旧进程）。源码基线在 task_static_precheck 前已自动恢复（A：git checkout；B：A snapshot restore），无需手动清理。重启后继续监控并回传 handled_at。'
        }
        else {
            'Resume rules: Use the open_unattended_ab_stage_window.ps1 from business_command to restart the main process; do NOT use open_unattended_ab_resume_window.ps1. The restart does NOT kill running monitor chain processes (monitors self-manage: guard/trigger auto-bind to new main process, guard cleans up old instances on startup). Source baseline is auto-restored before task_static_precheck (A: git checkout; B: A snapshot restore), no manual cleanup needed. After restart, continue monitoring and return handled_at.'
        }
        if (-not [string]::IsNullOrWhiteSpace($resumeRuleSuffix)) {
            $firstMessage = ("{0}`n`n{1}" -f $firstMessage.TrimEnd(), $resumeRuleSuffix)
        }
    }
}

$noAskConfirmationHardRule = if ($useChineseDispatchMessage) {
    '硬规则：禁止 ask-confirmation（例如“可以开始吗”）；拿到 route_guard classification 后，直接执行允许动作，不要再等待额外确认。'
}
else {
    'Hard rule: do not ask for confirmation (for example, "can I start?"); after obtaining route_guard classification, execute allowed actions directly without waiting for extra approval.'
}
$barrierPrecedenceHardRule = if ($useChineseDispatchMessage) {
    '硬规则：若 route_guard 输出 newer_barrier_tickets 非空，立即切换到最新 barrier 票据执行，并停止当前票据的 business_resume/阶段重启动作。'
}
else {
    'Hard rule: if route_guard returns non-empty newer_barrier_tickets, switch to the newest barrier ticket immediately and stop business_resume/stage-restart actions for the current ticket.'
}
$eventOnlyWordingHardRule = if ($useChineseDispatchMessage) {
    '硬规则：event-only 仅表示调度/触发策略，不得被描述为或执行为 low-disturb 流程；事件票与故障期一律按 route_guard 分类和 normal/full 标准处理。'
}
else {
    'Hard rule: event-only is scheduling/triggering policy only; do not describe or execute it as low-disturb flow. Event tickets and fault phases must follow route_guard classification and normal/full standard.'
}
$firstMessage = ("{0}`n`n{1}`n`n{2}`n`n{3}" -f $firstMessage, $noAskConfirmationHardRule, $barrierPrecedenceHardRule, $eventOnlyWordingHardRule).Trim()

$eventQueuePolicyHint = ''
if ($useChineseDispatchMessage) {
    if (-not [string]::IsNullOrWhiteSpace($eventQueueIdempotentPolicy) -or -not [string]::IsNullOrWhiteSpace($eventQueueScopeRule) -or -not [string]::IsNullOrWhiteSpace($modeRestorePolicy)) {
        $eventQueueIdempotentPolicyText = if ([string]::IsNullOrWhiteSpace($eventQueueIdempotentPolicy)) {
            '按本期最早未处理事件票排空，事件不存在即标记已处理并继续'
        }
        else {
            $eventQueueIdempotentPolicy
        }
        $eventQueueScopeRuleText = if ([string]::IsNullOrWhiteSpace($eventQueueScopeRule)) {
            '仅处理本期启动基线之后事件票，启动前历史票自动跳过'
        }
        else {
            $eventQueueScopeRule
        }
        $modeRestorePolicyText = if ([string]::IsNullOrWhiteSpace($modeRestorePolicy)) {
            '事件票排空后回到之前工作模式（normal/anti-missent/low-disturb/event-only）'
        }
        else {
            $modeRestorePolicy
        }

        $eventQueuePolicyHint = ('事件队列幂等策略：{0}；作用域：{1}；模式回归：{2}。' -f
            $eventQueueIdempotentPolicyText,
            $eventQueueScopeRuleText,
            $modeRestorePolicyText
        )
    }
}
else {
    if (-not [string]::IsNullOrWhiteSpace($eventQueueIdempotentPolicy) -or -not [string]::IsNullOrWhiteSpace($eventQueueScopeRule) -or -not [string]::IsNullOrWhiteSpace($modeRestorePolicy)) {
        $eventQueueIdempotentPolicyText = if ([string]::IsNullOrWhiteSpace($eventQueueIdempotentPolicy)) {
            'drain earliest unhandled in-session event tickets; if event missing mark done and continue'
        }
        else {
            $eventQueueIdempotentPolicy
        }
        $eventQueueScopeRuleText = if ([string]::IsNullOrWhiteSpace($eventQueueScopeRule)) {
            'in-session only; pre-start historical event tickets are skipped'
        }
        else {
            $eventQueueScopeRule
        }
        $modeRestorePolicyText = if ([string]::IsNullOrWhiteSpace($modeRestorePolicy)) {
            'after event queue drained, return to previous work mode (normal/anti-missent/low-disturb/event-only)'
        }
        else {
            $modeRestorePolicy
        }

        $eventQueuePolicyHint = ('Event queue idempotent policy: {0}; scope: {1}; mode restore: {2}.' -f
            $eventQueueIdempotentPolicyText,
            $eventQueueScopeRuleText,
            $modeRestorePolicyText
        )
    }
}

$mandatoryReceiptRule = if ($useChineseDispatchMessage) {
    "强制回执
handled_at: YYYY-MM-DD HH:mm:ss（必填，不得省略）"
}
else {
    "Mandatory Receipt
handled_at: YYYY-MM-DD HH:mm:ss (required, do not omit)"
}

if ($retryBudgetOneTimeOnly -or $retryBudgetExhausted) {
    if ($useChineseDispatchMessage) {
        $mandatoryReceiptRule = ('{0}`nretry_budget_used: yes|no（必填；one_time_retry_only=true 时本轮必须为 yes；retry_budget_exhausted=true 时必须为 no）' -f $mandatoryReceiptRule)
    }
    else {
        $mandatoryReceiptRule = ('{0}`nretry_budget_used: yes|no (required; must be yes when one_time_retry_only=true in this cycle; must be no when retry_budget_exhausted=true)' -f $mandatoryReceiptRule)
    }
}

$machineFactCloseoutRule = ''
if ($eventNormalized -ne 'running-status-report') {
    if (-not [string]::IsNullOrWhiteSpace($recoveryTransactionCommand)) {
        $machineFactCloseoutRule = if ($useChineseDispatchMessage) {
            ('机器事实闭环门禁：当前 brief 提供 recovery_transaction_command，必须将其作为“恢复+闭环事务”只执行一次：{0}。该命令会按当前工单字段执行授权的 business/continue/closeout 路径，并在内部校验 atomic closeout 机器事实。仅当命令退出码为 0 且 JSON 返回 success=true、handled_at 有效时，才可从该机器输出原样回传 handled_at 并声称闭环；自然语言声明不能替代此门禁。最终聊天回复必须以独立末行 `handled_at: YYYY-MM-DD HH:mm:ss` 结束。' -f $recoveryTransactionCommand)
        }
        else {
            ('Machine-fact closeout gate: this brief provides recovery_transaction_command; execute it exactly once as the recovery and closeout transaction: {0}. The command follows the current ticket fields for the authorized business/continue/closeout path and verifies atomic closeout machine facts internally. Claim closure and copy handled_at verbatim from machine output only when exit code is 0 and JSON reports success=true with a valid handled_at; natural-language claims do not satisfy this gate. The final chat reply must end with a standalone line `handled_at: YYYY-MM-DD HH:mm:ss`.' -f $recoveryTransactionCommand)
        }
    }
    elseif ([string]::IsNullOrWhiteSpace($atomicCloseoutCommand)) {
        $machineFactCloseoutRule = if ($useChineseDispatchMessage) {
            '机器事实闭环门禁：当前 brief 同时缺少 recovery_transaction_command 与 atomic_closeout_command，必须 fail-close。只报告闭环命令缺失并停止；不得自行生成 handled_at，不得声称票据已处理或已闭环。'
        }
        else {
            'Machine-fact closeout gate: both recovery_transaction_command and atomic_closeout_command are missing from the brief. Fail closed: report the missing command and stop; do not invent handled_at or claim that the ticket is processed or closed.'
        }
    }
    else {
        $machineFactCloseoutRule = if ($useChineseDispatchMessage) {
            ('机器事实闭环门禁：每张事件票处理结束时，atomic_closeout_command 只能执行一次，无论成功或失败均不得再次执行。最终回复前执行以下唯一原子收尾命令：{0}。仅当命令退出码为 0 且 JSON 同时满足 success=true、processed=true、ledger_status=done、receipt_valid=true、closure_pass=true、handled_at 格式有效时，才可从该机器输出原样回传 handled_at 并声称闭环；自然语言声明不能替代此门禁。最终聊天回复必须以独立末行 `handled_at: YYYY-MM-DD HH:mm:ss` 结束。' -f $atomicCloseoutCommand)
        }
        else {
            ('Machine-fact closeout gate: at the end of each event ticket, execute atomic_closeout_command exactly once; do not execute it again after either success or failure. Before the final reply, execute this single atomic closeout command: {0}. Claim closure and copy handled_at verbatim from machine output only when exit code is 0 and JSON reports success=true, processed=true, ledger_status=done, receipt_valid=true, closure_pass=true, and a valid handled_at; natural-language claims do not satisfy this gate. The final chat reply must end with a standalone line `handled_at: YYYY-MM-DD HH:mm:ss`.' -f $atomicCloseoutCommand)
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($eventQueuePolicyHint)) {
    $firstMessage = ("{0}`n`n{1}" -f $firstMessage, $eventQueuePolicyHint).Trim()
}
if (-not [string]::IsNullOrWhiteSpace($machineFactCloseoutRule)) {
    $firstMessage = ("{0}`n`n{1}" -f $firstMessage, $machineFactCloseoutRule).Trim()
}

Write-DispatchLog ("dispatch_phase message_ready ticket={0} event={1} route_guard_expected={2} summary_len={3}" -f $TicketId, $TicketEvent, $routeGuardExpected, $runningStatusShortSummary.Length)

$dispatchMessage = $firstMessage
$dispatchMessageMode = $runningStatusEffectiveMode

$dispatchSanitizeResult = Format-DispatchMessage -Message $dispatchMessage -AppendAdvisory $true -UseChinese ([bool]$useChineseDispatchMessage)
$dispatchMessage = [string]$dispatchSanitizeResult.message
$mandatoryReceiptPattern = '(?ms)(?:\r?\n){0,2}' + [regex]::Escape($mandatoryReceiptRule) + '\s*$'
$dispatchMessage = [regex]::Replace($dispatchMessage.Trim(), $mandatoryReceiptPattern, '')
$dispatchMessage = ("{0}`n`n{1}" -f $dispatchMessage.Trim(), $mandatoryReceiptRule).Trim()
$firstMessage = $dispatchMessage
if ([bool]$dispatchSanitizeResult.sanitized) {
    Write-DispatchLog ("dispatch_message_sanitized event={0} removed_lines={1} inline_replacements={2} transcript_blocks_removed={3} transcript_lines_removed={4} deduped_lines={5} truncated={6} rules={7}" -f $TicketEvent, [int]$dispatchSanitizeResult.removed_lines, [int]$dispatchSanitizeResult.inline_replacements, [int]$dispatchSanitizeResult.transcript_blocks_removed, [int]$dispatchSanitizeResult.transcript_lines_removed, [int]$dispatchSanitizeResult.deduped_lines, [bool]$dispatchSanitizeResult.truncated, [string]$dispatchSanitizeResult.rule_summary)
}
Write-DispatchLog ("dispatch_phase message_sanitize_done ticket={0} event={1} sanitized={2} length={3}" -f $TicketId, $TicketEvent, [bool]$dispatchSanitizeResult.sanitized, $dispatchMessage.Length)

$resumeCommand = ''
$guardCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}" -NoRestartIfRunning' -f $startFileRel
if ($eventNormalized -ne 'running-status-report' -and $eventNormalized -ne 'chat-session-final-status') {
    Write-DispatchLog ("dispatch_phase resume_plan_start ticket={0} event={1} session={2} a={3} b={4}" -f $TicketId, $TicketEvent, $resumeSessionStatus, $resumeAStatus, $resumeBStatus)
    $preferredStageHint = $resumePreferredStage
    if ([string]::IsNullOrWhiteSpace($preferredStageHint) -and $eventNormalized -in @('task-definition-fix-required', 'a-pass-conclusion-b-started')) {
        $preferredStageHint = 'B'
    }

    $resumeClosedByPassFinal = (($resumeSessionStatus -eq 'PASS') -or ($resumeAStatus -eq 'PASS' -and $resumeBStatus -eq 'PASS'))
    $resumeDisable = $sessionClosedByFlag -or $resumeClosedByPassFinal

    $resumePlan = Resolve-BusinessResumePlan -StartFileRel $startFileRel -SessionStatus $resumeSessionStatus -AStatus $resumeAStatus -BStatus $resumeBStatus -PreferredStage $preferredStageHint -DisableResume:$resumeDisable
    $resumeCommand = [string]$resumePlan.command
    if (-not [string]::IsNullOrWhiteSpace($resumeCommand)) {
        Write-DispatchLog ("business_resume_route event={0} stage={1} reason={2} session={3} a={4} b={5}" -f $TicketEvent, [string]$resumePlan.stage, [string]$resumePlan.reason, [string]$resumePlan.session_status, [string]$resumePlan.a_status, [string]$resumePlan.b_status)
    }

    if (-not [string]::IsNullOrWhiteSpace($resumeCommand)) {
    $guardCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}"' -f $startFileRel
    }
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
Write-DispatchLog ("dispatch_phase relay_build_start ticket={0} event={1} fallback_commands={2}" -f $TicketId, $TicketEvent, $fallbackCommands.Count)

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
    ('status_report_dispatch_message_mode={0}' -f $dispatchMessageMode),
    ('status_report_fault_phase={0}' -f $runningStatusFaultHandlingPhase),
    ('route_guard_expected={0}' -f $routeGuardExpected),
    ('route_guard_expected_source={0}' -f $routeGuardExpectedSource),
    ('route_guard_live_classification={0}' -f $routeGuardLiveClassification),
    ('route_guard_live_probe_reason={0}' -f $routeGuardLiveProbeReason),
    ('event_queue_idempotent_policy={0}' -f $eventQueueIdempotentPolicy),
    ('event_queue_scope_rule={0}' -f $eventQueueScopeRule),
    ('mode_restore_policy={0}' -f $modeRestorePolicy),
    '',
    'first_message:',
    $firstMessage,
    '',
    'dispatch_message:',
    $dispatchMessage,
    '',
    'fallback_commands:'
)
$relayLines += @($fallbackCommands.ToArray())
try {
    Write-DispatchLog ("dispatch_phase relay_write_start ticket={0} event={1} relay={2}" -f $TicketId, $TicketEvent, $relayRel)
    Write-Utf8BomFile -Path $relayPath -Value $relayLines
    Write-DispatchLog ("dispatch_phase relay_write_done ticket={0} event={1} relay={2}" -f $TicketId, $TicketEvent, $relayRel)
}
catch {
    $relayWriteFailure = Convert-ToSingleLineText -Text $_.Exception.Message
    Write-DispatchLog ("relay_write_failed ticket={0} event={1} relay={2} detail={3}" -f $TicketId, $TicketEvent, $relayRel, $relayWriteFailure)
    throw
}

$latestStatePath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $dispatchRoot ("latest_relay_{0}.json" -f $startToken)) -LegacyPath (Join-Path $dispatchRoot ("latest_relay_{0}.json" -f $legacyStartToken))
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
    status_report_dispatch_message_mode = $dispatchMessageMode
    status_report_fault_phase = $runningStatusFaultHandlingPhase
    route_guard_expected = $routeGuardExpected
    route_guard_expected_source = $routeGuardExpectedSource
    route_guard_live_classification = $routeGuardLiveClassification
    route_guard_live_probe_reason = $routeGuardLiveProbeReason
    event_queue_idempotent_policy = $eventQueueIdempotentPolicy
    event_queue_scope_rule = $eventQueueScopeRule
    mode_restore_policy = $modeRestorePolicy
    first_message = $firstMessage
    dispatch_message = $dispatchMessage
}
Write-Utf8BomFile -Path $latestStatePath -Value ($latestState | ConvertTo-Json -Depth 8)
Write-DispatchLog ("dispatch_phase latest_state_written ticket={0} event={1} path={2}" -f $TicketId, $TicketEvent, (Convert-ToRepoRelativePath -Path $latestStatePath))

if ($eventNormalized -eq 'running-status-report') {
    $statusReportState.updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $statusReportState.last_ticket_id = $TicketId
    $statusReportState.last_mode = $runningStatusEffectiveMode
    if ($runningStatusUseFullMessage -and -not [bool]$statusReportState.full_sent_once) {
        $statusReportState.full_sent_once = $true
        $statusReportState.first_full_ticket_id = $TicketId
    }

    try {
        Write-Utf8BomFile -Path $statusReportMessageStatePath -Value ($statusReportState | ConvertTo-Json -Depth 8)
    }
    catch {
        Write-DispatchLog ("status_report_message_state_write_failed path={0} detail={1}" -f (Convert-ToRepoRelativePath -Path $statusReportMessageStatePath), (Convert-ToSingleLineText -Text $_.Exception.Message))
    }
}

$clipboardApplied = $false
if ($useClipboardByPolicy -and $runInteractivePreActions) {
    try {
        Set-Clipboard -Value $dispatchMessage
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
    $clipboardSkipReason = if (-not $interactivePreActionsEnabled) { 'disabled-by-sender-mode' } else { 'disabled-by-policy' }
    Write-DispatchLog ("skip_clipboard event={0} reason={1}" -f $TicketEvent, $clipboardSkipReason)
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
$ahkRestorePreviousWindowActivationTrace = ''
$ahkRestorePreviousWindowActivationCountAttempted = 0
$ahkRestorePreviousWindowActivationCountSucceeded = 0
$ahkRestorePreviousWindowActivationFinalForegroundHandle = 0
$ahkRestorePreviousWindowActivationRestoreExecuted = $false
$ahkRestorePreviousWindowActivationSkippedReason = ''
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

if ($activeWindowOnly -and $runInteractivePreActions) {
    $codeMainBefore = Get-CodeMainProcessMap
    $codeRendererBefore = Get-CodeRendererWindowMap
}

if ($openEditorByPolicy -and $runInteractivePreActions) {
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
    $editorSkipReason = if (-not $interactivePreActionsEnabled) { 'disabled-by-sender-mode' } else { 'disabled-by-policy' }
    Write-DispatchLog ("skip_editor_and_chat_open event={0} reason={1}" -f $TicketEvent, $editorSkipReason)
}

if ($interactiveDispatchEnabled -and -not $suppressInteractiveActions -and $ahkAllowedByEvent) {
    $ahkDispatchTried = $true
    $ahkResult = Invoke-ConfiguredChatDispatch -SenderMode $dispatchSenderMode -AhkExecutable $ahkExecutable -PythonExecutable $pythonExecutable -Message $dispatchMessage -TicketId $TicketId -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -IpcMode $ipcDispatchMode -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $statusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $activeWindowOnly -CrossSenderFallbackEnabled $senderFallbackEnabled -ClearInputOnFailure $clearInputOnFailure
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
    $ahkRestorePreviousWindowActivationTrace = Convert-ToSingleLineText -Text ([string]$ahkResult.restore_previous_window_activation_trace)
    $ahkRestorePreviousWindowActivationCountAttempted = [int]$ahkResult.restore_previous_window_activation_count_attempted
    $ahkRestorePreviousWindowActivationCountSucceeded = [int]$ahkResult.restore_previous_window_activation_count_succeeded
    $ahkRestorePreviousWindowActivationFinalForegroundHandle = [Int64]$ahkResult.restore_previous_window_activation_final_foreground_handle
    $ahkRestorePreviousWindowActivationRestoreExecuted = [bool]$ahkResult.restore_previous_window_activation_restore_executed
    $ahkRestorePreviousWindowActivationSkippedReason = Convert-ToSingleLineText -Text ([string]$ahkResult.restore_previous_window_activation_skipped_reason)

    $shouldRetryWithoutActiveWindow = $activeWindowOnly -and (-not $ahkDispatchSent) -and ($eventNormalized -eq 'running-status-report') -and (($ahkDispatchExitCode -eq 40) -or ($ahkDispatchReason -like '*active-code-window-required*') -or ($ahkDispatchReason -like '*active_window_only_blocked*'))
    if ($shouldRetryWithoutActiveWindow) {
        $ahkFallbackTriggered = $true
        Write-DispatchLog ("ahk_dispatch_retry ticket={0} reason=active-window-only-blocked retry_active_window_only=false" -f $TicketId)

        $fallbackResult = Invoke-ConfiguredChatDispatch -SenderMode $dispatchSenderMode -AhkExecutable $ahkExecutable -PythonExecutable $pythonExecutable -Message $dispatchMessage -TicketId $TicketId -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -IpcMode $ipcDispatchMode -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $statusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $false -CrossSenderFallbackEnabled $senderFallbackEnabled -ClearInputOnFailure $clearInputOnFailure
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
            $ahkRestorePreviousWindowActivationTrace = Convert-ToSingleLineText -Text ([string]$fallbackResult.restore_previous_window_activation_trace)
            $ahkRestorePreviousWindowActivationCountAttempted = [int]$fallbackResult.restore_previous_window_activation_count_attempted
            $ahkRestorePreviousWindowActivationCountSucceeded = [int]$fallbackResult.restore_previous_window_activation_count_succeeded
            $ahkRestorePreviousWindowActivationFinalForegroundHandle = [Int64]$fallbackResult.restore_previous_window_activation_final_foreground_handle
            $ahkRestorePreviousWindowActivationRestoreExecuted = [bool]$fallbackResult.restore_previous_window_activation_restore_executed
            $ahkRestorePreviousWindowActivationSkippedReason = Convert-ToSingleLineText -Text ([string]$fallbackResult.restore_previous_window_activation_skipped_reason)
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

    $paletteRetryReason = (Convert-ToSingleLineText -Text $ahkDispatchReason).ToLowerInvariant()
    $statusReportVerifyUncertain = ($ahkDispatchExitCode -eq 2) -and (
        ($paletteRetryReason -like '*transcript_changed_without_message_match*') -or
        ($paletteRetryReason -like '*input_cleared_without_transcript_delta*') -or
        ($paletteRetryReason -like '*input_cleared_transcript_check_disabled*')
    )
    $statusReportInputObservationFailed = ($ahkDispatchExitCode -eq 1) -and (
        ($paletteRetryReason -like '*input_not_observed_after_set_text*') -or
        ($paletteRetryReason -like '*enter_submit_not_observed_input_retained*') -or
        ($paletteRetryReason -like '*input_not_cleared*')
    )
    $shouldRetryWithPaletteFocus = (-not $ahkDispatchSent) -and ($eventNormalized -eq 'running-status-report') -and (
        $statusReportVerifyUncertain -or
        $statusReportInputObservationFailed -or
        ($ahkDispatchExitCode -eq 39) -or
        ($ahkDispatchExitCode -eq 41) -or
        ($ahkDispatchExitCode -eq 42) -or
        ($paletteRetryReason -like '*required-code-chat-focus*') -or
        ($paletteRetryReason -like '*chat input caret is not in expected area*') -or
        ($paletteRetryReason -like '*chat input was not focused*') -or
        ($paletteRetryReason -like '*unable to verify chat submit outcome*')
    )
    if ($shouldRetryWithPaletteFocus) {
        $ahkPaletteFallbackTriggered = $true
        $paletteRetryTrigger = 'focus-validation-failed'
        if ($statusReportVerifyUncertain) {
            $paletteRetryTrigger = 'verify-uncertain'
        }
        elseif ($statusReportInputObservationFailed) {
            $paletteRetryTrigger = 'input-observation-failed'
        }
        Write-DispatchLog ("ahk_dispatch_palette_retry ticket={0} reason={1}" -f $TicketId, $paletteRetryTrigger)

        $paletteFallbackResult = Invoke-ConfiguredChatDispatch -SenderMode $dispatchSenderMode -AhkExecutable $ahkExecutable -PythonExecutable $pythonExecutable -Message $dispatchMessage -TicketId $TicketId -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -IpcMode $ipcDispatchMode -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $statusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $false -CrossSenderFallbackEnabled $senderFallbackEnabled -ClearInputOnFailure $clearInputOnFailure -StatusReportClickRecoveryOnly $true
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
            $ahkRestorePreviousWindowActivationTrace = Convert-ToSingleLineText -Text ([string]$paletteFallbackResult.restore_previous_window_activation_trace)
            $ahkRestorePreviousWindowActivationCountAttempted = [int]$paletteFallbackResult.restore_previous_window_activation_count_attempted
            $ahkRestorePreviousWindowActivationCountSucceeded = [int]$paletteFallbackResult.restore_previous_window_activation_count_succeeded
            $ahkRestorePreviousWindowActivationFinalForegroundHandle = [Int64]$paletteFallbackResult.restore_previous_window_activation_final_foreground_handle
            $ahkRestorePreviousWindowActivationRestoreExecuted = [bool]$paletteFallbackResult.restore_previous_window_activation_restore_executed
            $ahkRestorePreviousWindowActivationSkippedReason = Convert-ToSingleLineText -Text ([string]$paletteFallbackResult.restore_previous_window_activation_skipped_reason)
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
        ($ahkDispatchExitCode -in @(38, 41, 42)) -or
        ($focusGuardReason -like '*chat input was not focused*') -or
        ($focusGuardReason -like '*chat input caret is not in expected area*') -or
        ($focusGuardReason -like '*unable to verify chat submit outcome*') -or
        ($focusGuardReason -like '*ahk-exit-38*') -or
        ($focusGuardReason -like '*ahk-exit-41*') -or
        ($focusGuardReason -like '*ahk-exit-42*')
    )
    if ($shouldRetryWithFocusGuardRecovery) {
        $ahkFocusGuardFallbackTriggered = $true
        Write-DispatchLog ("ahk_dispatch_focus_guard_retry ticket={0} reason=focus-guard-failed retry_active_window_only=false force_focus_recovery=true" -f $TicketId)

        $focusGuardFallbackResult = Invoke-ConfiguredChatDispatch -SenderMode $dispatchSenderMode -AhkExecutable $ahkExecutable -PythonExecutable $pythonExecutable -Message $dispatchMessage -TicketId $TicketId -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -IpcMode $ipcDispatchMode -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $statusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $false -CrossSenderFallbackEnabled $senderFallbackEnabled -ClearInputOnFailure $clearInputOnFailure -ForceFocusRecovery $true
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
            $ahkRestorePreviousWindowActivationTrace = Convert-ToSingleLineText -Text ([string]$focusGuardFallbackResult.restore_previous_window_activation_trace)
            $ahkRestorePreviousWindowActivationCountAttempted = [int]$focusGuardFallbackResult.restore_previous_window_activation_count_attempted
            $ahkRestorePreviousWindowActivationCountSucceeded = [int]$focusGuardFallbackResult.restore_previous_window_activation_count_succeeded
            $ahkRestorePreviousWindowActivationFinalForegroundHandle = [Int64]$focusGuardFallbackResult.restore_previous_window_activation_final_foreground_handle
            $ahkRestorePreviousWindowActivationRestoreExecuted = [bool]$focusGuardFallbackResult.restore_previous_window_activation_restore_executed
            $ahkRestorePreviousWindowActivationSkippedReason = Convert-ToSingleLineText -Text ([string]$focusGuardFallbackResult.restore_previous_window_activation_skipped_reason)
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

    if ($activeWindowOnly -and $runInteractivePreActions) {
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
    if (-not [string]::IsNullOrWhiteSpace($ahkRestorePreviousWindowActivationTrace)) {
        Write-DispatchLog ("ahk_dispatch_restore_activation_trace ticket={0} attempted={1} succeeded={2} restore_executed={3} skipped_reason={4} final_foreground={5} trace={6}" -f $TicketId, $ahkRestorePreviousWindowActivationCountAttempted, $ahkRestorePreviousWindowActivationCountSucceeded, $ahkRestorePreviousWindowActivationRestoreExecuted, $ahkRestorePreviousWindowActivationSkippedReason, $ahkRestorePreviousWindowActivationFinalForegroundHandle, $ahkRestorePreviousWindowActivationTrace)
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
elseif ($interactiveDispatchEnabled -and -not $ahkAllowedByEvent) {
    if ([string]::IsNullOrWhiteSpace($ahkSkipReason)) {
        $ahkSkipReason = 'event-not-in-allowlist'
    }
    Write-DispatchLog ("ahk_dispatch_skipped event={0} reason={1} allowlist={2} heartbeat_timeout_send_enabled={3} heartbeat_timeout_require_code_focus={4}" -f $TicketEvent, $ahkSkipReason, (($ahkEventAllowList -join ';')), $heartbeatTimeoutSendEnabled, $heartbeatTimeoutRequireCodeFocus)
}
elseif ($interactiveDispatchEnabled) {
    Write-DispatchLog ("ahk_dispatch_skipped event={0} reason=status-report" -f $TicketEvent)
}

Write-DispatchLog ("relay_created ticket={0} event={1} relay={2} brief_exists={3} clipboard={4} clipboard_enabled={5} editor_opened={6} editor_enabled={7} chat_open_tried={8} chat_open_started={9} interactive_suppressed={10} interactive_pre_actions_enabled={11} run_interactive_pre_actions={12} status_report_interactive_enabled={13} use_ipc={14} use_ahk={15} ahk_allowed_by_event={16} ahk_event_allowlist={17} heartbeat_timeout_send_enabled={18} heartbeat_timeout_require_code_focus={19} active_window_only={20} new_code_main_detected={21} new_code_main_closed={22} new_code_window_configs_detected={23} new_code_window_pids_closed={24} ahk_tried={25} ahk_sent={26} ahk_exit_code={27} ahk_reason={28} ahk_esc_preflight_enabled={29} ahk_focus_guard_fallback_triggered={30} ahk_focus_guard_fallback_sent={31} ahk_focus_guard_fallback_exit_code={32} ahk_focus_guard_fallback_reason={33} ahk_restore_requested={34} ahk_restore_captured={35} ahk_restore_handles={36}" -f $TicketId, $TicketEvent, $relayRel, $briefExists, $clipboardApplied, $useClipboardByPolicy, $editorOpened, $openEditorByPolicy, $chatOpenTried, $chatOpenStarted, $suppressInteractiveActions, $interactivePreActionsEnabled, $runInteractivePreActions, $statusReportInteractiveEnabled, $useIpcDispatch, $useAhkDispatch, $ahkAllowedByEvent, (($ahkEventAllowList -join ';')), $heartbeatTimeoutSendEnabled, $heartbeatTimeoutRequireCodeFocus, $activeWindowOnly, ($newCodeMainDetected -join ','), ($newCodeMainClosed -join ','), ($newCodeWindowConfigsDetected -join ','), ($newCodeWindowPidsClosed -join ','), $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkEscPreflightEnabled, $ahkFocusGuardFallbackTriggered, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason, $ahkRestorePreviousWindowCountRequested, $ahkRestorePreviousWindowCountCaptured, $ahkRestorePreviousWindowHandles)
Write-DispatchLog ("dispatch_sender_result ticket={0} sender_mode={1} use_ipc={2} use_python={3} ipc_mode={4} sender_fallback_enabled={5} tried={6} sent={7} exit_code={8} reason={9}" -f $TicketId, $dispatchSenderMode, $useIpcDispatch, $usePythonDispatch, $ipcDispatchMode, $senderFallbackEnabled, $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason)
Write-DispatchLog ("dispatch_sender_metrics ticket={0} sender_mode={1} sender_tried={2} sender_sent={3} sender_exit_code={4} sender_reason={5} sender_attempts={6} sender_auto_resend_triggered={7} sender_auto_resend_reason={8} sender_esc_preflight_enabled={9} sender_focus_guard_fallback_triggered={10} sender_focus_guard_fallback_sent={11} sender_focus_guard_fallback_exit_code={12} sender_focus_guard_fallback_reason={13} sender_restore_requested={14} sender_restore_captured={15} sender_restore_handles={16}" -f $TicketId, $dispatchSenderMode, $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkDispatchAttemptCount, $ahkAutoResendTriggered, $ahkAutoResendReason, $ahkEscPreflightEnabled, $ahkFocusGuardFallbackTriggered, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason, $ahkRestorePreviousWindowCountRequested, $ahkRestorePreviousWindowCountCaptured, $ahkRestorePreviousWindowHandles)

try {
    $latestState.sender_mode = $dispatchSenderMode
    $latestState.sender_use_ipc = [bool]$useIpcDispatch
    $latestState.sender_use_python = [bool]$usePythonDispatch
    $latestState.sender_use_ahk = [bool]$useAhkDispatch
    $latestState.sender_ipc_mode = $ipcDispatchMode
    $latestState.sender_interactive_pre_actions_enabled = [bool]$interactivePreActionsEnabled
    $latestState.sender_fallback_enabled = [bool]$senderFallbackEnabled
    $latestState.sender_tried = [bool]$ahkDispatchTried
    $latestState.sender_sent = [bool]$ahkDispatchSent
    $latestState.sender_exit_code = [int]$ahkDispatchExitCode
    $latestState.sender_reason = Convert-ToSingleLineText -Text ([string]$ahkDispatchReason)
    $latestState.sender_attempts = [int]$ahkDispatchAttemptCount
    $latestState.sender_auto_resend_triggered = [bool]$ahkAutoResendTriggered
    $latestState.sender_auto_resend_reason = Convert-ToSingleLineText -Text ([string]$ahkAutoResendReason)
    $latestState.sender_esc_preflight_enabled = [bool]$ahkEscPreflightEnabled
    $latestState.sender_restore_requested = [int]$ahkRestorePreviousWindowCountRequested
    $latestState.sender_restore_captured = [int]$ahkRestorePreviousWindowCountCaptured
    $latestState.sender_restore_handles = Convert-ToSingleLineText -Text ([string]$ahkRestorePreviousWindowHandles)
    Write-Utf8BomFile -Path $latestStatePath -Value ($latestState | ConvertTo-Json -Depth 8)
}
catch {
    Write-DispatchLog ("latest_state_sender_update_failed path={0} detail={1}" -f (Convert-ToRepoRelativePath -Path $latestStatePath), (Convert-ToSingleLineText -Text $_.Exception.Message))
}

Write-Output ("[CHAT-DISPATCH] ticket={0} event={1} relay={2} first_message_in_clipboard={3} clipboard_enabled={4} editor_opened={5} editor_enabled={6} chat_open_started={7} interactive_suppressed={8}" -f $TicketId, $TicketEvent, $relayRel, $clipboardApplied, $useClipboardByPolicy, $editorOpened, $openEditorByPolicy, $chatOpenStarted, $suppressInteractiveActions)
Write-Output ("[CHAT-DISPATCH] use_ipc={0} use_ahk={1} status_report_interactive_enabled={2} interactive_pre_actions_enabled={3} run_interactive_pre_actions={4} ahk_allowed_by_event={5} ahk_event_allowlist={6} heartbeat_timeout_send_enabled={7} heartbeat_timeout_require_code_focus={8} active_window_only={9} new_code_main_detected={10} new_code_main_closed={11} new_code_window_configs_detected={12} new_code_window_pids_closed={13} ahk_tried={14} ahk_sent={15} ahk_exit_code={16} ahk_reason={17} ahk_attempts={18} ahk_auto_resend_triggered={19} ahk_auto_resend_reason={20} ahk_esc_preflight_enabled={21} ahk_focus_guard_fallback_triggered={22} ahk_focus_guard_fallback_sent={23} ahk_focus_guard_fallback_exit_code={24} ahk_focus_guard_fallback_reason={25} ahk_restore_requested={26} ahk_restore_captured={27} ahk_restore_handles={28}" -f $useIpcDispatch, $useAhkDispatch, $statusReportInteractiveEnabled, $interactivePreActionsEnabled, $runInteractivePreActions, $ahkAllowedByEvent, (($ahkEventAllowList -join ';')), $heartbeatTimeoutSendEnabled, $heartbeatTimeoutRequireCodeFocus, $activeWindowOnly, ($newCodeMainDetected -join ','), ($newCodeMainClosed -join ','), ($newCodeWindowConfigsDetected -join ','), ($newCodeWindowPidsClosed -join ','), $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkDispatchAttemptCount, $ahkAutoResendTriggered, $ahkAutoResendReason, $ahkEscPreflightEnabled, $ahkFocusGuardFallbackTriggered, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason, $ahkRestorePreviousWindowCountRequested, $ahkRestorePreviousWindowCountCaptured, $ahkRestorePreviousWindowHandles)
Write-Output ("[CHAT-DISPATCH] sender_mode={0} use_ipc={1} use_python={2} ipc_mode={3} sender_fallback_enabled={4} dispatch_tried={5}" -f $dispatchSenderMode, $useIpcDispatch, $usePythonDispatch, $ipcDispatchMode, $senderFallbackEnabled, $ahkDispatchTried)
Write-Output ("[CHAT-DISPATCH] sender_mode={0} sender_tried={1} sender_sent={2} sender_exit_code={3} sender_reason={4} sender_attempts={5} sender_auto_resend_triggered={6} sender_auto_resend_reason={7} sender_esc_preflight_enabled={8} sender_focus_guard_fallback_triggered={9} sender_focus_guard_fallback_sent={10} sender_focus_guard_fallback_exit_code={11} sender_focus_guard_fallback_reason={12} sender_restore_requested={13} sender_restore_captured={14} sender_restore_handles={15}" -f $dispatchSenderMode, $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkDispatchAttemptCount, $ahkAutoResendTriggered, $ahkAutoResendReason, $ahkEscPreflightEnabled, $ahkFocusGuardFallbackTriggered, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason, $ahkRestorePreviousWindowCountRequested, $ahkRestorePreviousWindowCountCaptured, $ahkRestorePreviousWindowHandles)

}
catch {
    $dispatchFailureDetail = Convert-ToSingleLineText -Text $_.Exception.Message
    try {
        Write-DispatchLog ("dispatch_main_failed ticket={0} event={1} detail={2}" -f $TicketId, $TicketEvent, $dispatchFailureDetail)
    }
    catch {
        $null = $_
    }

    Write-Output ("[CHAT-DISPATCH] dispatch_main_failed ticket={0} event={1} detail={2}" -f $TicketId, $TicketEvent, $dispatchFailureDetail)
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason ("dispatch_main_failed ticket={0} event={1} detail={2}" -f $TicketId, $TicketEvent, $dispatchFailureDetail) -ExitCode 1
}

