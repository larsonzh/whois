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

    $text = Convert-ToFileText -Value $Value
    [System.IO.File]::WriteAllText($Path, $text, (Get-Utf8BomEncoding))
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

function Get-StableStartFileToken {
    param([string]$StartFilePath)

    if ([string]::IsNullOrWhiteSpace($StartFilePath)) {
        return 'sf_unknown'
    }

    $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
        $hashBytes = $sha1.ComputeHash($bytes)
        $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha1.Dispose()
    }

    return ('sf_{0}' -f $hash)
}

function Get-LegacyStartFileToken {
    param([string]$StartFilePath)

    return Get-SafeToken -Text ([System.IO.Path]::GetFileNameWithoutExtension($StartFilePath))
}

function Resolve-PreferredDefaultPath {
    param(
        [string]$PreferredPath,
        [string]$LegacyPath
    )

    if (-not [string]::IsNullOrWhiteSpace($LegacyPath) -and -not (Test-Path -LiteralPath $PreferredPath) -and (Test-Path -LiteralPath $LegacyPath)) {
        return $LegacyPath
    }

    return $PreferredPath
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
        $advisory = 'Note: command palette or terminal transcript noise was detected and auto-filtered/truncated; diagnose the root cause before continuing the recovery flow.'
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
    foreach ($key in @('run_dir', 'supervisor_log', 'companion_log', 'guard_log', 'guard_state', 'live_status')) {
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
            if ($roleToken -eq 'supervisor' -and $line -match 'heartbeat.*stage=([A-Z]).*row_count=([0-9]+).*file_count=([0-9]+).*latest_path=([^ ]+).*remote_chain_count=([0-9]+)') {
                $leaf = Get-PathLeafToken -Token $Matches[4]
                return ('supervisor={0} stage={1} rows={2} files={3} chain={4} latest={5}' -f $time, $Matches[1], $Matches[2], $Matches[3], $Matches[5], $leaf)
            }

            if ($roleToken -eq 'companion' -and $line -match 'heartbeat.*stage=([A-Z]).*row_count=([0-9]+).*file_count=([0-9]+).*latest_path=([^ ]+).*remote_chain_count=([0-9]+)') {
                $leaf = Get-PathLeafToken -Token $Matches[4]
                return ('companion={0} stage={1} rows={2} files={3} chain={4} latest={5}' -f $time, $Matches[1], $Matches[2], $Matches[3], $Matches[5], $leaf)
            }

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
        $restorePreviousWindowHandles = ''
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
    $ipcPriority = if ($eventNormalized -eq 'running-status-report') { 'normal' } else { 'high' }
    if ($null -ne $Settings -and $Settings.Contains('AI_CHAT_DISPATCH_IPC_PRIORITY')) {
        $configuredPriority = (Convert-ToSingleLineText -Text ([string]$Settings.AI_CHAT_DISPATCH_IPC_PRIORITY)).ToLowerInvariant()
        if ($configuredPriority -in @('normal', 'high')) {
            $ipcPriority = $configuredPriority
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

        $pythonRestoreHandlesForFallback = ''
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

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Assert-Ps51Utf8BomCompatibility -ScriptPath $MyInvocation.MyCommand.Path -ScriptRole 'dispatch_takeover_to_chat.ps1'
$dispatchRoot = Join-Path $script:RepoRoot 'out\artifacts\ab_agent_queue\chat_dispatch'
New-Item -ItemType Directory -Path $dispatchRoot -Force | Out-Null

$startFilePath = Resolve-RepoPathAllowMissing -Path $StartFile
$startToken = Get-StableStartFileToken -StartFilePath $startFilePath
$legacyStartToken = Get-LegacyStartFileToken -StartFilePath $startFilePath
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
$sessionClosedByFlagRaw = $false
if ($startSettings.Contains('SESSION_CLOSED')) {
    $sessionClosedByFlagRaw = Convert-ToBooleanSetting -Value ([string]$startSettings.SESSION_CLOSED) -Default $false
}
$sessionClosedByPassFinal = ($sessionStatus -eq 'PASS') -or ($aStatus -eq 'PASS' -and $bStatus -eq 'PASS')
$sessionClosedByFlag = $sessionClosedByFlagRaw -and $sessionClosedByPassFinal

$dispatchAnchors = Get-DispatchAnchorMap -Settings $startSettings

$supervisorLogPath = Resolve-RepoPathAllowMissing -Path ([string]$dispatchAnchors.supervisor_log)
if ([string]::IsNullOrWhiteSpace($supervisorLogPath) -or -not (Test-Path -LiteralPath $supervisorLogPath)) {
    $supervisorLogPath = Get-LatestArtifactFilePath -RootRelative 'out\artifacts\ab_supervisor' -FileName 'supervisor.log'
}

$companionLogPath = Resolve-RepoPathAllowMissing -Path ([string]$dispatchAnchors.companion_log)
if ([string]::IsNullOrWhiteSpace($companionLogPath) -or -not (Test-Path -LiteralPath $companionLogPath)) {
    $companionLogPath = Get-LatestArtifactFilePath -RootRelative 'out\artifacts\ab_companion' -FileName 'companion.log'
}

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
    $liveStatusPath = Get-LatestArtifactFilePath -RootRelative 'out\artifacts\ab_supervisor' -FileName 'live_status.json'
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

$runningStatusSupervisorHeartbeat = Get-LatestHeartbeatDigest -Role 'supervisor' -LogPath $supervisorLogPath
$runningStatusCompanionHeartbeat = Get-LatestHeartbeatDigest -Role 'companion' -LogPath $companionLogPath
$runningStatusGuardHeartbeat = Get-LatestHeartbeatDigest -Role 'guard' -LogPath $guardLogPath

$runningStatusStateSummary = "SESSION={0}, A={1}, B={2}" -f (Get-CompactStatusToken -Value $sessionStatus), (Get-CompactStatusToken -Value $aStatus), (Get-CompactStatusToken -Value $bStatus)
$runningStatusBExitDigest = Get-StageExitDigest -StageName 'B'
$runningStatusBExitDigestRequired = if ([string]::IsNullOrWhiteSpace($runningStatusBExitDigest)) {
    'B_EXIT=unknown'
}
else {
    $runningStatusBExitDigest
}
$runningStatusHeartbeatSummary = "{0}; {1}; {2}" -f $runningStatusSupervisorHeartbeat, $runningStatusCompanionHeartbeat, $runningStatusGuardHeartbeat
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
    'a-pass-conclusion-b-started',
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

$runningStatusFullMessageEn = @'
[FULL-RUNBOOK] Keep this chat session active in "event-driven + 10-minute status tickets + proactive heartbeat" mode. Do not end the session. Keep the start-file encoded as UTF-8 with BOM + LF line endings. For every incident/status ticket, report root cause plus exact remediation path first. For running-status-report, execute only the provided business_command as health check and then continue_watch_command; do not stage-restart A/B from this status ticket unless a separate incident ticket is raised. Ticket-level mandatory receipt: after completing each ticket cycle, MUST return handled_at (YYYY-MM-DD HH:mm:ss). For running-status-report, handled_at must be returned immediately after business/continue_watch and cannot be omitted even when monitoring continues. Session-level closure receipt is separate: return session_closed_at only when I explicitly say "stop monitoring" or both A and B are terminal. If a script fault is found, you may fix the script directly and perform bounded closed-loop auto-repair (fix -> restart -> verify -> record). Read tickets from LOCAL_GUARD_AGENT_QUEUE_PATH (default out/artifacts/ab_agent_queue/agent_tickets.jsonl) and actively poll every round via tools/test/poll_agent_tickets.ps1. After each handling action, switch to read-only watch mode and keep monitoring with 10-minute heartbeat + poll cadence (do not repeatedly restart guard): heartbeat via tools/test/update_chat_session_heartbeat.ps1, poll in read-heartbeat mode (AI_CHAT_HEARTBEAT_WRITE_ON_POLL=false). Report every 10 minutes (include main_round, event_policy_strict_mode, event_policy_adjustments, and heartbeat summary; text label chat_heartbeat; JSON key chat_session_heartbeat). If strict policy is violated, fix LOCAL_GUARD_POLL_* settings first, then continue. Only stop when both A and B reach terminal states or I explicitly say "stop monitoring". When sending final session closure, include the session end date/time explicitly.
'@
$runningStatusShortMessageEn = '[SHORT-CARD] Ticket {0} (event={1}). Read {2}. 1) Report root cause + remediation in one concise block. For a healthy running-status-report, root cause is "no active fault / routine status ticket" and remediation is "continue watch only". 2) Run the provided business_command as health check, then continue_watch_command; do not stage-restart A/B from this status ticket unless a separate incident ticket is raised. 3) Return to read-only watch (10-minute heartbeat + poll) until "stop monitoring". Do not ask for extra approval to continue polling/watch. 4) Mandatory receipts: always return handled_at (YYYY-MM-DD HH:mm:ss) after this ticket cycle; for running-status-report, handled_at must be returned immediately after business/continue_watch; return session_closed_at only when stop monitoring is requested or both A/B are terminal, and include the explicit session end date/time in the final closure message. Do not infer a B restart from stale exit artifacts. Do not create ad-hoc handled/heartbeat files and do not create new scripts outside tmp. Return chat_heartbeat fields: SESSION/A/B, run_dir, main_round, supervisor/companion/guard latest heartbeats, B exit digest. Status: {3}.'
$finalStatusSummaryMessageEn = 'A/B tasks are complete. Please take over ticket {0} (event={1}), read {2} first, then summarize unattended execution and completion (execution window, status-ticket handling, root cause/remediation, key recovery actions, chat_heartbeat, ACK receipts, final conclusion). Include the explicit session end date/time in the final closure message. Status summary: {3}.'
$taskDefinitionFixMessageEn = 'Please take over ticket {0} (event={1}) and read {2} first. Diagnose whether the root cause is a mismatch between task-definition and current source shape (for example, CODE-STEP expected exactly one match, actual=0), then provide the minimal fix. Only modify task definition files under testdata; do not change business source code. After fixing, run required validation, restart phase B by procedure, continue monitoring, and return chat_heartbeat plus a fix conclusion.'
$runningStatusFullWrapMessageEn = 'Please take over ticket {0} (event={1}) and read {2} first. {3} Current status summary: {4}.'
$genericRecoveryMessageEn = 'Please take over ticket {0} (event={1}) and execute recovery by {2}: read {3} first, report root cause plus remediation method, and if self-healable without budget/cooldown exhaustion or nonrecoverable environment, trigger business_resume immediately. After handling, keep read-only monitoring with 10-minute heartbeat + poll cadence until "stop monitoring", and apply D1 90/30/10/20 rules.'

$runningStatusFullMessageZh = @'
[FULL-RUNBOOK] 请保持当前会话持续运行，并采用“事件驱动 + 每 10 分钟状态票 + 主动心跳”模式；不要结束会话。保持 start-file 为 UTF-8 with BOM 编码 + LF 行尾。对每一张事件票/状态票，先汇报根因与明确修复路径。对于 running-status-report，只执行已给出的 business_command 作为健康检查，再执行 continue_watch_command；除非出现独立事故票据，否则不得从该状态票发起 A/B 阶段重启。票级强制回执：每张票完成当轮动作后必须回传 handled_at（YYYY-MM-DD HH:mm:ss）。对于 running-status-report，执行完 business/continue_watch 后必须立即回传 handled_at，即使会话继续监控也不得省略。会话级收尾回执与票级分离：仅在我明确下达“stop monitoring”或 A/B 均终态时回传 session_closed_at。对 healthy 的 running-status-report，根因应明确写成“无活动故障/常规定时状态票”，修复路径应明确写成“continue_watch only”，不得仅凭旧的 exit 日志、旧失败摘要或残留 latest_b_exit.json 推断需要重启 B。若发现脚本故障，可直接修复并执行有界闭环自愈（fix -> restart -> verify -> record）。每轮都要从 LOCAL_GUARD_AGENT_QUEUE_PATH（默认 out/artifacts/ab_agent_queue/agent_tickets.jsonl）主动轮询票据（tools/test/poll_agent_tickets.ps1）。每次处置后切回只读盯盘，按“10 分钟心跳 + 轮询”持续监控（避免频繁重启 guard）：心跳通过 tools/test/update_chat_session_heartbeat.ps1 发送，poll 保持 read-heartbeat 模式（AI_CHAT_HEARTBEAT_WRITE_ON_POLL=false）。每 10 分钟回报一次（包含 main_round、event_policy_strict_mode、event_policy_adjustments 及心跳摘要；文本标签 chat_heartbeat；JSON 键 chat_session_heartbeat）。运行期不得再询问是否继续轮询/继续监控，也不得在未获明确要求时提出 PR、服务化改造、额外脚本方案。不得手工创建 chat_heartbeat*.jsonl、handled_tickets/*.md 等临时回执产物；仅使用现有 heartbeat/poll 脚本。若 strict 策略被破坏，先修复 LOCAL_GUARD_POLL_* 配置再继续。仅当 A 与 B 都达到终态，或我明确说“stop monitoring”时才停止。会话最终收尾时，需显式上报会话结束日期时间。
'@
$runningStatusShortMessageZh = '[SHORT-CARD] 票据 {0}（event={1}），先读 {2}。1）用一段话先报根因+修复路径；若本票是 healthy 的 running-status-report，根因应写“无活动故障/常规定时状态票”，修复路径应写“continue_watch only”。2）执行已给出的 business_command 作为健康检查，然后执行 continue_watch_command；除非出现独立事故票据，否则不得从该状态票发起 A/B 阶段重启。3）处置后回到只读盯盘（10 分钟心跳+轮询），直到“stop monitoring”，不要再询问是否继续轮询/监控。4）强制回执：本票当轮动作完成后必须回传 handled_at（YYYY-MM-DD HH:mm:ss）；running-status-report 在 business/continue_watch 后必须立即回传 handled_at；session_closed_at 仅在 stop monitoring 或 A/B 终态时回传，且最终收尾消息必须显式写出会话结束日期时间。不得仅凭旧 exit 证据推断需要重启 B；不得手工创建 chat_heartbeat/handled 临时回执文件；不得在未获同意时创建非 tmp 新脚本。回传 chat_heartbeat：SESSION/A/B、run_dir、main_round、supervisor/companion/guard 最新心跳、B exit digest。状态：{3}。'
$runningStatusLowDisturbMessageEn = '[LOW-DISTURB] Ticket {0} (event={1}). Read {2} first, then run only the minimal health check from business_command: current run status plus live main process and monitor-chain processes (supervisor/companion/guard/trigger), and do not treat lingering -NoExit shells as healthy stage processes. If the result is healthy and no repair/restart is triggered, reply with only two lines: "Running normal" and "handled_at: YYYY-MM-DD HH:mm:ss". If the result is abnormal, or any self-heal/fault-handling action is triggered, switch to normal status-report style: explain root cause, remediation/self-heal actions, current status, then return handled_at.'
$runningStatusLowDisturbMessageZh = '[LOW-DISTURB] 票据 {0}（event={1}），先读 {2}，然后只执行 business_command 中的最小健康检查：当前运行状态，以及主进程与监控链进程（supervisor/companion/guard/trigger）是否真实存活；不要把残留的 -NoExit 空壳 shell 当作阶段主进程健康。若检查结果正常，且没有触发任何自愈/重启/故障处理动作，则根因视为“无活动故障/常规定时状态票”，不要建议重启 B，回复内容只保留两行："运行正常" 和 "handled_at: YYYY-MM-DD HH:mm:ss"。若检查结果异常，或触发了自愈修复/故障处理，则立即切换为 normal 状态票口径回复：说明根因、修复/自愈动作、当前运行状态，然后回传 handled_at。不得手工创建 chat_heartbeat/handled 临时回执文件，也不得在未获同意时创建非 tmp 新脚本。'
$finalStatusSummaryMessageZh = 'A/B 任务已完成。请接管票据 {0}（event={1}），先阅读 {2}，然后总结本次无人值守执行与收尾（执行窗口、状态票处理、根因与修复、关键恢复动作、chat_heartbeat、ACK 回执、最终结论）。最终收尾消息中必须显式写出会话结束日期时间。状态摘要：{3}。'
$taskDefinitionFixMessageZh = '请接管票据 {0}（event={1}），先阅读 {2}。请诊断根因是否为 task-definition 与当前源码形态不匹配（例如 CODE-STEP expected exactly one match, actual=0），并给出最小修复。仅允许修改 testdata 下任务定义文件，不改业务源码。修复后执行必要验证，按流程重启 B 阶段并继续监控，最后回传 chat_heartbeat 与修复结论。'
$runningStatusFullWrapMessageZh = '请接管票据 {0}（event={1}），先阅读 {2}。{3} 当前状态摘要：{4}。'
$genericRecoveryMessageZh = '请接管票据 {0}（event={1}），按 {2} 执行恢复：先阅读 {3}，先汇报根因与修复方法；若可自愈且未触发预算/冷却耗尽且非不可恢复环境，立即触发 business_resume。处置后进入只读盯盘，按 10 分钟心跳 + 轮询持续监控，直到“stop monitoring”，并执行 D1 90/30/10/20 规则。'

$runningStatusFullMessage = if ($useChineseDispatchMessage) { $runningStatusFullMessageZh } else { $runningStatusFullMessageEn }
$runningStatusShortMessage = if ($useChineseDispatchMessage) { $runningStatusShortMessageZh } else { $runningStatusShortMessageEn }
$runningStatusLowDisturbMessage = if ($useChineseDispatchMessage) { $runningStatusLowDisturbMessageZh } else { $runningStatusLowDisturbMessageEn }
$finalStatusSummaryMessage = if ($useChineseDispatchMessage) { $finalStatusSummaryMessageZh } else { $finalStatusSummaryMessageEn }
$taskDefinitionFixMessage = if ($useChineseDispatchMessage) { $taskDefinitionFixMessageZh } else { $taskDefinitionFixMessageEn }
$runningStatusFullWrapMessage = if ($useChineseDispatchMessage) { $runningStatusFullWrapMessageZh } else { $runningStatusFullWrapMessageEn }
$genericRecoveryMessage = if ($useChineseDispatchMessage) { $genericRecoveryMessageZh } else { $genericRecoveryMessageEn }

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
$runningStatusUseFullMessage = $false
$runningStatusEffectiveMode = 'n/a'
$dispatchDeliveryProfile = ''
if ($startSettings.Contains('AI_CHAT_DISPATCH_DELIVERY_PROFILE')) {
    $dispatchDeliveryProfile = (Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_DISPATCH_DELIVERY_PROFILE)).ToLowerInvariant()
}
$policyWorkMode = ''
if ($startSettings.Contains('AI_CHAT_POLICY_WORK_MODE')) {
    $policyWorkMode = (Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_POLICY_WORK_MODE)).ToLowerInvariant()
}
$lowDisturbRunningStatus = ($eventNormalized -eq 'running-status-report' -and ($policyWorkMode -eq 'low-disturb' -or $dispatchDeliveryProfile -eq 'low-disturb'))
if ($eventNormalized -eq 'running-status-report') {
    if ($lowDisturbRunningStatus) {
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
    if ($lowDisturbRunningStatus) {
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
    $firstMessage = $taskDefinitionFixMessage -f $TicketId, $TicketEvent, $dispatchReadContextText
}
else {
    $firstMessage = $genericRecoveryMessage -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText
}

$dispatchMessage = $firstMessage
$dispatchMessageMode = $runningStatusEffectiveMode

$dispatchSanitizeResult = Format-DispatchMessage -Message $dispatchMessage -AppendAdvisory $true
$dispatchMessage = [string]$dispatchSanitizeResult.message
$firstMessage = $dispatchMessage
if ([bool]$dispatchSanitizeResult.sanitized) {
    Write-DispatchLog ("dispatch_message_sanitized event={0} removed_lines={1} inline_replacements={2} transcript_blocks_removed={3} transcript_lines_removed={4} deduped_lines={5} truncated={6} rules={7}" -f $TicketEvent, [int]$dispatchSanitizeResult.removed_lines, [int]$dispatchSanitizeResult.inline_replacements, [int]$dispatchSanitizeResult.transcript_blocks_removed, [int]$dispatchSanitizeResult.transcript_lines_removed, [int]$dispatchSanitizeResult.deduped_lines, [bool]$dispatchSanitizeResult.truncated, [string]$dispatchSanitizeResult.rule_summary)
}

$resumeCommand = ''
$guardCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}" -NoRestartIfRunning' -f $startFileRel
if ($eventNormalized -ne 'running-status-report' -and $eventNormalized -ne 'chat-session-final-status') {
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
Write-Utf8BomFile -Path $relayPath -Value $relayLines

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
    first_message = $firstMessage
    dispatch_message = $dispatchMessage
}
Write-Utf8BomFile -Path $latestStatePath -Value ($latestState | ConvertTo-Json -Depth 8)

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

