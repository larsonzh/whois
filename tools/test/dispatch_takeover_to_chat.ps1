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

    $command = ''
    if ($targetStage -eq 'B') {
        $command = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartFile "{0}" -StartMonitors -EnableBMonitorRestart' -f $StartFileRel
    }
    else {
        $command = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_resume_window.ps1 -StartFile "{0}" -StartMonitors' -f $StartFileRel
    }

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
        $advisory = '注：检测到命令面板或终端 transcript 噪声片段并已自动过滤/截断；请先排查根因后再继续恢复流程。'
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

function Get-LatestAnchorValueFromNotes {
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
        $anchors[$key] = Get-LatestAnchorValueFromNotes -Notes $notes -Key $key
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
        [int]$TimeoutMs = 12000,
        [System.Collections.IDictionary]$Settings = $null,
        [AllowEmptyString()][string]$EventName = '',
        [bool]$HeartbeatTimeoutRequireCodeFocus = $true,
        [bool]$StatusReportAllowInconclusiveSubmit = $true,
        [bool]$RestorePreviousForegroundWindow = $true,
        [int]$RestorePreviousForegroundWindowCount = 12,
        [bool]$ActiveWindowOnly = $false,
        [bool]$StatusReportForcePaletteFocus = $false,
        [bool]$StatusReportClickRecoveryOnly = $false,
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
        [int]$TimeoutMs = 12000,
        [System.Collections.IDictionary]$Settings = $null,
        [AllowEmptyString()][string]$EventName = '',
        [bool]$StatusReportAllowInconclusiveSubmit = $true,
        [bool]$RestorePreviousForegroundWindow = $true,
        [int]$RestorePreviousForegroundWindowCount = 12,
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
    }
    else {
        [void]$invokeArgs.Add('--NoRestorePreviousForegroundWindow')
    }

    if ($ActiveWindowOnly) {
        [void]$invokeArgs.Add('--NoActivateWindow')
        [void]$invokeArgs.Add('--RequireActiveCodeWindow')
    }

    $eventNormalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
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

    if ($null -ne $Settings) {
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
    }

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
            $dispatchJob = Start-Job -ScriptBlock {
                param(
                    [string]$PythonPath,
                    [string[]]$Arguments
                )

                & $PythonPath @Arguments 2>&1
            } -ArgumentList $PythonExecutable, ([string[]]$invokeArgs.ToArray())

            $watchdogWaitSec = [Math]::Max(5, [int][Math]::Ceiling([double]$pythonWatchdogTimeoutMs / 1000.0))
            $completedJob = Wait-Job -Job $dispatchJob -Timeout $watchdogWaitSec

            if ($null -eq $completedJob) {
                $watchdogTimedOut = $true
                try {
                    Stop-Job -Job $dispatchJob -Force -ErrorAction SilentlyContinue | Out-Null
                }
                catch {
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

        $restorePreviousWindowCountRequested = Convert-ToIntRangeSetting -Value ([string]$sendResult.restore_previous_window_count_requested) -Default 0 -Min 0 -Max 30
        $restorePreviousWindowCountCaptured = Convert-ToIntRangeSetting -Value ([string]$sendResult.restore_previous_window_count_captured) -Default 0 -Min 0 -Max 30
        $restorePreviousWindowHandles = ''
        $restorePreviousWindowCaptureSummary = Convert-ToSingleLineText -Text ([string]$sendResult.restore_previous_window_capture_summary)
        $restorePreviousWindowActivationTrace = Convert-ToSingleLineText -Text ([string]$sendResult.restore_previous_window_activation_trace)
        $restorePreviousWindowActivationCountAttempted = Convert-ToIntRangeSetting -Value ([string]$sendResult.restore_previous_window_activation_count_attempted) -Default 0 -Min 0 -Max 30
        $restorePreviousWindowActivationCountSucceeded = Convert-ToIntRangeSetting -Value ([string]$sendResult.restore_previous_window_activation_count_succeeded) -Default 0 -Min 0 -Max 30
        $restorePreviousWindowActivationFinalForegroundHandle = [Int64](Convert-ToIntRangeSetting -Value ([string]$sendResult.restore_previous_window_activation_final_foreground_handle) -Default 0 -Min 0 -Max 2147483647)
        $restorePreviousWindowActivationRestoreExecuted = [bool]$sendResult.restore_previous_window_activation_restore_executed
        $restorePreviousWindowActivationSkippedReason = Convert-ToSingleLineText -Text ([string]$sendResult.restore_previous_window_activation_skipped_reason)

        if ($sendResult.PSObject.Properties['restore_previous_window_handles']) {
            $handles = @($sendResult.restore_previous_window_handles)
            if ($handles.Count -gt 0) {
                $restorePreviousWindowHandles = Convert-ToSingleLineText -Text (($handles | ForEach-Object { [string]$_ }) -join ',')
            }
        }

        if ([string]::IsNullOrWhiteSpace($restorePreviousWindowHandles) -and $sendResult.PSObject.Properties['code_focus_policy'] -and $null -ne $sendResult.code_focus_policy) {
            $policyHandles = Get-ObjectMemberValue -Container $sendResult.code_focus_policy -MemberName 'restore_previous_window_handles'
            $handles = @($policyHandles)
            if ($handles.Count -gt 0) {
                $restorePreviousWindowHandles = Convert-ToSingleLineText -Text (($handles | ForEach-Object { [string]$_ }) -join ',')
            }
        }

        if ($restorePreviousWindowCountRequested -le 0 -and $RestorePreviousForegroundWindow) {
            $restorePreviousWindowCountRequested = [Math]::Min(30, [Math]::Max(1, $RestorePreviousForegroundWindowCount))
        }
        if ($restorePreviousWindowCountCaptured -le 0 -and -not [string]::IsNullOrWhiteSpace($restorePreviousWindowHandles)) {
            $handleItems = @($restorePreviousWindowHandles -split ',' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $restorePreviousWindowCountCaptured = [Math]::Min(30, $handleItems.Count)
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

function Invoke-ConfiguredChatDispatch {
    param(
        [ValidateSet('ahk', 'python')][string]$SenderMode,
        [AllowEmptyString()][string]$AhkExecutable,
        [AllowEmptyString()][string]$PythonExecutable,
        [string]$Message,
        [int]$TimeoutMs = 12000,
        [System.Collections.IDictionary]$Settings = $null,
        [AllowEmptyString()][string]$EventName = '',
        [bool]$HeartbeatTimeoutRequireCodeFocus = $true,
        [bool]$StatusReportAllowInconclusiveSubmit = $true,
        [bool]$RestorePreviousForegroundWindow = $true,
        [int]$RestorePreviousForegroundWindowCount = 12,
        [bool]$ActiveWindowOnly = $false,
        [bool]$StatusReportForcePaletteFocus = $false,
        [bool]$StatusReportClickRecoveryOnly = $false,
        [bool]$ForceFocusRecovery = $false
    )

    if ($SenderMode -eq 'python') {
        $pythonResult = Invoke-PythonChatDispatch -PythonExecutable $PythonExecutable -Message $Message -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -StatusReportAllowInconclusiveSubmit $StatusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $ForceFocusRecovery

        if ($null -eq $pythonResult) {
            return $pythonResult
        }

        $pythonReason = Convert-ToSingleLineText -Text ([string]$pythonResult.reason)
        $watchdogTimedOut = $false
        if ($pythonResult.PSObject.Properties['watchdog_timeout']) {
            $watchdogTimedOut = [bool]$pythonResult.watchdog_timeout
        }
        if (-not $watchdogTimedOut -and $pythonReason.ToLowerInvariant().StartsWith('python-watchdog-timeout')) {
            $watchdogTimedOut = $true
        }

        if ($watchdogTimedOut) {
            $ahkReady = (-not [string]::IsNullOrWhiteSpace($AhkExecutable)) -and (Test-Path -LiteralPath $AhkExecutable)
            if ($ahkReady) {
                $ahkFallback = Invoke-AhkChatDispatch -AhkExecutable $AhkExecutable -Message $Message -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -HeartbeatTimeoutRequireCodeFocus $HeartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $StatusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $ForceFocusRecovery

                $ahkReason = Convert-ToSingleLineText -Text ([string]$ahkFallback.reason)
                if ([string]::IsNullOrWhiteSpace($pythonReason)) {
                    $pythonReason = 'python-watchdog-timeout'
                }
                if ([string]::IsNullOrWhiteSpace($ahkReason)) {
                    $ahkReason = 'fallback-unsent'
                }
                $ahkFallback.reason = ('python-watchdog-fallback python_reason={0};ahk_reason={1}' -f $pythonReason, $ahkReason)
                return $ahkFallback
            }

            $pythonResult.reason = if ([string]::IsNullOrWhiteSpace($pythonReason)) {
                'python-watchdog-timeout;ahk-fallback-unavailable'
            }
            else {
                '{0};ahk-fallback-unavailable' -f $pythonReason
            }
        }

        return $pythonResult
    }

    return Invoke-AhkChatDispatch -AhkExecutable $AhkExecutable -Message $Message -TimeoutMs $TimeoutMs -Settings $Settings -EventName $EventName -HeartbeatTimeoutRequireCodeFocus $HeartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $StatusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $RestorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $RestorePreviousForegroundWindowCount -ActiveWindowOnly $ActiveWindowOnly -StatusReportForcePaletteFocus $StatusReportForcePaletteFocus -StatusReportClickRecoveryOnly $StatusReportClickRecoveryOnly -ForceFocusRecovery $ForceFocusRecovery
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

$usePythonDispatch = $UsePythonSender.IsPresent
$useAhkDispatch = $UseAhk.IsPresent

if (-not $usePythonDispatch -and -not $useAhkDispatch -and $startSettings.Contains('AI_CHAT_DISPATCH_USE_PY_SENDER')) {
    $usePythonDispatch = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_USE_PY_SENDER) -Default $false
}

if (-not $usePythonDispatch -and -not $useAhkDispatch -and $startSettings.Contains('AI_CHAT_DISPATCH_USE_AHK')) {
    $useAhkDispatch = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_USE_AHK) -Default $false
}

if ($usePythonDispatch -and $useAhkDispatch) {
    $useAhkDispatch = $false
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
if ($usePythonDispatch) {
    $pythonExecutable = Resolve-PythonExecutablePath -ConfiguredPath $configuredPythonPath -StrictConfiguredPath:$strictConfiguredPythonPath
    if ([string]::IsNullOrWhiteSpace($pythonExecutable)) {
        if ($strictConfiguredPythonPath) {
            Write-DispatchLog ("python_dispatch_enabled_but_configured_executable_missing configured_path={0}" -f (Convert-ToSingleLineText -Text $configuredPythonPath))
        }
        else {
            Write-DispatchLog 'python_dispatch_enabled_but_executable_missing'
        }
    }
}

$dispatchSenderMode = if ($usePythonDispatch) { 'python' } elseif ($useAhkDispatch) { 'ahk' } else { 'none' }
$interactiveDispatchEnabled = $dispatchSenderMode -ne 'none'
Write-DispatchLog ("dispatch_sender_config mode={0} use_ahk={1} use_python={2} ahk_exe={3} python_exe={4}" -f $dispatchSenderMode, $useAhkDispatch, $usePythonDispatch, (Convert-ToSingleLineText -Text $ahkExecutable), (Convert-ToSingleLineText -Text $pythonExecutable))

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
    '{0} 与 {1}' -f $dispatchReadContextPath, $queueRel
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

$runningStatusFullMessage = @'
从现在起，会话内代理按“事件驱动 + 每 10 分钟状态票 + 主动心跳”节奏维持监控与汇报，不要结束会话；修改 start-file 用 UTF-8 编码；发现脚本故障可直接修复脚本，并可在预算内执行闭环自动修复代码（修复->重启->复核->记录）；工单从 LOCAL_GUARD_AGENT_QUEUE_PATH（默认 out/artifacts/ab_agent_queue/agent_tickets.jsonl）读取，并通过 tools/test/poll_agent_tickets.ps1 每轮主动拉取；每次取到工单后按先 business_command、后 continue_watch_command 的顺序逐条执行（business_command 为空则仅执行 continue_watch_command）；会话内需定时主动调用 tools/test/update_chat_session_heartbeat.ps1 发送心跳（建议每 5~10 分钟一次，并在关键恢复动作后补发一次），poll 保持读心跳模式（AI_CHAT_HEARTBEAT_WRITE_ON_POLL=false）；每 10 分钟汇报一次（包含 main_round、event_policy_strict_mode、event_policy_adjustments 与心跳摘要，文本标签为 chat_heartbeat，JSON 键为 chat_session_heartbeat）；若 strict 违规先修正 LOCAL_GUARD_POLL_* 配置再继续；仅在 A/B 都到终态或我明确下达“停止监控”时结束。
'@
$runningStatusShortMessage = '请接管工单 {0}（event={1}），先读取 {2}；这是每10分钟状态票，请按既定事件驱动与轮询流程执行（business_command -> continue_watch_command，business 为空则仅 continue），并回传 chat_heartbeat（强制字段：SESSION/A/B、run_dir、main_round、supervisor/companion/guard 最新心跳、B exit digest）。状态摘要：{3}。'
$finalStatusSummaryMessage = 'A/B 任务已完成，请接管工单 {0}（event={1}），先读取 {2}；然后总结本次无人值守任务执行和完成情况（执行区间、状态票处理、关键恢复动作、chat_heartbeat、ACK 回执、最终结论）。状态摘要：{3}。'
$taskDefinitionFixMessage = '请接管工单 {0}（event={1}），先读取 {2}；先做诊断并确认 root cause 是否为 task-definition 与当前源码形态不匹配（例如 CODE-STEP expected exactly one match, actual=0），再给出最小修改方案；仅允许修改 testdata 任务定义文件，不改业务源码；修复后先做必要校验，再按流程重启 B 阶段并继续监控，最后回传 chat_heartbeat 与修复结论。'
$runningStatusUseFullMessage = $false
$runningStatusEffectiveMode = 'n/a'
if ($eventNormalized -eq 'running-status-report') {
    $runningStatusEffectiveMode = 'short'
    if ($statusReportMessageMode -eq 'full') {
        $runningStatusUseFullMessage = $true
        $runningStatusEffectiveMode = 'full'
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
}
if ($eventNormalized -eq 'running-status-report') {
    if ($runningStatusUseFullMessage) {
        $firstMessage = "请接管工单 {0}（event={1}），先读取 {2}。{3} 当前状态摘要：{4}。" -f $TicketId, $TicketEvent, $dispatchReadContextText, $runningStatusFullMessage, $runningStatusShortSummary
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
    $firstMessage = "请接管工单 {0}（event={1}），按 {2} 执行恢复：先读取 {3}，然后继续按事件驱动与定时状态票节奏监控并按 D1 90/30/10/20 规则处理。" -f $TicketId, $TicketEvent, $startFileRel, $dispatchReadContextText
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
    status_report_dispatch_message_mode = $dispatchMessageMode
    first_message = $firstMessage
    dispatch_message = $dispatchMessage
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

if ($interactiveDispatchEnabled -and -not $suppressInteractiveActions -and $ahkAllowedByEvent) {
    $ahkDispatchTried = $true
    $ahkResult = Invoke-ConfiguredChatDispatch -SenderMode $dispatchSenderMode -AhkExecutable $ahkExecutable -PythonExecutable $pythonExecutable -Message $dispatchMessage -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $statusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $activeWindowOnly
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

        $fallbackResult = Invoke-ConfiguredChatDispatch -SenderMode $dispatchSenderMode -AhkExecutable $ahkExecutable -PythonExecutable $pythonExecutable -Message $dispatchMessage -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $statusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $false
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
    $shouldRetryWithPaletteFocus = (-not $ahkDispatchSent) -and ($eventNormalized -eq 'running-status-report') -and (
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
        Write-DispatchLog ("ahk_dispatch_palette_retry ticket={0} reason=focus-validation-failed" -f $TicketId)

        $paletteFallbackResult = Invoke-ConfiguredChatDispatch -SenderMode $dispatchSenderMode -AhkExecutable $ahkExecutable -PythonExecutable $pythonExecutable -Message $dispatchMessage -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $statusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $false -StatusReportClickRecoveryOnly $true
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

        $focusGuardFallbackResult = Invoke-ConfiguredChatDispatch -SenderMode $dispatchSenderMode -AhkExecutable $ahkExecutable -PythonExecutable $pythonExecutable -Message $dispatchMessage -TimeoutMs $AhkTimeoutMs -Settings $startSettings -EventName $eventNormalized -HeartbeatTimeoutRequireCodeFocus $heartbeatTimeoutRequireCodeFocus -StatusReportAllowInconclusiveSubmit $statusReportAllowInconclusiveSubmit -RestorePreviousForegroundWindow $restorePreviousForegroundWindow -RestorePreviousForegroundWindowCount $restorePreviousForegroundWindowCount -ActiveWindowOnly $false -ForceFocusRecovery $true
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

Write-DispatchLog ("relay_created ticket={0} event={1} relay={2} brief_exists={3} clipboard={4} clipboard_enabled={5} editor_opened={6} editor_enabled={7} chat_open_tried={8} chat_open_started={9} interactive_suppressed={10} status_report_interactive_enabled={11} use_ahk={12} ahk_allowed_by_event={13} ahk_event_allowlist={14} heartbeat_timeout_send_enabled={15} heartbeat_timeout_require_code_focus={16} active_window_only={17} new_code_main_detected={18} new_code_main_closed={19} new_code_window_configs_detected={20} new_code_window_pids_closed={21} ahk_tried={22} ahk_sent={23} ahk_exit_code={24} ahk_reason={25} ahk_esc_preflight_enabled={26} ahk_focus_guard_fallback_triggered={27} ahk_focus_guard_fallback_sent={28} ahk_focus_guard_fallback_exit_code={29} ahk_focus_guard_fallback_reason={30} ahk_restore_requested={31} ahk_restore_captured={32} ahk_restore_handles={33}" -f $TicketId, $TicketEvent, $relayRel, $briefExists, $clipboardApplied, $useClipboardByPolicy, $editorOpened, $openEditorByPolicy, $chatOpenTried, $chatOpenStarted, $suppressInteractiveActions, $statusReportInteractiveEnabled, $useAhkDispatch, $ahkAllowedByEvent, (($ahkEventAllowList -join ';')), $heartbeatTimeoutSendEnabled, $heartbeatTimeoutRequireCodeFocus, $activeWindowOnly, ($newCodeMainDetected -join ','), ($newCodeMainClosed -join ','), ($newCodeWindowConfigsDetected -join ','), ($newCodeWindowPidsClosed -join ','), $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkEscPreflightEnabled, $ahkFocusGuardFallbackTriggered, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason, $ahkRestorePreviousWindowCountRequested, $ahkRestorePreviousWindowCountCaptured, $ahkRestorePreviousWindowHandles)
Write-DispatchLog ("dispatch_sender_result ticket={0} sender_mode={1} use_python={2} tried={3} sent={4} exit_code={5} reason={6}" -f $TicketId, $dispatchSenderMode, $usePythonDispatch, $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason)
Write-DispatchLog ("dispatch_sender_metrics ticket={0} sender_mode={1} sender_tried={2} sender_sent={3} sender_exit_code={4} sender_reason={5} sender_attempts={6} sender_auto_resend_triggered={7} sender_auto_resend_reason={8} sender_esc_preflight_enabled={9} sender_focus_guard_fallback_triggered={10} sender_focus_guard_fallback_sent={11} sender_focus_guard_fallback_exit_code={12} sender_focus_guard_fallback_reason={13} sender_restore_requested={14} sender_restore_captured={15} sender_restore_handles={16}" -f $TicketId, $dispatchSenderMode, $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkDispatchAttemptCount, $ahkAutoResendTriggered, $ahkAutoResendReason, $ahkEscPreflightEnabled, $ahkFocusGuardFallbackTriggered, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason, $ahkRestorePreviousWindowCountRequested, $ahkRestorePreviousWindowCountCaptured, $ahkRestorePreviousWindowHandles)

try {
    $latestState.sender_mode = $dispatchSenderMode
    $latestState.sender_use_python = [bool]$usePythonDispatch
    $latestState.sender_use_ahk = [bool]$useAhkDispatch
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
    $latestState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $latestStatePath -Encoding utf8
}
catch {
    Write-DispatchLog ("latest_state_sender_update_failed path={0} detail={1}" -f (Convert-ToRepoRelativePath -Path $latestStatePath), (Convert-ToSingleLineText -Text $_.Exception.Message))
}

Write-Output ("[CHAT-DISPATCH] ticket={0} event={1} relay={2} first_message_in_clipboard={3} clipboard_enabled={4} editor_opened={5} editor_enabled={6} chat_open_started={7} interactive_suppressed={8}" -f $TicketId, $TicketEvent, $relayRel, $clipboardApplied, $useClipboardByPolicy, $editorOpened, $openEditorByPolicy, $chatOpenStarted, $suppressInteractiveActions)
Write-Output ("[CHAT-DISPATCH] use_ahk={0} status_report_interactive_enabled={1} ahk_allowed_by_event={2} ahk_event_allowlist={3} heartbeat_timeout_send_enabled={4} heartbeat_timeout_require_code_focus={5} active_window_only={6} new_code_main_detected={7} new_code_main_closed={8} new_code_window_configs_detected={9} new_code_window_pids_closed={10} ahk_tried={11} ahk_sent={12} ahk_exit_code={13} ahk_reason={14} ahk_attempts={15} ahk_auto_resend_triggered={16} ahk_auto_resend_reason={17} ahk_esc_preflight_enabled={18} ahk_focus_guard_fallback_triggered={19} ahk_focus_guard_fallback_sent={20} ahk_focus_guard_fallback_exit_code={21} ahk_focus_guard_fallback_reason={22} ahk_restore_requested={23} ahk_restore_captured={24} ahk_restore_handles={25}" -f $useAhkDispatch, $statusReportInteractiveEnabled, $ahkAllowedByEvent, (($ahkEventAllowList -join ';')), $heartbeatTimeoutSendEnabled, $heartbeatTimeoutRequireCodeFocus, $activeWindowOnly, ($newCodeMainDetected -join ','), ($newCodeMainClosed -join ','), ($newCodeWindowConfigsDetected -join ','), ($newCodeWindowPidsClosed -join ','), $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkDispatchAttemptCount, $ahkAutoResendTriggered, $ahkAutoResendReason, $ahkEscPreflightEnabled, $ahkFocusGuardFallbackTriggered, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason, $ahkRestorePreviousWindowCountRequested, $ahkRestorePreviousWindowCountCaptured, $ahkRestorePreviousWindowHandles)
Write-Output ("[CHAT-DISPATCH] sender_mode={0} use_python={1} dispatch_tried={2}" -f $dispatchSenderMode, $usePythonDispatch, $ahkDispatchTried)
Write-Output ("[CHAT-DISPATCH] sender_mode={0} sender_tried={1} sender_sent={2} sender_exit_code={3} sender_reason={4} sender_attempts={5} sender_auto_resend_triggered={6} sender_auto_resend_reason={7} sender_esc_preflight_enabled={8} sender_focus_guard_fallback_triggered={9} sender_focus_guard_fallback_sent={10} sender_focus_guard_fallback_exit_code={11} sender_focus_guard_fallback_reason={12} sender_restore_requested={13} sender_restore_captured={14} sender_restore_handles={15}" -f $dispatchSenderMode, $ahkDispatchTried, $ahkDispatchSent, $ahkDispatchExitCode, $ahkDispatchReason, $ahkDispatchAttemptCount, $ahkAutoResendTriggered, $ahkAutoResendReason, $ahkEscPreflightEnabled, $ahkFocusGuardFallbackTriggered, $ahkFocusGuardFallbackSent, $ahkFocusGuardFallbackExitCode, $ahkFocusGuardFallbackReason, $ahkRestorePreviousWindowCountRequested, $ahkRestorePreviousWindowCountCaptured, $ahkRestorePreviousWindowHandles)

