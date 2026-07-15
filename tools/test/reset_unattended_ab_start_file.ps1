param(
    [string]$StartFile = 'testdata\unattended_start\active\unattended_ab_start_20260504-1123.md',
    [string]$TemplateFile = 'docs\UNATTENDED_AB_START_TEMPLATE_CN.md',
    [AllowEmptyString()][string]$ResetFields = '',
    [switch]$UseDefaultResetFieldList,
    [switch]$UseTemplateBaseline,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'RESET-UNATTENDED-AB-START-FILE'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

function Get-Utf8Text {
    param([string]$Path)

    $encoding = New-Object System.Text.UTF8Encoding($true, $true)
    try {
        return [System.IO.File]::ReadAllText($Path, $encoding)
    }
    catch {
        throw "Failed to read UTF-8 text file: $Path; detail=$($_.Exception.Message)"
    }
}

function Test-Utf8TextReplacementChar {
    param(
        [string]$Text,
        [string]$Path,
        [string]$Tag
    )

    if ($Text -match '\ufffd') {
        throw ("UTF-8 replacement char U+FFFD detected in {0}; tag={1}" -f $Path, $Tag)
    }
}

function Get-TemplateBlock {
    param([string]$TemplatePath)

    $templateText = Get-Utf8Text -Path $TemplatePath
    Test-Utf8TextReplacementChar -Text $templateText -Path $TemplatePath -Tag 'RESET-START-FILE'

    $lines = @($templateText -split "`r?`n")
    if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -eq '') {
        if ($lines.Count -eq 1) {
            $lines = @()
        }
        else {
            $lines = @($lines[0..($lines.Count - 2)])
        }
    }

    $inFence = $false
    $block = New-Object 'System.Collections.Generic.List[string]'

    foreach ($line in $lines) {
        if ($line.Trim().StartsWith('```')) {
            if (-not $inFence) {
                $inFence = $true
                $block = New-Object 'System.Collections.Generic.List[string]'
                continue
            }

            $inFence = $false
            $candidate = @($block)
            $hasHeader = $candidate -contains 'AB_UNATTENDED_START_V1'
            $hasKeyValue = @($candidate | Where-Object { $_ -match '^[A-Z0-9_]+=.*$' }).Count -gt 10
            if ($hasHeader -and $hasKeyValue) {
                return $candidate
            }
            continue
        }

        if ($inFence) {
            [void]$block.Add([string]$line)
        }
    }

    throw "Unable to locate start-file template block in $TemplatePath"
}

function Convert-LinesToOrderedMap {
    param([string[]]$Lines)

    $orderedKeys = New-Object 'System.Collections.Generic.List[string]'
    $map = [ordered]@{}
    $keyLineMap = @{}
    $lineNo = 0

    foreach ($line in @($Lines)) {
        $lineNo++
        if ($line -match '^([A-Z0-9_]+)=(.*)$') {
            $key = $Matches[1]
            $value = $Matches[2]

            if ($map.Contains($key)) {
                $firstLine = [int]$keyLineMap[$key]
                throw ("Duplicate key '{0}' detected in template block at line {1} and line {2}." -f $key, $firstLine, $lineNo)
            }

            $keyLineMap[$key] = $lineNo
            [void]$orderedKeys.Add($key)
            $map[$key] = $value
        }
    }

    return [pscustomobject]@{
        OrderedKeys = @($orderedKeys)
        Map = $map
    }
}

function Get-StartFileState {
    param([string]$StartFilePath)

    $startText = Get-Utf8Text -Path $StartFilePath
    Test-Utf8TextReplacementChar -Text $startText -Path $StartFilePath -Tag 'RESET-START-FILE'

    $lines = @($startText -split "`r?`n")
    if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -eq '') {
        if ($lines.Count -eq 1) {
            $lines = @()
        }
        else {
            $lines = @($lines[0..($lines.Count - 2)])
        }
    }

    $lineIndex = @{}
    $orderedKeys = New-Object 'System.Collections.Generic.List[string]'
    $map = [ordered]@{}

    for ($index = 0; $index -lt $lines.Count; $index++) {
        $line = [string]$lines[$index]
        if ($line -match '^([A-Z0-9_]+)=(.*)$') {
            $key = $Matches[1]
            $value = $Matches[2]

            if ($lineIndex.ContainsKey($key)) {
                $firstLine = ([int]$lineIndex[$key]) + 1
                throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $StartFilePath, $firstLine, ($index + 1))
            }

            $lineIndex[$key] = $index
            [void]$orderedKeys.Add($key)
            $map[$key] = $value
        }
    }

    return [pscustomobject]@{
        Lines = $lines
        KeyLineIndex = $lineIndex
        OrderedKeys = @($orderedKeys)
        Map = $map
    }
}

function Get-ResetSelectorSet {
    param([string]$RawSelectors)

    return @(
        $RawSelectors -split ';' |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Resolve-StartFileMode {
    param(
        [System.Collections.IDictionary]$StartFileMap
    )

    if ($null -eq $StartFileMap -or -not $StartFileMap.Contains('AI_CHAT_POLICY_WORK_MODE')) {
        return 'event-only'
    }

    $mode = ([string]$StartFileMap['AI_CHAT_POLICY_WORK_MODE']).Trim().ToLowerInvariant()
    switch ($mode) {
        'normal' { return 'normal' }
        'anti-missent' { return 'anti-missent' }
        'anti_missent' { return 'anti-missent' }
        'low-disturb' { return 'low-disturb' }
        'low_disturb' { return 'low-disturb' }
        'event-only' { return 'event-only' }
        'event_only' { return 'event-only' }
        default { return 'event-only' }
    }
}

function Resolve-SelectorKeySet {
    param(
        [string[]]$Selectors,
        [string[]]$AvailableKeys
    )

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($selector in @($Selectors)) {
        if ([string]::IsNullOrWhiteSpace($selector)) {
            continue
        }

        if ($selector.EndsWith('*')) {
            $prefix = $selector.Substring(0, $selector.Length - 1)
            foreach ($key in @($AvailableKeys)) {
                if ($key.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    [void]$set.Add($key)
                }
            }
            continue
        }

        foreach ($key in @($AvailableKeys)) {
            if ($key.Equals($selector, [System.StringComparison]::OrdinalIgnoreCase)) {
                [void]$set.Add($key)
            }
        }
    }

    $expanded = New-Object 'System.Collections.Generic.List[string]'
    foreach ($key in @($AvailableKeys)) {
        if ($set.Contains($key)) {
            [void]$expanded.Add($key)
        }
    }

    return @($expanded)
}

function Get-ResetValue {
    param(
        [string]$Key,
        [AllowEmptyString()][string]$CurrentValue,
        [System.Collections.IDictionary]$TemplateMap,
        [bool]$UseTemplateBaseline = $false
    )

    switch -Regex ($Key) {
        '^PRECHECK_REQUIRED$' {
            if ($TemplateMap.Contains($Key)) {
                return [string]$TemplateMap[$Key]
            }
            return $CurrentValue
        }
        '^PRECHECK_OPERATOR$' { return $CurrentValue }
        '^PRECHECK_WORKSPACE_STATUS_DETAIL$' { return 'TO_BE_FILLED' }
        '^PRECHECK_(START_GATE|REMOTE_LOCK)$' { return 'NOT_RUN' }
        '^PRECHECK_(AT|START_BLOCKER|FAILURE_REASON|NOTES)$' { return '' }
        '^PRECHECK_' { return 'NOT_RUN' }
        '^NETWORK_PRECHECK_LAST_RESULT$' { return 'NOT_RUN' }
        '^NETWORK_PRECHECK_LAST_(AT|REASON)$' { return '' }
        '^(A_FINAL_STATUS|B_FINAL_STATUS|SESSION_FINAL_STATUS)$' { return 'NOT_RUN' }
        '^SESSION_CLOSED$' { return 'false' }
        '^SESSION_CLOSED_(AT|REASON)$' { return '' }
        '^A_SUCCESS_SNAPSHOT_' { return '' }
        '^(A_LAUNCH_PID|B_LAUNCH_PID|WATCH_(PARENT_PID|LAUNCH_PID|LAST_EXIT_PID))$' { return '0' }
        '^(SESSION_FINAL_NOTES|RESTART_EVIDENCE_NOTES|AI_SESSION_BLOCKING_WATCH_NOTES)$' { return '' }
    }

    if ($UseTemplateBaseline -and $TemplateMap.Contains($Key)) {
        $templateValue = [string]$TemplateMap[$Key]
        if (-not [string]::IsNullOrWhiteSpace($templateValue) -and $templateValue -notmatch '^<.*>$') {
            return $templateValue
        }
    }

    if ($Key -match '(_STATUS|_RESULT)$') {
        return 'NOT_RUN'
    }

    if ($Key -match '(_AT|_NOTES|_REASON|_BLOCKER|_SUMMARY|_STATE)$') {
        return ''
    }

    return $CurrentValue
}

$startFilePath = Resolve-RepoPath -Path $StartFile -MustExist $true
$templatePath = Resolve-RepoPath -Path $TemplateFile -MustExist $true

$defaultSelectorText = 'PRECHECK_*;NETWORK_PRECHECK_LAST_RESULT;NETWORK_PRECHECK_LAST_AT;NETWORK_PRECHECK_LAST_REASON;A_SUCCESS_SNAPSHOT_FINAL_STATUS;A_SUCCESS_SNAPSHOT_SUMMARY;A_SUCCESS_SNAPSHOT_SOURCE_STATE;A_FINAL_STATUS;B_FINAL_STATUS;SESSION_FINAL_STATUS;SESSION_CLOSED;SESSION_CLOSED_AT;SESSION_CLOSED_REASON;SESSION_FINAL_NOTES;AI_SESSION_BLOCKING_WATCH_NOTES;RESTART_EVIDENCE_NOTES;A_LAUNCH_PID;B_LAUNCH_PID;WATCH_LAUNCH_PID;WATCH_PARENT_PID;WATCH_LAST_START_AT;WATCH_LAST_EXIT_PID;WATCH_LAST_EXIT_AT;LOCAL_GUARD_WAIT_FOR_MANUAL_RESTART;LOCAL_GUARD_AUTO_RECOVER_B;LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED;LOCAL_GUARD_RESTART_REQUIRES_CONFIRM;LOCAL_GUARD_RESTART_APPROVED;LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS;AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE;LOCAL_GUARD_POLL_STATUS_REPORT_EVENTS;LOCAL_GUARD_POLL_DRAIN_SAFE_EVENTS;LOCAL_GUARD_POLL_BARRIER_EVENTS;LOCAL_GUARD_POLL_RESTART_SENSITIVE_EVENTS;LOCAL_GUARD_POLL_CONTRACT_GATE_EVENTS;LOCAL_GUARD_POLL_EVENT_POLICY_STRICT;LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_TICKET_CHAIN_CHECK;LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_MAIN_PROCESS_HEALTH_CHECK;LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MAIN_PROCESS_SELF_HEAL;LOCAL_GUARD_STATUS_ONLY_AUTOFLOW_EXEC_TOKEN;TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS;EXTERNAL_TRIGGER_EXECUTE;EXTERNAL_TRIGGER_COMMAND'

$startState = Get-StartFileState -StartFilePath $startFilePath

if ($UseTemplateBaseline.IsPresent) {
    $selectedMode = Resolve-StartFileMode -StartFileMap $startState.Map
    $createScriptPath = Join-Path $PSScriptRoot 'create_unattended_ab_start_file.ps1'
    if (-not (Test-Path -LiteralPath $createScriptPath)) {
        throw "Missing script: $createScriptPath"
    }

    Write-Output ("[RESET-START-FILE] start_file={0}" -f $startFilePath)
    Write-Output ("[RESET-START-FILE] template_file={0}" -f $templatePath)
    Write-Output '[RESET-START-FILE] mode=delegate-create'
    Write-Output ("[RESET-START-FILE] template_baseline_mode={0}" -f $UseTemplateBaseline.IsPresent)
    Write-Output ("[RESET-START-FILE] selected_mode={0}" -f $selectedMode)

    if ($DryRun.IsPresent) {
        Write-Output ("[RESET-START-FILE] dry_run=true delegate_command=powershell -NoProfile -ExecutionPolicy Bypass -File {0} -TemplateFile {1} -OutputFile {2} -Mode {3} -Force" -f $createScriptPath, $templatePath, $startFilePath, $selectedMode)
        Write-Output '[RESET-START-FILE] dry_run=true write_skipped=true'
        exit 0
    }

    & $createScriptPath -TemplateFile $templatePath -OutputFile $startFilePath -Mode $selectedMode -Force
    Write-Output '[RESET-START-FILE] dry_run=false delegate_applied=true'
    exit 0
}

$templateBlock = Get-TemplateBlock -TemplatePath $templatePath
$templateState = Convert-LinesToOrderedMap -Lines $templateBlock

$selectorText = ''
if (-not [string]::IsNullOrWhiteSpace($ResetFields)) {
    $selectorText = $ResetFields
}
elseif (-not $UseDefaultResetFieldList.IsPresent -and $startState.Map.Contains('RERUN_FROM_A_STARTFILE_RESET_FIELDS') -and -not [string]::IsNullOrWhiteSpace([string]$startState.Map.RERUN_FROM_A_STARTFILE_RESET_FIELDS)) {
    $selectorText = [string]$startState.Map.RERUN_FROM_A_STARTFILE_RESET_FIELDS
}
else {
        $selectorText = 'A_TASK_DEFINITION;B_TASK_DEFINITION;RUN_MODE;ENTRY_MODE;D1_PROGRESS_STALL_WINDOW_MINUTES;D1_PROGRESS_STALL_NO_NEW_ROUND_MINUTES;D1_PROGRESS_STALL_MAX_IDLE_MINUTES;D1_PROGRESS_REQUIRE_OUTPUT_PROGRESS;D1_PROGRESS_MIN_ROUND_DELTA;D1_PROGRESS_REQUIRE_STRICT_ASCENDING;D1_EXIT_STALL_SECONDS;D1_EXIT_GRACE_SECONDS;D1_EXIT_REQUIRE_ROUND_LOG_GROWTH;D1_EXIT_REQUIRE_ACTIVE_STAGE_MATCH;D1_EXIT_REQUIRE_FRESHNESS_WINDOW_SECONDS;D1_EXIT_HEARTBEAT_MAX_AGE_SECONDS;D1_EXIT_REQUIRE_LOG_LOCK_CONSISTENCY;D1_EXIT_LOCK_MISMATCH_FAILS;CHAT_DISPATCH_USE_FILE_POLLER;CHAT_DISPATCH_FILE_POLLER_SCRIPT;CHAT_DISPATCH_FILE_POLLER_POLL_MS;CHAT_DISPATCH_FILE_POLLER_STABLE_COUNT;CHAT_DISPATCH_FILE_POLLER_STABLE_DELAY_MS;CHAT_DISPATCH_FILE_POLLER_TIMEOUT_MS;CHAT_DISPATCH_FILE_POLLER_MIN_BYTES;CHAT_DISPATCH_FILE_POLLER_REQUIRE_NON_EMPTY;CHAT_DISPATCH_FILE_POLLER_REJECT_PATTERNS;CHAT_DISPATCH_FILE_POLLER_ENCODING;CHAT_DISPATCH_FILE_POLLER_MAX_WAIT_MS;CHAT_DISPATCH_FILE_POLLER_MAX_RETRIES;CHAT_DISPATCH_FILE_POLLER_RETRY_DELAY_MS;CHAT_DISPATCH_FILE_POLLER_REQUIRE_TRAILING_NEWLINE;CHAT_DISPATCH_FILE_POLLER_REQUIRE_BOM;CHAT_DISPATCH_FILE_POLLER_REQUIRE_UTF8;CHAT_DISPATCH_FILE_POLLER_FAIL_ON_TIMEOUT;CHAT_DISPATCH_FILE_POLLER_FAIL_ON_EMPTY;CHAT_DISPATCH_FILE_POLLER_FAIL_ON_REJECT;CHAT_DISPATCH_FILE_POLLER_FAIL_ON_ENCODING;CHAT_DISPATCH_FILE_POLLER_FAIL_ON_BOM;CHAT_DISPATCH_FILE_POLLER_FAIL_ON_TRAILING_NEWLINE;CHAT_DISPATCH_FILE_POLLER_REQUIRE_JSON_VALID;CHAT_DISPATCH_FILE_POLLER_REQUIRE_JSON_SCHEMA;CHAT_DISPATCH_FILE_POLLER_REQUIRE_JSON_KEYS;CHAT_DISPATCH_FILE_POLLER_JSON_REQUIRED_KEYS;CHAT_DISPATCH_FILE_POLLER_REQUIRE_JSON_NON_EMPTY_KEYS;CHAT_DISPATCH_FILE_POLLER_JSON_NON_EMPTY_KEYS;CHAT_DISPATCH_FILE_POLLER_REQUIRE_JSON_NO_EXTRA_KEYS;CHAT_DISPATCH_FILE_POLLER_JSON_ALLOWED_KEYS;CHAT_DISPATCH_FILE_POLLER_REQUIRE_JSON_KEY_TYPES;CHAT_DISPATCH_FILE_POLLER_JSON_KEY_TYPES;CHAT_DISPATCH_FILE_POLLER_REQUIRE_JSON_TIMESTAMP_KEYS;CHAT_DISPATCH_FILE_POLLER_JSON_TIMESTAMP_KEYS;CHAT_DISPATCH_FILE_POLLER_REQUIRE_JSON_TIMESTAMP_FRESHNESS_MS;CHAT_DISPATCH_FILE_POLLER_JSON_TIMESTAMP_FRESHNESS_MS;CHAT_DISPATCH_FILE_POLLER_REQUIRE_JSON_SEQ_MONOTONIC;CHAT_DISPATCH_FILE_POLLER_JSON_SEQ_KEY;CHAT_DISPATCH_FILE_POLLER_JSON_SEQ_START;CHAT_DISPATCH_FILE_POLLER_REQUIRE_JSON_SOURCE_MATCH;CHAT_DISPATCH_FILE_POLLER_JSON_SOURCE_KEY;CHAT_DISPATCH_FILE_POLLER_JSON_SOURCE_VALUE;CHAT_DISPATCH_USE_AHK;CHAT_DISPATCH_USE_PY_SENDER;CHAT_DISPATCH_USE_IPC;CHAT_DISPATCH_OPEN_EDITOR;CHAT_DISPATCH_USE_CLIPBOARD;CHAT_DISPATCH_AUTO_RECONNECT_RESEND;CHAT_DISPATCH_RECONNECT_DELAY_MS;CHAT_DISPATCH_RECONNECT_WINDOW_SEC;CHAT_DISPATCH_MAXIMIZE_WINDOW;CHAT_DISPATCH_AHK_EVENT_ALLOWLIST;CHAT_DISPATCH_HEARTBEAT_TIMEOUT_SEND_ENABLED;CHAT_DISPATCH_HEARTBEAT_TIMEOUT_REQUIRE_CODE_FOCUS;CHAT_DISPATCH_ACTIVE_WINDOW_ONLY;CHAT_DISPATCH_STATUS_REPORT_INTERACTIVE;CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE;CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST;CHAT_DISPATCH_CLEAR_INPUT_ON_FAILURE;CHAT_DISPATCH_ESC_PREFLIGHT;CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT_ENABLED;CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT;CHAT_DISPATCH_X_MODE;CHAT_DISPATCH_RIGHT_OFFSET_PX;CHAT_DISPATCH_BOTTOM_AVOID_PX;CHAT_DISPATCH_PRESEND_DELAY_MS;RERUN_FROM_A_ENABLED;RERUN_FROM_A_STARTFILE_RESET_FIELDS;LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS;AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START;AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE;LOCAL_GUARD_POLL_STATUS_REPORT_EVENTS;LOCAL_GUARD_POLL_DRAIN_SAFE_EVENTS;LOCAL_GUARD_POLL_BARRIER_EVENTS;LOCAL_GUARD_POLL_RESTART_SENSITIVE_EVENTS;LOCAL_GUARD_POLL_CONTRACT_GATE_EVENTS;LOCAL_GUARD_POLL_EVENT_POLICY_STRICT;LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_TICKET_CHAIN_CHECK;LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_MAIN_PROCESS_HEALTH_CHECK;LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MAIN_PROCESS_SELF_HEAL;LOCAL_GUARD_STATUS_ONLY_AUTOFLOW_EXEC_TOKEN;TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS;EXTERNAL_TRIGGER_EXECUTE;EXTERNAL_TRIGGER_COMMAND'
}

$selectors = Get-ResetSelectorSet -RawSelectors $selectorText
$alwaysSelectors = Get-ResetSelectorSet -RawSelectors $defaultSelectorText
$allSelectors = @($selectors + $alwaysSelectors)

$keysToReset = Resolve-SelectorKeySet -Selectors $allSelectors -AvailableKeys $startState.OrderedKeys
if ($keysToReset.Count -lt 1) {
    throw 'No fields matched reset selectors. Nothing to reset.'
}

$newLines = @($startState.Lines)
$changes = New-Object 'System.Collections.Generic.List[object]'
foreach ($key in @($keysToReset)) {
    $oldValue = if ($startState.Map.Contains($key)) { [string]$startState.Map[$key] } else { '' }
    $newValue = Get-ResetValue -Key $key -CurrentValue $oldValue -TemplateMap $templateState.Map -UseTemplateBaseline $UseTemplateBaseline.IsPresent

    if ($oldValue -ceq $newValue) {
        continue
    }

    if ($startState.KeyLineIndex.ContainsKey($key)) {
        $lineIndex = [int]$startState.KeyLineIndex[$key]
        $newLines[$lineIndex] = "$key=$newValue"
    }
    else {
        $newLines += "$key=$newValue"
    }

    [void]$changes.Add([pscustomobject]@{
        Key = $key
        OldValue = $oldValue
        NewValue = $newValue
    })
}

Write-Output ("[RESET-START-FILE] start_file={0}" -f $startFilePath)
Write-Output ("[RESET-START-FILE] template_file={0}" -f $templatePath)
Write-Output ("[RESET-START-FILE] selectors={0}" -f ($allSelectors -join ';'))
Write-Output ("[RESET-START-FILE] template_baseline_mode={0}" -f $UseTemplateBaseline.IsPresent)
Write-Output ("[RESET-START-FILE] matched_keys={0}" -f $keysToReset.Count)
Write-Output ("[RESET-START-FILE] changed_keys={0}" -f $changes.Count)

foreach ($change in $changes) {
    Write-Output ("[RESET-START-FILE] change key={0} old='{1}' new='{2}'" -f $change.Key, $change.OldValue, $change.NewValue)
}

if ($DryRun.IsPresent) {
    Write-Output '[RESET-START-FILE] dry_run=true write_skipped=true'
    exit 0
}

$outputText = ($newLines -join "`n") + "`n"
Test-Utf8TextReplacementChar -Text $outputText -Path $startFilePath -Tag 'RESET-START-FILE'
$mutex = New-Object System.Threading.Mutex($false, (Get-StartFileMutexName -StartFilePath $startFilePath))
$locked = $false
$tempPath = ''
try {
    try {
        $locked = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
    }
    catch [System.Threading.AbandonedMutexException] {
        $locked = $true
    }

    if (-not $locked) {
        throw "Failed to acquire start-file write lock within timeout: $startFilePath"
    }

    $tempPath = "$startFilePath.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    $utf8WithBom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($tempPath, $outputText, $utf8WithBom)
    Move-Item -LiteralPath $tempPath -Destination $startFilePath -Force
    $tempPath = ''
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }

    if ($locked) {
        try { $mutex.ReleaseMutex() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
    }
    $mutex.Dispose()
}
Write-Output '[RESET-START-FILE] dry_run=false write_applied=true'
