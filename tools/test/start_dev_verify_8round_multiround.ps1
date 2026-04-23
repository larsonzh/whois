param(
    [string]$GitBashPath = "C:\Program Files\Git\bin\bash.exe",
    [string]$Version = "3.2.12",
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$RemoteIp = "10.0.0.199",
    [string]$User = "larson",
    [string]$KeyPath = "/c/ssh/id_rsa",
    [string]$Queries = "8.8.8.8 1.1.1.1 10.0.0.8",
    [string]$VerifyRound3Queries = "64.6.64.6 103.53.144.0/22 2620:fe::fe",
    [string]$SyncDir = "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois",
    [string]$Smoke = "1",
    [string]$Golden = "1",
    [AllowEmptyString()][string]$SmokeArgs = "",
    [AllowEmptyString()][string]$CflagsExtra = "",
    [string]$OptProfile = "lto-auto",
    [string]$Step47ListFile = "testdata/step47_reserved_list_default.txt",
    [string]$PreclassThresholdFile = "testdata/preclass_p1_group_thresholds_default.txt",
    [ValidateRange(0, 2)][int]$NoDeltaRetryMax = 1,
    [ValidateRange(0, 2)][int]$D6RetryMax = 1,
    [ValidateRange(1, 8)][int]$StartRound = 1,
    [ValidateRange(1, 8)][int]$EndRound = 8,
    [switch]$ResetCodeStepState,
    [ValidateSet("restore-source", "state-only")][string]$CodeStepResetPolicy = "restore-source",
    [string]$AutopilotOutDirRoot = "d:\LZProjects\whois\out\artifacts\autopilot_dev_recheck_8round",
    [string]$SessionOutDirRoot = "d:\LZProjects\whois\out\artifacts\dev_verify_multiround",
    [string]$CodeStepScript = "tools\test\autopilot_code_step_rounds.ps1",
    [AllowEmptyString()][string]$TaskDefinitionFile = "testdata/autopilot_code_step_tasks_default.json",
    [ValidateSet("full", "d6-only")][string]$VerifyExecutionProfile = "d6-only",
    [ValidateSet("true", "false")][string]$QuietRemoteBuildLogs = "false",
    [ValidateSet("true", "false")][string]$QuietTerminalOutput = "true",
    [ValidateSet("off", "safe")][string]$TerminalWatchdogMode = "off",
    [ValidateRange(30, 900)][int]$TerminalWatchdogIntervalSec = 120,
    [ValidateRange(60, 7200)][int]$TerminalWatchdogMinAgeSec = 600,
    [ValidateRange(1, 4)][int]$DevVerifyStride = 1,
    [AllowNull()][object]$EnableGateOnlySourceDrivenSkip = $true,
    [AllowNull()][object]$EnableFastV2Skip = $true,
    [AllowNull()][object]$EnableGuardedFastMode = $true,
    [ValidateSet("0", "1")][string]$RbPreflight = "1",
    [ValidateSet("0", "1")][string]$RbPreclassTableGuard = "1",
    [ValidateSet("off", "warn", "enforce")][string]$TaskDesignQualityPolicy = "warn",
    [ValidateSet("off", "warn", "enforce")][string]$TaskStaticPrecheckPolicy = "enforce",
    [ValidateRange(0, 3)][int]$UnknownNoOpBudget = 1,
    [ValidateRange(1, 3)][int]$UnknownNoOpConsecutiveLimit = 2,
    [AllowNull()][object]$EnableRoundRuntimeGate = $true,
    [ValidateRange(2, 8)][int]$RoundRuntimeGateStartRound = 2,
    [ValidateRange(1, 3)][int]$RoundRuntimeGateMaxAttempts = 2,
    [ValidateRange(1, 30)][int]$RoundRuntimeGateRetryDelaySec = 2,
    [ValidateRange(0, 102400)][int]$RoundRuntimeGateMinFreeDiskMB = 256,
    [AllowNull()][object]$RoundRuntimeGateCheckRemoteLock = $true,
    [AllowNull()][object]$RoundRuntimeGateCheckNetwork = $true,
    [AllowNull()][object]$RoundRuntimeGateCheckProcessConflict = $true,
    [switch]$DisableUnknownNoOpBudgetGate,
    [switch]$DisableSourceDrivenSkip
)

$ErrorActionPreference = "Stop"
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

function Convert-ToStrictBool {
    param(
        [AllowNull()][object]$Value,
        [string]$ParameterName,
        [bool]$DefaultValue
    )

    if ($null -eq $Value) {
        return $DefaultValue
    }

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    if ($Value -is [int] -or $Value -is [long]) {
        if ([int64]$Value -eq 0) { return $false }
        if ([int64]$Value -eq 1) { return $true }
        throw "$ParameterName only accepts bool/0/1, actual numeric value=$Value"
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $DefaultValue
    }

    switch ($text.Trim().ToLowerInvariant()) {
        "true"  { return $true }
        "false" { return $false }
        "1"     { return $true }
        "0"     { return $false }
        default {
            throw "$ParameterName only accepts bool/0/1/true/false, actual value='$text'"
        }
    }
}

$EnableGateOnlySourceDrivenSkip = Convert-ToStrictBool -Value $EnableGateOnlySourceDrivenSkip -ParameterName "EnableGateOnlySourceDrivenSkip" -DefaultValue $true
$EnableFastV2Skip = Convert-ToStrictBool -Value $EnableFastV2Skip -ParameterName "EnableFastV2Skip" -DefaultValue $true
$EnableGuardedFastMode = Convert-ToStrictBool -Value $EnableGuardedFastMode -ParameterName "EnableGuardedFastMode" -DefaultValue $true
$EnableRoundRuntimeGate = Convert-ToStrictBool -Value $EnableRoundRuntimeGate -ParameterName "EnableRoundRuntimeGate" -DefaultValue $true
$RoundRuntimeGateCheckRemoteLock = Convert-ToStrictBool -Value $RoundRuntimeGateCheckRemoteLock -ParameterName "RoundRuntimeGateCheckRemoteLock" -DefaultValue $true
$RoundRuntimeGateCheckNetwork = Convert-ToStrictBool -Value $RoundRuntimeGateCheckNetwork -ParameterName "RoundRuntimeGateCheckNetwork" -DefaultValue $true
$RoundRuntimeGateCheckProcessConflict = Convert-ToStrictBool -Value $RoundRuntimeGateCheckProcessConflict -ParameterName "RoundRuntimeGateCheckProcessConflict" -DefaultValue $true

function Get-EnvRawValue {
    param([string]$Name)

    $item = Get-Item -Path ("Env:" + $Name) -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        return ""
    }

    return [string]$item.Value
}

function Resolve-BoolSettingFromEnv {
    param(
        [string]$EnvName,
        [bool]$Default
    )

    $raw = Get-EnvRawValue -Name $EnvName
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    return Convert-ToStrictBool -Value $raw -ParameterName $EnvName -DefaultValue $Default
}

function Resolve-IntSettingFromEnv {
    param(
        [string]$EnvName,
        [int]$Default,
        [int]$Min,
        [int]$Max
    )

    $raw = Get-EnvRawValue -Name $EnvName
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    $parsed = 0
    if (-not [int]::TryParse($raw.Trim(), [ref]$parsed)) {
        throw "$EnvName must be an integer, actual value='$raw'"
    }

    if ($parsed -lt $Min -or $parsed -gt $Max) {
        throw "$EnvName out of range [$Min,$Max], actual value=$parsed"
    }

    return $parsed
}

function Convert-MsysPathToWindowsPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ($Path -match '^/([a-zA-Z])/(.*)$') {
        $drive = $Matches[1].ToUpperInvariant()
        $rest = $Matches[2] -replace '/', '\\'
        return ("{0}:\\{1}" -f $drive, $rest)
    }

    return $Path
}

function Resolve-RemoteKeyPathForGate {
    param([string]$InputPath)

    if (-not [string]::IsNullOrWhiteSpace($InputPath) -and (Test-Path -LiteralPath $InputPath)) {
        return (Resolve-Path -LiteralPath $InputPath).Path
    }

    $converted = Convert-MsysPathToWindowsPath -Path $InputPath
    if (-not [string]::IsNullOrWhiteSpace($converted) -and (Test-Path -LiteralPath $converted)) {
        return (Resolve-Path -LiteralPath $converted).Path
    }

    $fallback = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_rsa'
    if (Test-Path -LiteralPath $fallback) {
        return (Resolve-Path -LiteralPath $fallback).Path
    }

    throw "Unable to resolve SSH private key for round gate. input=$InputPath"
}

function Get-RemoteLockField {
    param(
        [string[]]$Lines,
        [string]$Key
    )

    $escapedKey = [regex]::Escape($Key)
    foreach ($record in @($Lines)) {
        if ($null -eq $record) {
            continue
        }

        foreach ($rawLine in @(([string]$record) -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($rawLine)) {
                continue
            }

            $line = $rawLine.Trim().TrimStart([char]0xFEFF)
            if ($line -match ('^\[CHECK-REMOTE-LOCK\]\s+' + $escapedKey + '=(.*)$')) {
                return $Matches[1].Trim()
            }

            if ($line -match ('(?:^|\s)' + $escapedKey + '=(.*)$')) {
                return $Matches[1].Trim()
            }
        }
    }

    return ''
}

$EnableRoundRuntimeGate = Resolve-BoolSettingFromEnv -EnvName 'AUTO_ROUND_RUNTIME_GATE_ENABLED' -Default $EnableRoundRuntimeGate
$RoundRuntimeGateCheckRemoteLock = Resolve-BoolSettingFromEnv -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK' -Default $RoundRuntimeGateCheckRemoteLock
$RoundRuntimeGateCheckNetwork = Resolve-BoolSettingFromEnv -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_NETWORK' -Default $RoundRuntimeGateCheckNetwork
$RoundRuntimeGateCheckProcessConflict = Resolve-BoolSettingFromEnv -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT' -Default $RoundRuntimeGateCheckProcessConflict
$RoundRuntimeGateStartRound = Resolve-IntSettingFromEnv -EnvName 'AUTO_ROUND_RUNTIME_GATE_START_ROUND' -Default $RoundRuntimeGateStartRound -Min 2 -Max 8
$RoundRuntimeGateMaxAttempts = Resolve-IntSettingFromEnv -EnvName 'AUTO_ROUND_RUNTIME_GATE_MAX_ATTEMPTS' -Default $RoundRuntimeGateMaxAttempts -Min 1 -Max 3
$RoundRuntimeGateRetryDelaySec = Resolve-IntSettingFromEnv -EnvName 'AUTO_ROUND_RUNTIME_GATE_RETRY_DELAY_SEC' -Default $RoundRuntimeGateRetryDelaySec -Min 1 -Max 30
$RoundRuntimeGateMinFreeDiskMB = Resolve-IntSettingFromEnv -EnvName 'AUTO_ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB' -Default $RoundRuntimeGateMinFreeDiskMB -Min 0 -Max 102400

function Format-ElapsedString {
    param([TimeSpan]$Elapsed)

    $hours = [int][Math]::Floor($Elapsed.TotalHours)
    return ("{0:00}:{1:00}:{2:00}.{3:000}" -f $hours, $Elapsed.Minutes, $Elapsed.Seconds, $Elapsed.Milliseconds)
}

function Write-RunTimingSummary {
    param(
        [string]$Tag,
        [datetime]$StartTime
    )

    $endTime = Get-Date
    $elapsed = $endTime - $StartTime
    Write-Output ("[{0}] finished_at={1}" -f $Tag, $endTime.ToString("yyyy-MM-dd HH:mm:ss"))
    Write-Output ("[{0}] elapsed={1} total_seconds={2:N3}" -f $Tag, (Format-ElapsedString -Elapsed $elapsed), $elapsed.TotalSeconds)
}

$runStart = Get-Date
Write-Output ("[DEV-VERIFY-MULTI] started_at={0}" -f $runStart.ToString("yyyy-MM-dd HH:mm:ss"))
Write-Output ("[DEV-VERIFY-MULTI] self_pid={0}" -f $PID)

if ($StartRound -gt $EndRound) {
    throw "StartRound must be less than or equal to EndRound"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot

$autopilotScript = Join-Path $repoRoot "tools\test\autopilot_dev_recheck_8round.ps1"
$codeStepScriptPath = if ([System.IO.Path]::IsPathRooted($CodeStepScript)) { $CodeStepScript } else { Join-Path $repoRoot $CodeStepScript }
$terminalWatchdogScript = Join-Path $repoRoot "tools\test\unattended_terminal_watchdog.ps1"
$taskStaticCheckScript = Join-Path $repoRoot "tools\test\check_task_definition_static.ps1"
$resolvedTaskDefinitionFile = ""
if (-not [string]::IsNullOrWhiteSpace($TaskDefinitionFile)) {
    $resolvedTaskDefinitionFile = if ([System.IO.Path]::IsPathRooted($TaskDefinitionFile)) { $TaskDefinitionFile } else { Join-Path $repoRoot $TaskDefinitionFile }
}

if (-not (Test-Path -LiteralPath $GitBashPath)) {
    throw "Git Bash not found: $GitBashPath"
}
if (-not (Test-Path -LiteralPath $autopilotScript)) {
    throw "Autopilot script not found: $autopilotScript"
}
if (-not (Test-Path -LiteralPath $codeStepScriptPath)) {
    throw "Code-step script not found: $codeStepScriptPath"
}
if ($TerminalWatchdogMode -ne "off" -and -not (Test-Path -LiteralPath $terminalWatchdogScript)) {
    throw "Terminal watchdog script not found: $terminalWatchdogScript"
}
if (-not [string]::IsNullOrWhiteSpace($resolvedTaskDefinitionFile) -and -not (Test-Path -LiteralPath $resolvedTaskDefinitionFile)) {
    throw "Task definition file not found: $resolvedTaskDefinitionFile"
}
if ($TaskStaticPrecheckPolicy -ne "off" -and -not (Test-Path -LiteralPath $taskStaticCheckScript)) {
    throw "Task static check script not found: $taskStaticCheckScript"
}

if ($TaskStaticPrecheckPolicy -ne "off" -and -not [string]::IsNullOrWhiteSpace($resolvedTaskDefinitionFile)) {
    Write-Output "[DEV-VERIFY-MULTI] task_static_precheck_policy=$TaskStaticPrecheckPolicy task_definition=$resolvedTaskDefinitionFile"
    & $taskStaticCheckScript -TaskDefinitionFile $resolvedTaskDefinitionFile -RepoRoot $repoRoot -Policy $TaskStaticPrecheckPolicy
    $taskStaticCheckExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    if ($taskStaticCheckExitCode -ne 0) {
        throw "Task static precheck failed (exit=$taskStaticCheckExitCode): $resolvedTaskDefinitionFile"
    }
}

$resolvedAutopilotOutDirRoot = if ([System.IO.Path]::IsPathRooted($AutopilotOutDirRoot)) {
    $AutopilotOutDirRoot
}
else {
    Join-Path $repoRoot $AutopilotOutDirRoot
}

$codeStepStateDir = Join-Path $resolvedAutopilotOutDirRoot "_code_step_state"
$codeStepStateFile = Join-Path $codeStepStateDir "state.json"

function Get-CodeStepStateSnapshot {
    param([string]$StateFile)

    if (-not (Test-Path -LiteralPath $StateFile)) {
        return [pscustomobject]@{
            Exists = $false
            ParseOk = $true
            InvocationCount = 0
            ErrorMessage = ""
        }
    }

    try {
        $stateObject = (Get-Content -LiteralPath $StateFile -Raw) | ConvertFrom-Json
        $invocationCount = 0
        if ($stateObject -and ($stateObject.PSObject.Properties.Name -contains "invocationCount")) {
            $invocationRaw = [string]$stateObject.invocationCount
            if (-not [int]::TryParse($invocationRaw, [ref]$invocationCount)) {
                throw "invalid invocationCount='$invocationRaw'"
            }
        }

        return [pscustomobject]@{
            Exists = $true
            ParseOk = $true
            InvocationCount = $invocationCount
            ErrorMessage = ""
        }
    }
    catch {
        return [pscustomobject]@{
            Exists = $true
            ParseOk = $false
            InvocationCount = 0
            ErrorMessage = $_.Exception.Message
        }
    }
}

$runIncludesD1 = ($StartRound -le 1 -and $EndRound -ge 1)
if ($runIncludesD1 -and -not $ResetCodeStepState.IsPresent) {
    $stateSnapshot = Get-CodeStepStateSnapshot -StateFile $codeStepStateFile
    if (-not $stateSnapshot.ParseOk) {
        throw "[DEV-VERIFY-MULTI] unable to parse code-step state file for d1-reset guard: $codeStepStateFile; error=$($stateSnapshot.ErrorMessage); re-run with -ResetCodeStepState"
    }

    if ($stateSnapshot.Exists -and $stateSnapshot.InvocationCount -gt 0) {
        throw "[DEV-VERIFY-MULTI] missing required -ResetCodeStepState when CodeStepResetPolicy=$CodeStepResetPolicy and run includes D1; detected invocationCount=$($stateSnapshot.InvocationCount) in $codeStepStateFile"
    }
}

if ($ResetCodeStepState.IsPresent) {
    $resetParams = @{
        Reset = $true
    }
    if ($CodeStepResetPolicy -eq "state-only") {
        $resetParams["ResetStateOnly"] = $true
    }
    if (-not [string]::IsNullOrWhiteSpace($resolvedTaskDefinitionFile)) {
        $resetParams["TaskDefinitionFile"] = $resolvedTaskDefinitionFile
    }

    & $codeStepScriptPath @resetParams
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to reset code-step state"
    }
}

$AutopilotOutDirRoot = $resolvedAutopilotOutDirRoot

$sessionStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionOutDir = Join-Path $SessionOutDirRoot $sessionStamp
New-Item -ItemType Directory -Path $sessionOutDir -Force | Out-Null
$snapshotDir = Join-Path $sessionOutDir "snapshots"
New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null
$terminalWatchdogLog = Join-Path $sessionOutDir "terminal_watchdog.log"
$terminalWatchdogProcess = $null

function Start-TerminalWatchdogProcess {
    param(
        [string]$ScriptPath,
        [string]$Mode,
        [int]$IntervalSec,
        [int]$MinAgeSec,
        [string]$SessionDir,
        [string]$LogFilePath
    )

    if ($Mode -eq "off") {
        return $null
    }

    $powershellPath = Join-Path $PSHOME "powershell.exe"
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = "powershell.exe"
    }

    $argumentList = @(
        "-NoProfile"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        $ScriptPath
        "-ProtectedRootPid"
        ([string]$PID)
        "-SessionOutDir"
        $SessionDir
        "-Mode"
        $Mode
        "-IntervalSec"
        ([string]$IntervalSec)
        "-MinAgeSec"
        ([string]$MinAgeSec)
    )

    try {
        $processInfo = Start-Process -FilePath $powershellPath -ArgumentList $argumentList -WindowStyle Hidden -PassThru
        return $processInfo
    }
    catch {
        Write-Warning "[DEV-VERIFY-MULTI] terminal watchdog start failed: $($_.Exception.Message)"
        return $null
    }
}

function Stop-TerminalWatchdogProcess {
    param([AllowNull()][object]$Process)

    $resolvedProcess = $null
    if ($Process -is [System.Diagnostics.Process]) {
        $resolvedProcess = $Process
    }
    elseif ($Process -is [System.Array]) {
        $resolvedProcess = @($Process | Where-Object { $_ -is [System.Diagnostics.Process] } | Select-Object -Last 1)[0]
    }

    if ($null -eq $resolvedProcess) {
        return
    }

    try {
        if (-not $resolvedProcess.HasExited) {
            Stop-Process -Id $resolvedProcess.Id -Force -ErrorAction Stop
            Write-Output ("[DEV-VERIFY-MULTI] terminal_watchdog_stop pid={0}" -f $resolvedProcess.Id)
        }
    }
    catch {
        Write-Warning "[DEV-VERIFY-MULTI] terminal watchdog stop failed: $($_.Exception.Message)"
    }
}

function ConvertTo-NormalizedLine {
    param([object[]]$Raw)

    $lines = @()
    foreach ($item in $Raw) {
        if ($item -is [System.Management.Automation.ErrorRecord]) {
            $lines += $item.Exception.Message
        }
        else {
            $lines += [string]$item
        }
    }

    return $lines
}

function Invoke-StreamingCapture {
    param(
        [scriptblock]$Action,
        [bool]$EmitToConsole = $true
    )

    $captured = New-Object System.Collections.Generic.List[string]
    & $Action 2>&1 | ForEach-Object {
        $line = if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.Exception.Message
        }
        else {
            [string]$_
        }

        [void]$captured.Add($line)
        if ($EmitToConsole) {
            Write-Host $line
        }
    }

    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) {
        $exitCode = 0
    }

    return [pscustomobject]@{
        Raw = @($captured)
        ExitCode = $exitCode
    }
}

function Get-TextHash {
    param([string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hashBytes = $sha.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hashBytes)).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Invoke-CodeStepRound {
    param(
        [string]$RoundTag,
        [string]$ScriptPath,
        [string]$OutDir,
        [AllowEmptyString()][string]$TaskDefinitionFile = ""
    )

    if ([string]::IsNullOrWhiteSpace($TaskDefinitionFile)) {
        $invokeResult = Invoke-StreamingCapture -Action { & $ScriptPath }
    }
    else {
        $invokeResult = Invoke-StreamingCapture -Action { & $ScriptPath -TaskDefinitionFile $TaskDefinitionFile }
    }
    $exitCode = $invokeResult.ExitCode

    $lines = ConvertTo-NormalizedLine -Raw $invokeResult.Raw

    $logFile = Join-Path $OutDir ("{0}_code_step.log" -f $RoundTag)
    $lines | Out-File -FilePath $logFile -Encoding utf8

    $action = ""
    foreach ($line in $lines) {
        if ($line -match '^\[CODE-STEP\] round=[^ ]+ action=([a-zA-Z0-9-]+)\b') {
            $action = $Matches[1]
            break
        }
    }

    return [pscustomobject]@{
        Pass = ($exitCode -eq 0)
        ExitCode = $exitCode
        Action = $action
        LogFile = $logFile
        Lines = $lines
    }
}

function Get-GitSnapshot {
    param([string]$RepoPath)

    function Invoke-GitCapture {
        param([string[]]$GitArgs)

        $raw = & git -c core.safecrlf=false -c core.autocrlf=false -C $RepoPath @GitArgs 2>&1
        $rc = $LASTEXITCODE
        $lines = @()
        foreach ($item in $raw) {
            $line = if ($item -is [System.Management.Automation.ErrorRecord]) { $item.ToString() } else { [string]$item }
            if ($line -match '^warning: in the working copy of .+ CRLF will be replaced by LF') {
                continue
            }
            if ($line.Trim().Length -gt 0) {
                $lines += $line
            }
        }

        if ($rc -ne 0) {
            throw "git $($GitArgs -join ' ') failed: $($lines -join '; ')"
        }

        return $lines
    }

    $statusLines = @(Invoke-GitCapture -GitArgs @('status', '--short'))
    $headLines = @(Invoke-GitCapture -GitArgs @('rev-parse', 'HEAD'))
    $diffNames = @(Invoke-GitCapture -GitArgs @('diff', '--name-only'))
    $sourceDiffNames = @(Invoke-GitCapture -GitArgs @('diff', '--name-only', '--', 'src', 'include'))
    $sourcePatchLines = @(Invoke-GitCapture -GitArgs @('diff', '--', 'src', 'include'))
    $sourcePatchText = ($sourcePatchLines -join "`n")
    $sourcePatchHash = Get-TextHash -Text $sourcePatchText
    $headLine = if ($headLines.Count -gt 0) { $headLines[0] } else { "" }

    return [pscustomobject]@{
        StatusLines = $statusLines
        Head = [string]$headLine
        DiffNames = $diffNames
        SourceDiffNames = $sourceDiffNames
        SourcePatchHash = $sourcePatchHash
    }
}

function Join-OrNone {
    param([string[]]$Items)

    $normalized = @($Items | Where-Object { $_ -and $_.Trim().Length -gt 0 })
    if ($normalized.Count -eq 0) {
        return "(none)"
    }
    return ($normalized -join ";")
}

function Get-D1ToD3NoOpCount {
    param([hashtable]$Decisions)

    $count = 0
    foreach ($tag in @("D1", "D2", "D3")) {
        if ($Decisions.ContainsKey($tag) -and $Decisions[$tag] -eq "D-NOP") {
            $count++
        }
    }

    return $count
}

function Get-D1ToD3UnknownNoOpCount {
    param(
        [hashtable]$Decisions,
        [hashtable]$NoOpClasses
    )

    $count = 0
    foreach ($tag in @("D1", "D2", "D3")) {
        if ($Decisions.ContainsKey($tag) -and $Decisions[$tag] -eq "D-NOP") {
            $class = ""
            if ($NoOpClasses.ContainsKey($tag)) {
                $class = [string]$NoOpClasses[$tag]
            }
            if ($class -eq "unknown-unexplained") {
                $count++
            }
        }
    }

    return $count
}

function Get-D1ToD3SafeNoOpCount {
    param(
        [hashtable]$Decisions,
        [hashtable]$NoOpClasses
    )

    $count = 0
    foreach ($tag in @("D1", "D2", "D3")) {
        if ($Decisions.ContainsKey($tag) -and $Decisions[$tag] -eq "D-NOP") {
            $class = ""
            if ($NoOpClasses.ContainsKey($tag)) {
                $class = [string]$NoOpClasses[$tag]
            }
            if ($class -ne "unknown-unexplained") {
                $count++
            }
        }
    }

    return $count
}

function Normalize-RelativePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }
    return (($Path -replace '\\', '/') -replace '^\./', '').Trim()
}

function Test-PathListContains {
    param(
        [string[]]$Paths,
        [string]$TargetPath
    )

    $target = Normalize-RelativePath -Path $TargetPath
    if ([string]::IsNullOrWhiteSpace($target)) {
        return $false
    }

    foreach ($item in @($Paths)) {
        $normalized = Normalize-RelativePath -Path ([string]$item)
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }
        if ($normalized.Equals($target, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Get-TaskTypeText {
    param([object]$RoundTask)

    if (-not $RoundTask) {
        return ""
    }

    $typeText = "builtin"
    if ($RoundTask.PSObject.Properties.Name -contains "type") {
        $candidate = [string]$RoundTask.type
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $typeText = $candidate.Trim().ToLowerInvariant()
        }
    }

    return $typeText
}

function Convert-ToRoundTaskMap {
    param([object]$TaskDefinition)

    $map = @{}
    if (-not $TaskDefinition -or -not $TaskDefinition.rounds) {
        return $map
    }

    foreach ($prop in $TaskDefinition.rounds.PSObject.Properties) {
        $map[$prop.Name] = $prop.Value
    }

    return $map
}

function Resolve-TaskTargetRelativePath {
    param(
        [object]$TaskDefinition,
        [string]$RepoRoot
    )

    if (-not $TaskDefinition -or -not ($TaskDefinition.PSObject.Properties.Name -contains "targetFile")) {
        return ""
    }

    $rawTarget = [string]$TaskDefinition.targetFile
    if ([string]::IsNullOrWhiteSpace($rawTarget)) {
        return ""
    }

    if ([System.IO.Path]::IsPathRooted($rawTarget)) {
        $repoFull = [System.IO.Path]::GetFullPath($RepoRoot)
        $targetFull = [System.IO.Path]::GetFullPath($rawTarget)
        if (-not $targetFull.StartsWith($repoFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ""
        }
        $relative = $targetFull.Substring($repoFull.Length).TrimStart([char]'\\', [char]'/')
        return Normalize-RelativePath -Path $relative
    }

    return Normalize-RelativePath -Path $rawTarget
}

function Test-TaskDefinitionDesignQuality {
    param([hashtable]$RoundTaskMap)

    $warnings = @()
    $errors = @()
    $required = @("D1", "D2", "D3", "D4")

    foreach ($tag in $required) {
        if (-not $RoundTaskMap.ContainsKey($tag)) {
            $errors += "missing round definition: $tag"
        }
    }

    foreach ($tag in @("D1", "D2", "D3")) {
        if (-not $RoundTaskMap.ContainsKey($tag)) {
            continue
        }

        $task = $RoundTaskMap[$tag]
        $typeText = Get-TaskTypeText -RoundTask $task
        if ($typeText -eq "noop") {
            $errors += "$tag type=noop is not allowed for development rounds"
        }

        $description = ""
        if ($task.PSObject.Properties.Name -contains "description") {
            $description = [string]$task.description
        }
        if ([string]::IsNullOrWhiteSpace($description)) {
            $warnings += "$tag missing description"
        }

        if ($typeText -eq "regex-patch") {
            $operations = @()
            if ($task.PSObject.Properties.Name -contains "operations") {
                $operations = @($task.operations)
            }
            if ($operations.Count -eq 0) {
                $errors += "$tag regex-patch missing operations"
            }

            $markers = @()
            if ($task.PSObject.Properties.Name -contains "idempotentContains") {
                $rawMarkers = $task.idempotentContains
                if ($rawMarkers -is [string]) {
                    $markers = @($rawMarkers)
                }
                else {
                    $markers = @($rawMarkers)
                }
            }
            if ($markers.Count -eq 0) {
                $warnings += "$tag regex-patch missing idempotentContains"
            }
        }
    }

    if ($RoundTaskMap.ContainsKey("D4")) {
        $d4Type = Get-TaskTypeText -RoundTask $RoundTaskMap["D4"]
        if ($d4Type -ne "noop") {
            $warnings += "D4 type is '$d4Type' (recommended noop for freeze round)"
        }
    }

    return [pscustomobject]@{
        Warnings = $warnings
        Errors = $errors
    }
}

function Get-RoundNoOpClassification {
    param(
        [string]$RoundTag,
        [string]$CodeStepAction,
        [string[]]$BeforeSourceDiffNames,
        [string[]]$AfterCodeStepSourceDiffNames,
        [string]$TargetSourceRelativePath,
        [object]$RoundTask
    )

    $class = "unknown-unexplained"
    $targetInBefore = Test-PathListContains -Paths $BeforeSourceDiffNames -TargetPath $TargetSourceRelativePath
    $targetInAfterCodeStep = Test-PathListContains -Paths $AfterCodeStepSourceDiffNames -TargetPath $TargetSourceRelativePath
    $targetSeen = ($targetInBefore -or $targetInAfterCodeStep)

    if (($CodeStepAction -eq "already-applied" -or $CodeStepAction -eq "applied") -and $targetSeen) {
        $class = "absorbed-by-prior-round"
    }
    elseif ($CodeStepAction -eq "already-applied") {
        $class = "idempotent-replay"
    }

    $allowedClasses = @()
    if ($RoundTask -and ($RoundTask.PSObject.Properties.Name -contains "noOpPolicy")) {
        $policy = $RoundTask.noOpPolicy
        if ($policy -and ($policy.PSObject.Properties.Name -contains "allowedClasses")) {
            $rawAllowed = $policy.allowedClasses
            if ($rawAllowed -is [string]) {
                $allowedClasses = @([string]$rawAllowed)
            }
            else {
                $allowedClasses = @($rawAllowed | ForEach-Object { [string]$_ })
            }
            $allowedClasses = @($allowedClasses | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
        }
    }

    $policyMismatch = $false
    if ($allowedClasses.Count -gt 0 -and ($allowedClasses -notcontains $class)) {
        $policyMismatch = $true
        $class = "unknown-unexplained"
    }

    $evidence = "action=$CodeStepAction; target_seen=$targetSeen; target_in_before=$targetInBefore; target_in_after_code_step=$targetInAfterCodeStep"
    if ($policyMismatch) {
        $evidence = "$evidence; policy_mismatch=true"
    }

    return [pscustomobject]@{
        Class = $class
        Evidence = $evidence
        PolicyMismatch = $policyMismatch
    }
}

function Write-GitSnapshot {
    param(
        [pscustomobject]$Snapshot,
        [string]$Tag
    )

    $statusPath = Join-Path $snapshotDir ("{0}_git_status_short.txt" -f $Tag)
    $headPath = Join-Path $snapshotDir ("{0}_git_head.txt" -f $Tag)
    $diffPath = Join-Path $snapshotDir ("{0}_git_diff_name_only.txt" -f $Tag)
    $sourceDiffPath = Join-Path $snapshotDir ("{0}_git_diff_source_name_only.txt" -f $Tag)
    $sourceHashPath = Join-Path $snapshotDir ("{0}_git_diff_source_hash.txt" -f $Tag)

    @($Snapshot.StatusLines) | Out-File -FilePath $statusPath -Encoding utf8
    @($Snapshot.Head) | Out-File -FilePath $headPath -Encoding utf8
    @($Snapshot.DiffNames) | Out-File -FilePath $diffPath -Encoding utf8
    @($Snapshot.SourceDiffNames) | Out-File -FilePath $sourceDiffPath -Encoding utf8
    @($Snapshot.SourcePatchHash) | Out-File -FilePath $sourceHashPath -Encoding utf8
}

function Invoke-RoundRuntimeGate {
    param(
        [string]$RoundTag,
        [string]$Phase,
        [int]$PhaseRound,
        [string]$RepoRoot,
        [string]$SessionOutDir,
        [string]$AutopilotOutDirRoot,
        [string]$RemoteIp,
        [string]$RemoteUser,
        [string]$KeyPath,
        [bool]$Enabled,
        [int]$StartRound,
        [int]$MaxAttempts,
        [int]$RetryDelaySec,
        [int]$MinFreeDiskMB,
        [bool]$CheckRemoteLock,
        [bool]$CheckNetwork,
        [bool]$CheckProcessConflict,
        [hashtable]$NetworkSettings
    )

    $result = [ordered]@{
        Applied = $false
        Pass = $true
        Attempts = 0
        RequiredFailures = 0
        OptionalFailures = 0
        Reason = ''
        Lines = @()
    }

    if (-not $Enabled -or $Phase -ne 'DEV' -or $PhaseRound -lt $StartRound) {
        return [pscustomobject]$result
    }

    $result.Applied = $true
    $allLines = New-Object 'System.Collections.Generic.List[string]'
    $resolvedKeyPath = ''

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $requiredFailures = New-Object 'System.Collections.Generic.List[string]'
        $optionalFailures = New-Object 'System.Collections.Generic.List[string]'

        [void]$allLines.Add(("[DEV-VERIFY-MULTI] round_gate_attempt={0} attempt={1}/{2}" -f $RoundTag, $attempt, $MaxAttempts))

        foreach ($dirPath in @($SessionOutDir, $AutopilotOutDirRoot)) {
            try {
                if (-not (Test-Path -LiteralPath $dirPath)) {
                    New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
                }

                $resolvedDir = (Resolve-Path -LiteralPath $dirPath).Path
                $probePath = Join-Path $resolvedDir (".round_gate_probe_{0}_{1}.tmp" -f $PID, $attempt)
                Set-Content -LiteralPath $probePath -Value $RoundTag -Encoding ascii
                Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue

                $item = Get-Item -LiteralPath $resolvedDir
                if ($null -ne $item.PSDrive) {
                    $freeMb = [int][Math]::Floor($item.PSDrive.Free / 1MB)
                    if ($freeMb -lt $MinFreeDiskMB) {
                        [void]$requiredFailures.Add(("disk_free_low path={0} free_mb={1} min_mb={2}" -f $resolvedDir, $freeMb, $MinFreeDiskMB))
                    }
                }
            }
            catch {
                [void]$requiredFailures.Add(("path_unhealthy path={0} detail={1}" -f $dirPath, $_.Exception.Message.Replace(' ', '_')))
            }
        }

        if ($CheckProcessConflict) {
            try {
                $conflicts = @(
                    Get-CimInstance Win32_Process -Filter "Name LIKE '%powershell.exe%' OR Name LIKE '%pwsh.exe%'" |
                        Where-Object {
                            if ([int]$_.ProcessId -eq $PID) {
                                return $false
                            }

                            $line = [string]$_.CommandLine
                            if ([string]::IsNullOrWhiteSpace($line)) {
                                return $false
                            }

                            $line = $line.ToLowerInvariant()
                            return $line.Contains('start_dev_verify_8round_multiround.ps1')
                        } |
                        Select-Object -ExpandProperty ProcessId -Unique
                )

                if ($conflicts.Count -gt 0) {
                    [void]$optionalFailures.Add(("process_conflict_detected pids={0}" -f ($conflicts -join ',')))
                }
            }
            catch {
                [void]$optionalFailures.Add(("process_conflict_check_error detail={0}" -f $_.Exception.Message.Replace(' ', '_')))
            }
        }

        $needsRemoteKey = ($CheckRemoteLock -or ($CheckNetwork -and [bool]$NetworkSettings.CheckRemote))
        if ($needsRemoteKey) {
            try {
                $resolvedKeyPath = Resolve-RemoteKeyPathForGate -InputPath $KeyPath
            }
            catch {
                [void]$requiredFailures.Add(("ssh_key_unavailable detail={0}" -f $_.Exception.Message.Replace(' ', '_')))
            }
        }

        if ($CheckRemoteLock -and $requiredFailures.Count -eq 0) {
            $checkRemoteLockScript = Join-Path $RepoRoot 'tools\dev\check_remote_lock.ps1'
            if (-not (Test-Path -LiteralPath $checkRemoteLockScript)) {
                [void]$requiredFailures.Add(("remote_lock_script_missing path={0}" -f $checkRemoteLockScript))
            }
            else {
                try {
                    $lockResult = Invoke-StreamingCapture -Action {
                        & $checkRemoteLockScript -RemoteIp $RemoteIp -RemoteUser $RemoteUser -KeyPath $resolvedKeyPath -TimeoutSec 20
                    } -EmitToConsole:$false
                    $lockLines = ConvertTo-NormalizedLine -Raw $lockResult.Raw
                    foreach ($line in @($lockLines)) {
                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            [void]$allLines.Add($line)
                        }
                    }

                    $lockExitCode = if ($null -eq $lockResult.ExitCode) { 0 } else { [int]$lockResult.ExitCode }
                    if ($lockExitCode -ne 0) {
                        [void]$requiredFailures.Add(("remote_lock_check_exit={0}" -f $lockExitCode))
                    }
                    else {
                        $state = (Get-RemoteLockField -Lines $lockLines -Key 'state').ToLowerInvariant()
                        if ($state -ne 'absent') {
                            [void]$requiredFailures.Add(("remote_lock_state={0}" -f $state))
                        }
                    }
                }
                catch {
                    [void]$requiredFailures.Add(("remote_lock_check_error detail={0}" -f $_.Exception.Message.Replace(' ', '_')))
                }
            }
        }

        if ($CheckNetwork -and $requiredFailures.Count -eq 0) {
            $networkScript = Join-Path $RepoRoot 'tools\dev\check_dualstack_whois_connectivity.ps1'
            if (-not (Test-Path -LiteralPath $networkScript)) {
                [void]$requiredFailures.Add(("network_precheck_script_missing path={0}" -f $networkScript))
            }
            else {
                try {
                    $networkKeyPath = if ([bool]$NetworkSettings.CheckRemote) { $resolvedKeyPath } else { $KeyPath }
                    $networkResult = Invoke-StreamingCapture -Action {
                        & $networkScript `
                            -Targets ([string]$NetworkSettings.Targets) `
                            -TimeoutSec ([int]$NetworkSettings.TimeoutSec) `
                            -CheckLocal:([bool]$NetworkSettings.CheckLocal) `
                            -CheckRemote:([bool]$NetworkSettings.CheckRemote) `
                            -CheckIPv4:([bool]$NetworkSettings.CheckIPv4) `
                            -CheckIPv6:([bool]$NetworkSettings.CheckIPv6) `
                            -RequireIPv4:([bool]$NetworkSettings.RequireIPv4) `
                            -RequireIPv6:([bool]$NetworkSettings.RequireIPv6) `
                            -RemoteIp $RemoteIp `
                            -RemoteUser $RemoteUser `
                            -KeyPath $networkKeyPath
                    } -EmitToConsole:$false

                    $networkLines = ConvertTo-NormalizedLine -Raw $networkResult.Raw
                    foreach ($line in @($networkLines)) {
                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            [void]$allLines.Add($line)
                        }
                    }

                    $networkExitCode = if ($null -eq $networkResult.ExitCode) { 0 } else { [int]$networkResult.ExitCode }
                    if ($networkExitCode -ne 0) {
                        [void]$requiredFailures.Add(("network_required_check_failed exit={0}" -f $networkExitCode))
                    }

                    $optionalFailCount = 0
                    foreach ($line in @($networkLines)) {
                        if ($line -match '^\[CHECK-NET-PREFLIGHT\]\s+summary\s+overall=\w+\s+checks=\d+\s+required_fails=(\d+)\s+optional_fails=(\d+)$') {
                            $optionalFailCount = [int]$Matches[2]
                        }
                    }
                    if ($optionalFailCount -gt 0) {
                        [void]$optionalFailures.Add(("network_optional_failures={0}" -f $optionalFailCount))
                    }
                }
                catch {
                    [void]$requiredFailures.Add(("network_precheck_error detail={0}" -f $_.Exception.Message.Replace(' ', '_')))
                }
            }
        }

        $requiredText = if ($requiredFailures.Count -gt 0) { $requiredFailures -join '; ' } else { '(none)' }
        $optionalText = if ($optionalFailures.Count -gt 0) { $optionalFailures -join '; ' } else { '(none)' }
        $attemptStatus = if ($requiredFailures.Count -eq 0) { 'PASS' } else { 'FAIL' }
        [void]$allLines.Add(("[DEV-VERIFY-MULTI] round_gate_attempt_end={0} attempt={1}/{2} status={3} required={4} optional={5}" -f $RoundTag, $attempt, $MaxAttempts, $attemptStatus, $requiredText, $optionalText))

        $result.Attempts = $attempt
        $result.RequiredFailures = $requiredFailures.Count
        $result.OptionalFailures = $optionalFailures.Count
        if ($requiredFailures.Count -eq 0) {
            $result.Pass = $true
            $result.Reason = ''
            break
        }

        $result.Pass = $false
        $result.Reason = $requiredText
        if ($attempt -lt $MaxAttempts) {
            [void]$allLines.Add(("[DEV-VERIFY-MULTI] round_gate_retry={0} wait_sec={1}" -f $RoundTag, $RetryDelaySec))
            Start-Sleep -Seconds $RetryDelaySec
        }
    }

    $result.Lines = @($allLines)
    return [pscustomobject]$result
}

$taskDefinitionObject = $null
$roundTaskMap = @{}
$taskTargetRelativePath = ""

if (-not [string]::IsNullOrWhiteSpace($resolvedTaskDefinitionFile)) {
    try {
        $taskDefinitionObject = (Get-Content -LiteralPath $resolvedTaskDefinitionFile -Raw) | ConvertFrom-Json
        $roundTaskMap = Convert-ToRoundTaskMap -TaskDefinition $taskDefinitionObject
        $taskTargetRelativePath = Resolve-TaskTargetRelativePath -TaskDefinition $taskDefinitionObject -RepoRoot $repoRoot
    }
    catch {
        Write-Warning "[TASK-DESIGN] unable to parse task definition for quality checks: $resolvedTaskDefinitionFile"
        $taskDefinitionObject = $null
        $roundTaskMap = @{}
        $taskTargetRelativePath = ""
    }
}

if ($TaskDesignQualityPolicy -ne "off" -and $roundTaskMap.Count -gt 0) {
    $quality = Test-TaskDefinitionDesignQuality -RoundTaskMap $roundTaskMap
    foreach ($warn in @($quality.Warnings)) {
        Write-Output "[TASK-DESIGN] policy=$TaskDesignQualityPolicy severity=warn detail=$warn"
    }
    foreach ($err in @($quality.Errors)) {
        if ($TaskDesignQualityPolicy -eq "enforce") {
            throw "[TASK-DESIGN] policy=enforce severity=error detail=$err"
        }
        Write-Output "[TASK-DESIGN] policy=$TaskDesignQualityPolicy severity=error detail=$err"
    }
}

Write-Output "[DEV-VERIFY-MULTI] task_design_policy=$TaskDesignQualityPolicy unknown_noop_budget=$UnknownNoOpBudget unknown_noop_consecutive_limit=$UnknownNoOpConsecutiveLimit unknown_noop_budget_gate=$([string](-not $DisableUnknownNoOpBudgetGate))"
Write-Output "[DEV-VERIFY-MULTI] task_static_precheck_policy=$TaskStaticPrecheckPolicy"
Write-Output "[DEV-VERIFY-MULTI] quiet_remote_build_logs=$QuietRemoteBuildLogs quiet_terminal_output=$QuietTerminalOutput dev_verify_stride=$DevVerifyStride"
Write-Output "[DEV-VERIFY-MULTI] code_step_reset_policy=$CodeStepResetPolicy"
Write-Output "[DEV-VERIFY-MULTI] gate_only_source_driven_skip=$EnableGateOnlySourceDrivenSkip fast_v2_skip=$EnableFastV2Skip rb_preflight=$RbPreflight rb_table_guard=$RbPreclassTableGuard"

$networkPrecheckRequiredForRoundGate = Get-EnvBoolOrDefault -Name 'AUTO_NETWORK_PRECHECK_REQUIRED' -DefaultValue $true
if (-not $networkPrecheckRequiredForRoundGate) {
    $RoundRuntimeGateCheckNetwork = $false
}

$roundGateNetworkSettings = @{
    CheckLocal = Get-EnvBoolOrDefault -Name 'AUTO_NETWORK_PRECHECK_LOCAL_REQUIRED' -DefaultValue $true
    CheckRemote = Get-EnvBoolOrDefault -Name 'AUTO_NETWORK_PRECHECK_REMOTE_REQUIRED' -DefaultValue $true
    CheckIPv4 = Get-EnvBoolOrDefault -Name 'AUTO_NETWORK_PRECHECK_CHECK_IPV4' -DefaultValue $true
    CheckIPv6 = Get-EnvBoolOrDefault -Name 'AUTO_NETWORK_PRECHECK_CHECK_IPV6' -DefaultValue $true
    RequireIPv4 = Get-EnvBoolOrDefault -Name 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV4' -DefaultValue $false
    RequireIPv6 = Get-EnvBoolOrDefault -Name 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV6' -DefaultValue $true
    Targets = Get-EnvValueOrDefault -Name 'AUTO_NETWORK_PRECHECK_TARGETS' -DefaultValue 'whois.iana.org;whois.arin.net'
    TimeoutSec = Get-EnvIntOrDefault -Name 'AUTO_NETWORK_PRECHECK_TIMEOUT_SEC' -DefaultValue 8 -MinValue 1 -MaxValue 30
}

if ($roundGateNetworkSettings.RequireIPv4 -and -not $roundGateNetworkSettings.CheckIPv4) {
    $roundGateNetworkSettings.CheckIPv4 = $true
}
if ($roundGateNetworkSettings.RequireIPv6 -and -not $roundGateNetworkSettings.CheckIPv6) {
    $roundGateNetworkSettings.CheckIPv6 = $true
}
if (-not $roundGateNetworkSettings.CheckLocal -and -not $roundGateNetworkSettings.CheckRemote) {
    $RoundRuntimeGateCheckNetwork = $false
}
if (-not $roundGateNetworkSettings.CheckIPv4 -and -not $roundGateNetworkSettings.CheckIPv6) {
    $RoundRuntimeGateCheckNetwork = $false
}

Write-Output "[DEV-VERIFY-MULTI] round_runtime_gate enabled=$EnableRoundRuntimeGate start_round=$RoundRuntimeGateStartRound max_attempts=$RoundRuntimeGateMaxAttempts retry_delay_sec=$RoundRuntimeGateRetryDelaySec min_free_disk_mb=$RoundRuntimeGateMinFreeDiskMB check_remote_lock=$RoundRuntimeGateCheckRemoteLock check_network=$RoundRuntimeGateCheckNetwork check_process_conflict=$RoundRuntimeGateCheckProcessConflict"
if ($RoundRuntimeGateCheckNetwork) {
    Write-Output "[DEV-VERIFY-MULTI] round_runtime_gate_network targets=$($roundGateNetworkSettings.Targets) timeout_sec=$($roundGateNetworkSettings.TimeoutSec) check_local=$($roundGateNetworkSettings.CheckLocal) check_remote=$($roundGateNetworkSettings.CheckRemote) check_ipv4=$($roundGateNetworkSettings.CheckIPv4) check_ipv6=$($roundGateNetworkSettings.CheckIPv6) require_ipv4=$($roundGateNetworkSettings.RequireIPv4) require_ipv6=$($roundGateNetworkSettings.RequireIPv6)"
}

$guardedFastModeActive = ($EnableGuardedFastMode -and $VerifyExecutionProfile -eq "d6-only")
Write-Output "[DEV-VERIFY-MULTI] guarded_fast_mode=$guardedFastModeActive"
$terminalWatchdogProcess = Start-TerminalWatchdogProcess -ScriptPath $terminalWatchdogScript -Mode $TerminalWatchdogMode -IntervalSec $TerminalWatchdogIntervalSec -MinAgeSec $TerminalWatchdogMinAgeSec -SessionDir $sessionOutDir -LogFilePath $terminalWatchdogLog
if ($TerminalWatchdogMode -eq "off") {
    Write-Output "[DEV-VERIFY-MULTI] terminal_watchdog=off"
}
elseif ($null -ne $terminalWatchdogProcess) {
    Write-Output "[DEV-VERIFY-MULTI] terminal_watchdog_mode=$TerminalWatchdogMode interval_sec=$TerminalWatchdogIntervalSec min_age_sec=$TerminalWatchdogMinAgeSec"
    Write-Output ("[DEV-VERIFY-MULTI] terminal_watchdog_start pid={0} log={1}" -f $terminalWatchdogProcess.Id, $terminalWatchdogLog)
}
else {
    Write-Output "[DEV-VERIFY-MULTI] terminal_watchdog=failed"
}

$rows = @()
$devRoundDecisions = @{}
$devRoundNoOpClasses = @{}
$globalNoSourceChange = $false
$unknownNoOpCount = 0
$unknownNoOpConsecutive = 0
$unknownNoOpBudgetExceeded = $false

for ($round = $StartRound; $round -le $EndRound; $round++) {
    $phase = if ($round -le 4) { "DEV" } else { "VERIFY" }
    $phaseRound = if ($phase -eq "DEV") { $round } else { $round - 4 }
    $roundTag = if ($phase -eq "DEV") { "D$phaseRound" } else { "V$phaseRound" }
    $roundStartTime = Get-Date

    $forceDevLightRound = ($guardedFastModeActive -and $phase -eq "DEV" -and ($phaseRound -eq 2 -or $phaseRound -eq 3))
    $forceDevFullRound = ($guardedFastModeActive -and $phase -eq "DEV" -and $phaseRound -eq 4)
    $forceVerifyFullRound = ($guardedFastModeActive -and $phase -eq "VERIFY" -and $phaseRound -eq 1)

    $roundDevExecutionProfile = if ($forceDevLightRound) { "strict-only" } else { "full" }
    $roundVerifyExecutionProfile = if ($phase -eq "VERIFY") {
        if ($forceVerifyFullRound) { "full" } else { $VerifyExecutionProfile }
    }
    else {
        "full"
    }

    $mode = if ($phase -eq "DEV") { "code-change" } else { "gate-only" }
    $effectiveMode = "gate-only"
    $roundDecision = "EXECUTE"
    $skipReason = ""
    $skipRound = $false
    $autopilotExecuted = $false
    $dNoOpCountBeforeRound = Get-D1ToD3NoOpCount -Decisions $devRoundDecisions
    $dSafeNoOpCountBeforeRound = Get-D1ToD3SafeNoOpCount -Decisions $devRoundDecisions -NoOpClasses $devRoundNoOpClasses
    $dUnknownNoOpCountBeforeRound = Get-D1ToD3UnknownNoOpCount -Decisions $devRoundDecisions -NoOpClasses $devRoundNoOpClasses
    $hasD1ToD3Decisions = (
        $devRoundDecisions.ContainsKey("D1") -and
        $devRoundDecisions.ContainsKey("D2") -and
        $devRoundDecisions.ContainsKey("D3")
    )
    $devStrideSkipsAutopilot = ($phase -eq "DEV" -and $DevVerifyStride -gt 1 -and ((($phaseRound - 1) % $DevVerifyStride) -ne 0))

    $codeStepExit = 0
    $codeStepAction = ""
    $codeStepLog = ""
    $sourceDeltaAfterCodeStep = "not-applicable"
    $noOpClass = "none"
    $noOpEvidence = ""
    $roundGateApplied = $false
    $roundGatePass = $true
    $roundGateAttempts = 0
    $roundGateRequiredFailures = 0
    $roundGateOptionalFailures = 0
    $roundGateReason = ''
    $lines = @()

    $roundGate = Invoke-RoundRuntimeGate `
        -RoundTag $roundTag `
        -Phase $phase `
        -PhaseRound $phaseRound `
        -RepoRoot $repoRoot `
        -SessionOutDir $sessionOutDir `
        -AutopilotOutDirRoot $AutopilotOutDirRoot `
        -RemoteIp $RemoteIp `
        -RemoteUser $User `
        -KeyPath $KeyPath `
        -Enabled $EnableRoundRuntimeGate `
        -StartRound $RoundRuntimeGateStartRound `
        -MaxAttempts $RoundRuntimeGateMaxAttempts `
        -RetryDelaySec $RoundRuntimeGateRetryDelaySec `
        -MinFreeDiskMB $RoundRuntimeGateMinFreeDiskMB `
        -CheckRemoteLock $RoundRuntimeGateCheckRemoteLock `
        -CheckNetwork $RoundRuntimeGateCheckNetwork `
        -CheckProcessConflict $RoundRuntimeGateCheckProcessConflict `
        -NetworkSettings $roundGateNetworkSettings

    $roundGateApplied = [bool]$roundGate.Applied
    $roundGatePass = [bool]$roundGate.Pass
    $roundGateAttempts = [int]$roundGate.Attempts
    $roundGateRequiredFailures = [int]$roundGate.RequiredFailures
    $roundGateOptionalFailures = [int]$roundGate.OptionalFailures
    $roundGateReason = [string]$roundGate.Reason

    foreach ($gateLine in @($roundGate.Lines)) {
        if ([string]::IsNullOrWhiteSpace($gateLine)) {
            continue
        }

        Write-Output $gateLine
        $lines += $gateLine
    }

    if ($roundGateApplied -and -not $roundGatePass) {
        $skipRound = $true
        $roundDecision = 'ROUND-GATE-FAIL'
        $skipReason = if ([string]::IsNullOrWhiteSpace($roundGateReason)) { 'round-runtime-gate-failed' } else { $roundGateReason }
        $gateFailLine = "[DEV-VERIFY-MULTI] round_gate_fail=$roundTag reason=$skipReason"
        Write-Output $gateFailLine
        $lines += $gateFailLine
    }
    elseif ($roundGateApplied -and $roundGateOptionalFailures -gt 0) {
        $gateWarnLine = "[DEV-VERIFY-MULTI] round_gate_optional=$roundTag optional_failures=$roundGateOptionalFailures"
        Write-Output $gateWarnLine
        $lines += $gateWarnLine
    }

    $beforeSnapshot = Get-GitSnapshot -RepoPath $repoRoot
    Write-GitSnapshot -Snapshot $beforeSnapshot -Tag ("{0}_before" -f $roundTag)

    $afterCodeStepSnapshot = $beforeSnapshot

    if (-not $skipRound -and -not $DisableSourceDrivenSkip) {
        if ($phase -eq "VERIFY") {
            if ($forceVerifyFullRound) {
                Write-Output "[DEV-VERIFY-MULTI] round_forced_full=$roundTag reason=guarded-fast-mode-v1"
            }
            else {
                if ($globalNoSourceChange) {
                    $skipRound = $true
                    $roundDecision = "V-SKIP"
                    $skipReason = "global-no-source-change"
                }
                elseif ($phaseRound -eq 2 -and $hasD1ToD3Decisions -and $dNoOpCountBeforeRound -eq 0 -and $dUnknownNoOpCountBeforeRound -eq 0) {
                    if (-not $EnableFastV2Skip) {
                        $skipRound = $true
                        $roundDecision = "V-SKIP"
                        $skipReason = "fast-skip-v2-flag-false-d-nop-count-0"
                        $fastSkipLine = "[DEV-VERIFY-MULTI] fast_skip_v2=true reason=$skipReason d_nop=$dNoOpCountBeforeRound d_safe_nop=$dSafeNoOpCountBeforeRound d_unknown_nop=$dUnknownNoOpCountBeforeRound"
                        Write-Output $fastSkipLine
                        $lines += $fastSkipLine
                    }
                    else {
                        Write-Output "[DEV-VERIFY-MULTI] fast_skip_not_applied=V2 reason=d-nop-count-zero-exec-all-v d_nop=$dNoOpCountBeforeRound"
                    }
                }
                elseif ($EnableFastV2Skip -and $phaseRound -eq 2 -and $hasD1ToD3Decisions -and $dNoOpCountBeforeRound -gt 0 -and $dNoOpCountBeforeRound -lt 3 -and $dUnknownNoOpCountBeforeRound -eq 0) {
                    $skipRound = $true
                    $roundDecision = "V-SKIP"
                    $skipReason = "fast-skip-v2-d-nop-count-$dNoOpCountBeforeRound-of-3"
                    $fastSkipLine = "[DEV-VERIFY-MULTI] fast_skip_v2=true reason=$skipReason d_nop=$dNoOpCountBeforeRound d_safe_nop=$dSafeNoOpCountBeforeRound d_unknown_nop=$dUnknownNoOpCountBeforeRound"
                    Write-Output $fastSkipLine
                    $lines += $fastSkipLine
                }
                elseif ($EnableFastV2Skip -and $phaseRound -eq 2 -and $hasD1ToD3Decisions -and $dUnknownNoOpCountBeforeRound -gt 0) {
                    Write-Output "[DEV-VERIFY-MULTI] fast_skip_blocked=V2 reason=unknown-d-nop-present count=$dUnknownNoOpCountBeforeRound"
                }
                elseif ($EnableFastV2Skip -and $phaseRound -eq 2 -and $hasD1ToD3Decisions -and $dUnknownNoOpCountBeforeRound -eq 0) {
                    Write-Output "[DEV-VERIFY-MULTI] fast_skip_not_applied=V2 reason=d-nop-count-out-of-range d_nop=$dNoOpCountBeforeRound"
                }
            }
        }
        elseif ($phase -eq "DEV" -and $phaseRound -eq 4 -and $globalNoSourceChange) {
            if ($forceDevFullRound) {
                Write-Output "[DEV-VERIFY-MULTI] round_forced_full=$roundTag reason=guarded-fast-mode-d4"
            }
            else {
                $skipRound = $true
                $roundDecision = "D-SKIP"
                $skipReason = "d-nop-count-eq-3"
                $devRoundDecisions[$roundTag] = "D-SKIP"
            }
        }
    }

    $outDir = ""
    $result = ""
    $exitCode = 0

    if (-not $skipRound -and $phase -eq "DEV") {
        Write-Output ("[DEV-VERIFY-MULTI] code_step_start={0}" -f $roundTag)
        $codeStep = Invoke-CodeStepRound -RoundTag $roundTag -ScriptPath $codeStepScriptPath -OutDir $sessionOutDir -TaskDefinitionFile $resolvedTaskDefinitionFile
        $codeStepExit = $codeStep.ExitCode
        $codeStepAction = if ([string]::IsNullOrWhiteSpace($codeStep.Action)) { "unknown" } else { $codeStep.Action }
        $codeStepLog = $codeStep.LogFile
        $lines += $codeStep.Lines

        $afterCodeStepSnapshot = Get-GitSnapshot -RepoPath $repoRoot
        Write-GitSnapshot -Snapshot $afterCodeStepSnapshot -Tag ("{0}_after_code_step" -f $roundTag)

        $sourceDeltaAfterCodeStep = if ($beforeSnapshot.SourcePatchHash -eq $afterCodeStepSnapshot.SourcePatchHash) {
            "unchanged"
        }
        else {
            "changed"
        }

        if (-not $codeStep.Pass) {
            $roundDecision = "CODE-STEP-FAIL"
        }
        elseif (-not $DisableSourceDrivenSkip -and $phaseRound -le 3 -and $sourceDeltaAfterCodeStep -eq "unchanged") {
            $stateOnlyD1PreexistingSourceDelta = $false
            if ($CodeStepResetPolicy -eq "state-only" -and $phaseRound -eq 1) {
                if (-not [string]::IsNullOrWhiteSpace($taskTargetRelativePath)) {
                    $stateOnlyD1PreexistingSourceDelta = Test-PathListContains -Paths @($beforeSnapshot.SourceDiffNames) -TargetPath $taskTargetRelativePath
                }
                else {
                    $stateOnlyD1PreexistingSourceDelta = (@($beforeSnapshot.SourceDiffNames).Count -gt 0)
                }
            }

            if ($stateOnlyD1PreexistingSourceDelta) {
                $unknownNoOpConsecutive = 0
                $roundDecision = "EXECUTE"
                $skipRound = $false
                $skipReason = ""
                $devRoundDecisions[$roundTag] = "D-CHANGED"
                $devRoundNoOpClasses[$roundTag] = "none"
                $noOpClass = "none"
                $noOpEvidence = "state-only-d1-preexisting-source-delta action=$codeStepAction source_delta_after_code_step=$sourceDeltaAfterCodeStep"
                $overrideLine = "[DEV-VERIFY-MULTI] round_nop_override=$roundTag reason=state-only-d1-preexisting-source-delta action=$codeStepAction"
                Write-Output $overrideLine
                $lines += $overrideLine
            }
            else {
                $roundTask = $null
                if ($roundTaskMap.ContainsKey($roundTag)) {
                    $roundTask = $roundTaskMap[$roundTag]
                }

                $noOp = Get-RoundNoOpClassification `
                    -RoundTag $roundTag `
                    -CodeStepAction $codeStepAction `
                    -BeforeSourceDiffNames @($beforeSnapshot.SourceDiffNames) `
                    -AfterCodeStepSourceDiffNames @($afterCodeStepSnapshot.SourceDiffNames) `
                    -TargetSourceRelativePath $taskTargetRelativePath `
                    -RoundTask $roundTask

                $noOpClass = $noOp.Class
                $noOpEvidence = $noOp.Evidence

                $skipRound = $true
                $skipReason = "no-source-delta-after-code-step"

                if ($noOpClass -eq "unknown-unexplained") {
                    $unknownNoOpCount++
                    $unknownNoOpConsecutive++

                    $budgetExceeded = (($unknownNoOpCount -gt $UnknownNoOpBudget) -or ($unknownNoOpConsecutive -ge $UnknownNoOpConsecutiveLimit))
                    if ($budgetExceeded -and -not $DisableUnknownNoOpBudgetGate) {
                        $roundDecision = "D-NOP-RISK"
                        $skipReason = "unknown-no-op-budget-exceeded-$unknownNoOpCount-of-$UnknownNoOpBudget"
                        $devRoundDecisions[$roundTag] = "D-RISK"
                        $devRoundNoOpClasses[$roundTag] = $noOpClass
                        $unknownNoOpBudgetExceeded = $true
                        $riskLine = "[DEV-VERIFY-MULTI] round_risk=$roundTag reason=$skipReason class=$noOpClass evidence=$noOpEvidence"
                        Write-Output $riskLine
                        $lines += $riskLine
                    }
                    else {
                        $roundDecision = "D-NOP"
                        $devRoundDecisions[$roundTag] = "D-NOP"
                        $devRoundNoOpClasses[$roundTag] = $noOpClass
                        $nopLine = "[DEV-VERIFY-MULTI] round_nop=$roundTag reason=$skipReason class=$noOpClass evidence=$noOpEvidence"
                        Write-Output $nopLine
                        $lines += $nopLine
                    }
                }
                else {
                    $unknownNoOpConsecutive = 0
                    $roundDecision = "D-NOP"
                    $devRoundDecisions[$roundTag] = "D-NOP"
                    $devRoundNoOpClasses[$roundTag] = $noOpClass
                    $nopLine = "[DEV-VERIFY-MULTI] round_nop=$roundTag reason=$skipReason class=$noOpClass evidence=$noOpEvidence"
                    Write-Output $nopLine
                    $lines += $nopLine
                }

                if ($forceDevLightRound -and $roundDecision -eq "D-NOP") {
                    $skipRound = $false
                    $roundDecision = "EXECUTE"
                    $skipReason = ""
                    $lightGateLine = "[DEV-VERIFY-MULTI] round_nop_light_gate=$roundTag profile=strict-only"
                    Write-Output $lightGateLine
                    $lines += $lightGateLine
                }
            }
        }
        else {
            $unknownNoOpConsecutive = 0
            if ($phaseRound -le 3) {
                $devRoundDecisions[$roundTag] = "D-CHANGED"
                $devRoundNoOpClasses[$roundTag] = "none"
            }
            else {
                $devRoundDecisions[$roundTag] = "D-EXECUTED"
            }
        }

        if (-not $DisableSourceDrivenSkip -and $phaseRound -eq 3) {
            $dNoOpCountAfterD3 = Get-D1ToD3NoOpCount -Decisions $devRoundDecisions
            $dSafeNoOpCountAfterD3 = Get-D1ToD3SafeNoOpCount -Decisions $devRoundDecisions -NoOpClasses $devRoundNoOpClasses
            $dUnknownNoOpCountAfterD3 = Get-D1ToD3UnknownNoOpCount -Decisions $devRoundDecisions -NoOpClasses $devRoundNoOpClasses
            $allNoOp = (($dNoOpCountAfterD3 -eq 3) -and ($dUnknownNoOpCountAfterD3 -eq 0))
            if ($allNoOp) {
                $globalNoSourceChange = $true
                $globalLine = "[DEV-VERIFY-MULTI] global_early_stop=true reason=d-nop-count-eq-3 d_nop=$dNoOpCountAfterD3 d_safe_nop=$dSafeNoOpCountAfterD3 d_unknown_nop=$dUnknownNoOpCountAfterD3"
                Write-Output $globalLine
                $lines += $globalLine
            }
        }

        if (-not $skipRound -and $devStrideSkipsAutopilot -and $roundDecision -ne "CODE-STEP-FAIL" -and $roundDecision -ne "D-NOP-RISK" -and -not $forceDevLightRound -and -not $forceDevFullRound) {
            $skipRound = $true
            $roundDecision = "D-CODESTEP-ONLY"
            $skipReason = "dev-verify-stride-$DevVerifyStride"
            $strideLine = "[DEV-VERIFY-MULTI] round_stride_skip=$roundTag reason=$skipReason"
            Write-Output $strideLine
            $lines += $strideLine
        }
    }

    if (-not $skipRound -and $roundDecision -ne "CODE-STEP-FAIL") {
        $roundVerifyProfile = if ($phase -eq "VERIFY") { $roundVerifyExecutionProfile } else { "n/a" }
        Write-Output ("[DEV-VERIFY-MULTI] round_policy={0} dev_profile={1} verify_profile={2} force_dev_light={3} force_dev_full={4} force_verify_full={5}" -f $roundTag, $roundDevExecutionProfile, $roundVerifyProfile, $forceDevLightRound, $forceDevFullRound, $forceVerifyFullRound)
        Write-Output ("[DEV-VERIFY-MULTI] round_start={0} phase={1} mode={2} phase_mode={3} verify_profile={4}" -f $roundTag, $phase, $effectiveMode, $mode, $roundVerifyProfile)

        $autopilotParams = @{
            Mode = $effectiveMode
            DevExecutionProfile = $roundDevExecutionProfile
            VerifyExecutionProfile = $roundVerifyExecutionProfile
            StartRound = $round
            EndRound = $round
            Version = $Version
            BinaryPath = $BinaryPath
            RemoteIp = $RemoteIp
            User = $User
            KeyPath = $KeyPath
            Smoke = $Smoke
            Queries = $Queries
            VerifyRound3Queries = $VerifyRound3Queries
            SyncDir = $SyncDir
            Golden = $Golden
            OptProfile = $OptProfile
            Step47ListFile = $Step47ListFile
            PreclassThresholdFile = $PreclassThresholdFile
            QuietRemoteBuildLogs = $QuietRemoteBuildLogs
            QuietTerminalOutput = $QuietTerminalOutput
            RbPreflight = $RbPreflight
            RbPreclassTableGuard = $RbPreclassTableGuard
            GitBashPath = $GitBashPath
            NoDeltaRetryMax = $NoDeltaRetryMax
            D6RetryMax = $D6RetryMax
            OutDirRoot = $AutopilotOutDirRoot
        }

        # Outer wrapper already performs code-step and source-driven skip decisions.
        # Do not forward gate-only source-driven skip into inner autopilot, otherwise
        # DEV rounds can be reclassified as D-NOP based on inner no-op code-step.

        if (-not [string]::IsNullOrWhiteSpace($SmokeArgs)) {
            $autopilotParams["SmokeArgs"] = $SmokeArgs
        }
        if (-not [string]::IsNullOrWhiteSpace($CflagsExtra)) {
            $autopilotParams["CflagsExtra"] = $CflagsExtra
        }

        Write-Output ("[DEV-VERIFY-MULTI] autopilot_start={0}" -f $roundTag)
        $emitTerminal = ($QuietTerminalOutput -ne "true")
        $invokeResult = Invoke-StreamingCapture -Action { & $autopilotScript @autopilotParams } -EmitToConsole:$emitTerminal
        $exitCode = $invokeResult.ExitCode
        $autopilotExecuted = $true

        $runLines = ConvertTo-NormalizedLine -Raw $invokeResult.Raw
        $lines += $runLines
        $autopilotEndLine = ("[DEV-VERIFY-MULTI] autopilot_end={0} exit={1}" -f $roundTag, $exitCode)
        Write-Output $autopilotEndLine
        $lines += $autopilotEndLine

        foreach ($line in $runLines) {
            if ($line -match '^\[AUTOPILOT-8R\] out_dir=(.+)$') {
                $outDir = $Matches[1].Trim()
            }
            if ($line -match '^\[AUTOPILOT-8R\] result=(pass|fail)$') {
                $result = $Matches[1]
            }
        }
    }
    elseif ($roundDecision -eq "CODE-STEP-FAIL") {
        $exitCode = if ($codeStepExit -ne 0) { $codeStepExit } else { 1 }
        $result = "fail"
    }
    elseif ($roundDecision -eq "ROUND-GATE-FAIL") {
        $exitCode = 1
        $result = "fail"
    }
    elseif ($roundDecision -eq "D-NOP-RISK") {
        $exitCode = 1
        $result = "fail"
    }
    else {
        $exitCode = 0
        if ($roundDecision -eq "D-CODESTEP-ONLY") {
            $result = "code-step-only"
        }
        elseif ($globalNoSourceChange) {
            $result = "no-source-change"
        }
        else {
            $result = "skip"
        }

        $skipLine = ("[DEV-VERIFY-MULTI] round_skip={0} decision={1} reason={2}" -f $roundTag, $roundDecision, $skipReason)
        Write-Output $skipLine
        $lines += $skipLine
    }

    $afterSnapshot = Get-GitSnapshot -RepoPath $repoRoot
    Write-GitSnapshot -Snapshot $afterSnapshot -Tag ("{0}_after" -f $roundTag)

    $beforeStatusCount = @($beforeSnapshot.StatusLines).Count
    $afterStatusCount = @($afterSnapshot.StatusLines).Count
    $beforeDiffNames = Join-OrNone -Items @($beforeSnapshot.DiffNames)
    $afterDiffNames = Join-OrNone -Items @($afterSnapshot.DiffNames)
    $beforeSourceDiffNames = Join-OrNone -Items @($beforeSnapshot.SourceDiffNames)
    $afterCodeStepSourceDiffNames = Join-OrNone -Items @($afterCodeStepSnapshot.SourceDiffNames)
    $afterSourceDiffNames = Join-OrNone -Items @($afterSnapshot.SourceDiffNames)
    $beforeStatusText = (@($beforeSnapshot.StatusLines) -join "`n")
    $afterStatusText = (@($afterSnapshot.StatusLines) -join "`n")
    $snapshotDelta = if (($beforeSnapshot.Head -eq $afterSnapshot.Head) -and
        ($beforeStatusText -eq $afterStatusText) -and
        ($beforeDiffNames -eq $afterDiffNames)) {
        "unchanged"
    }
    else {
        "changed"
    }

    $roundPass = if ($roundDecision -eq "CODE-STEP-FAIL" -or $roundDecision -eq "ROUND-GATE-FAIL" -or $roundDecision -eq "D-NOP-RISK") {
        $false
    }
    elseif ($skipRound) {
        $true
    }
    else {
        ($exitCode -eq 0 -and $result -eq "pass")
    }

    if (-not $result -or $result.Trim().Length -eq 0) {
        $result = if ($roundPass) { "pass" } else { "unknown" }
    }

    $roundEndTime = Get-Date
    $roundElapsed = $roundEndTime - $roundStartTime
    $roundTimingLine = ("[DEV-VERIFY-MULTI] round_timing={0} started_at={1} finished_at={2} elapsed={3} total_seconds={4:N3}" -f $roundTag, $roundStartTime.ToString("yyyy-MM-dd HH:mm:ss"), $roundEndTime.ToString("yyyy-MM-dd HH:mm:ss"), (Format-ElapsedString -Elapsed $roundElapsed), $roundElapsed.TotalSeconds)
    Write-Output $roundTimingLine
    $lines += $roundTimingLine

    $roundLog = Join-Path $sessionOutDir ("{0}.log" -f $roundTag)
    $lines | Out-File -FilePath $roundLog -Encoding utf8

    $dNoOpCountAfterRound = Get-D1ToD3NoOpCount -Decisions $devRoundDecisions
    $dSafeNoOpCountAfterRound = Get-D1ToD3SafeNoOpCount -Decisions $devRoundDecisions -NoOpClasses $devRoundNoOpClasses
    $dUnknownNoOpCountAfterRound = Get-D1ToD3UnknownNoOpCount -Decisions $devRoundDecisions -NoOpClasses $devRoundNoOpClasses
    $checklistMark = ""
    $checklistComment = ""
    if ($roundDecision -eq "D-NOP-RISK") {
        $checklistMark = "ERROR"
        $checklistComment = "unknown-no-op budget exceeded; fast path blocked"
    }
    elseif ($roundDecision -eq "ROUND-GATE-FAIL") {
        $checklistMark = "ERROR"
        $checklistComment = "round runtime gate failed; early stop"
    }
    elseif ($roundDecision -eq "D-CODESTEP-ONLY") {
        $checklistMark = "CODE-STEP-ONLY"
        $checklistComment = "autopilot skipped by dev_verify_stride"
    }
    elseif ($skipRound) {
        $checklistMark = "NOT-RUN"
        $checklistComment = "unexecuted; decision=$roundDecision; reason=$skipReason"
    }
    elseif ($roundDecision -eq "CODE-STEP-FAIL") {
        $checklistMark = "ERROR"
        $checklistComment = "code-step failed before round execution"
    }
    elseif (-not $autopilotExecuted -and $phase -eq "DEV") {
        $checklistMark = "CODE-STEP-ONLY"
        $checklistComment = "autopilot run not executed"
    }

    $rows += [pscustomobject]@{
        Round = $round
        Phase = $phase
        RoundTag = $roundTag
        GuardedFastMode = $guardedFastModeActive
        ForceDevLightRound = $forceDevLightRound
        ForceDevFullRound = $forceDevFullRound
        ForceVerifyFullRound = $forceVerifyFullRound
        RoundDevExecutionProfile = $roundDevExecutionProfile
        RoundVerifyExecutionProfile = $roundVerifyExecutionProfile
        Mode = $mode
        EffectiveMode = $effectiveMode
        VerifyExecutionProfile = $VerifyExecutionProfile
        RoundDecision = $roundDecision
        SkipReason = $skipReason
        RoundGateApplied = $roundGateApplied
        RoundGatePass = $roundGatePass
        RoundGateAttempts = $roundGateAttempts
        RoundGateRequiredFailures = $roundGateRequiredFailures
        RoundGateOptionalFailures = $roundGateOptionalFailures
        RoundGateReason = $roundGateReason
        ExitCode = $exitCode
        Result = $result
        RoundPass = $roundPass
        AutopilotExecuted = $autopilotExecuted
        AutopilotOutDir = $outDir
        CodeStepAction = if ($codeStepAction) { $codeStepAction } else { "(none)" }
        CodeStepExit = $codeStepExit
        CodeStepLog = if ($codeStepLog) { $codeStepLog } else { "" }
        RoundStartedAt = $roundStartTime.ToString("yyyy-MM-dd HH:mm:ss")
        RoundFinishedAt = $roundEndTime.ToString("yyyy-MM-dd HH:mm:ss")
        RoundElapsed = Format-ElapsedString -Elapsed $roundElapsed
        RoundElapsedSeconds = [Math]::Round($roundElapsed.TotalSeconds, 3)
        BeforeHead = $beforeSnapshot.Head
        AfterHead = $afterSnapshot.Head
        BeforeStatusCount = $beforeStatusCount
        AfterStatusCount = $afterStatusCount
        BeforeDiffNames = $beforeDiffNames
        AfterDiffNames = $afterDiffNames
        BeforeSourceDiffNames = $beforeSourceDiffNames
        AfterCodeStepSourceDiffNames = $afterCodeStepSourceDiffNames
        AfterSourceDiffNames = $afterSourceDiffNames
        SourceDeltaAfterCodeStep = $sourceDeltaAfterCodeStep
        NoOpClass = $noOpClass
        NoOpEvidence = $noOpEvidence
        SnapshotDelta = $snapshotDelta
        GlobalNoSourceChange = $globalNoSourceChange
        D1D3NoOpCount = $dNoOpCountAfterRound
        D1D3SafeNoOpCount = $dSafeNoOpCountAfterRound
        D1D3UnknownNoOpCount = $dUnknownNoOpCountAfterRound
        UnknownNoOpCount = $unknownNoOpCount
        UnknownNoOpBudget = $UnknownNoOpBudget
        UnknownNoOpConsecutive = $unknownNoOpConsecutive
        UnknownNoOpConsecutiveLimit = $UnknownNoOpConsecutiveLimit
        UnknownNoOpBudgetExceeded = $unknownNoOpBudgetExceeded
        TaskDesignQualityPolicy = $TaskDesignQualityPolicy
        ChecklistMark = $checklistMark
        ChecklistComment = $checklistComment
        TaskDefinitionFile = if ($resolvedTaskDefinitionFile) { $resolvedTaskDefinitionFile } else { "(default-in-code-step)" }
        LogFile = $roundLog
    }

    $partialCsv = Join-Path $sessionOutDir "summary_partial.csv"
    $rows | Export-Csv -Path $partialCsv -NoTypeInformation -Encoding UTF8

    if (-not $roundPass) {
        Write-Output ("[DEV-VERIFY-MULTI] round_fail={0}" -f $roundTag)
        break
    }

    Write-Output ("[DEV-VERIFY-MULTI] round_pass={0} decision={1}" -f $roundTag, $roundDecision)
}

$summaryCsv = Join-Path $sessionOutDir "summary.csv"
$summaryTxt = Join-Path $sessionOutDir "summary.txt"
$rows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$rows | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$expected = $EndRound - $StartRound + 1
$allPass = ($rows.Count -eq $expected) -and (@($rows | Where-Object { -not $_.RoundPass }).Count -eq 0)

Write-Output ("[DEV-VERIFY-MULTI] out_dir={0}" -f $sessionOutDir)
Write-Output ("[DEV-VERIFY-MULTI] summary_csv={0}" -f $summaryCsv)
Write-Output ("[DEV-VERIFY-MULTI] summary_txt={0}" -f $summaryTxt)

if ($globalNoSourceChange) {
    Write-Output "[DEV-VERIFY-MULTI] final_conclusion=already-applied+unchanged"
    Write-Output "[DEV-VERIFY-MULTI] checklist_backfill_note=unexecuted_rounds_marked_by_ChecklistMark_and_ChecklistComment"
}

if ($unknownNoOpBudgetExceeded) {
    Write-Output "[DEV-VERIFY-MULTI] quality_gate=unknown-no-op-budget-exceeded action=blocked"
}

$finalResult = if ($allPass) { "pass" } else { "fail" }
$finalExitCode = if ($allPass) { 0 } else { 1 }
$nextRoundReady = $allPass
$finalDecision = if ($nextRoundReady) { "continue-next-round" } else { "stop-and-investigate" }
$failedRoundTags = @($rows | Where-Object { -not $_.RoundPass } | ForEach-Object { $_.RoundTag })
$failedRows = @($rows | Where-Object { -not $_.RoundPass } | Sort-Object Round)
$firstFailedRow = if ($failedRows.Count -gt 0) { $failedRows[0] } else { $null }

$statusJson = Join-Path $sessionOutDir "final_status.json"
$statusTxt = Join-Path $sessionOutDir "final_status.txt"
$finalStatus = [ordered]@{
    Script = "DEV-VERIFY-MULTI"
    Result = $finalResult
    ExitCode = $finalExitCode
    NextRoundReady = $nextRoundReady
    FinalDecision = $finalDecision
    ExpectedRoundCount = $expected
    CompletedRoundCount = $rows.Count
    FailedRoundTags = @($failedRoundTags)
    FailedRoundDecision = if ($null -ne $firstFailedRow) { [string]$firstFailedRow.RoundDecision } else { "" }
    FailedRoundReason = if ($null -ne $firstFailedRow) { [string]$firstFailedRow.SkipReason } else { "" }
    FailedRoundGateReason = if ($null -ne $firstFailedRow) { [string]$firstFailedRow.RoundGateReason } else { "" }
    OutDir = $sessionOutDir
    SummaryCsv = $summaryCsv
    SummaryTxt = $summaryTxt
    GlobalNoSourceChange = $globalNoSourceChange
    UnknownNoOpBudgetExceeded = $unknownNoOpBudgetExceeded
    GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

($finalStatus | ConvertTo-Json -Depth 5) | Out-File -FilePath $statusJson -Encoding utf8
@(
    "script=DEV-VERIFY-MULTI"
    "result=$finalResult"
    "exit_code=$finalExitCode"
    "next_round_ready=$(([string]$nextRoundReady).ToLowerInvariant())"
    "final_decision=$finalDecision"
    "out_dir=$sessionOutDir"
    "summary_csv=$summaryCsv"
    "summary_txt=$summaryTxt"
    "status_json=$statusJson"
) | Out-File -FilePath $statusTxt -Encoding utf8

Write-Output ("[DEV-VERIFY-MULTI] status_json={0}" -f $statusJson)
Write-Output ("[DEV-VERIFY-MULTI] status_txt={0}" -f $statusTxt)
Write-Output ("[DEV-VERIFY-MULTI] next_round_ready={0}" -f $(([string]$nextRoundReady).ToLowerInvariant()))
Write-Output ("[DEV-VERIFY-MULTI] final_decision={0}" -f $finalDecision)

Stop-TerminalWatchdogProcess -Process $terminalWatchdogProcess
Write-Output ("[DEV-VERIFY-MULTI] shutdown_pid pid={0}" -f $PID)

if ($allPass) {
    Write-Output "[DEV-VERIFY-MULTI] result=pass"
    Write-RunTimingSummary -Tag "DEV-VERIFY-MULTI" -StartTime $runStart
    exit 0
}

Write-Output "[DEV-VERIFY-MULTI] result=fail"
Write-RunTimingSummary -Tag "DEV-VERIFY-MULTI" -StartTime $runStart
exit 1
