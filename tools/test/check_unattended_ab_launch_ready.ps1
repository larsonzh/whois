param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [ValidateSet('A', 'B')][string]$Stage = 'A',
    [string]$Operator = 'Copilot',
    [switch]$GuardManagedLaunch,
    [switch]$RequireCleanWorkspace,
    [switch]$DryRun,
    [switch]$DetailedOutput,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'CHECK-UNATTENDED-AB-LAUNCH-READY'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

$useDetailedOutput = $DetailedOutput.IsPresent
$useAsJsonOutput = $AsJson.IsPresent

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

function Test-IsCiEnvironment {
    $ciFlags = @(
        [string]$env:CI,
        [string]$env:GITHUB_ACTIONS,
        [string]$env:TF_BUILD,
        [string]$env:BUILD_BUILDID
    )

    foreach ($flag in $ciFlags) {
        if (Convert-ToBooleanSetting -Value $flag -Default $false) {
            return $true
        }
    }

    return $false
}

function Get-ResultObject {
    param(
        [string]$Step,
        [string]$Status,
        [string]$Reason,
        [string[]]$OutputLines,
        [string]$StartFilePath
    )

    return [ordered]@{
        schema = 'AB_LAUNCH_READY_CHECK_V1'
        generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        start_file = $StartFilePath
        result = $Status
        step = $Step
        status = $Status
        reason = $Reason
        output = @($OutputLines)
    }
}

function Write-ResultAndExit {
    param(
        [string]$Step,
        [string]$Status,
        [string]$Reason,
        [string[]]$OutputLines,
        [int]$ExitCode,
        [string]$StartFilePath
    )

    $result = Get-ResultObject -Step $Step -Status $Status -Reason $Reason -OutputLines $OutputLines -StartFilePath $StartFilePath
    if ($useAsJsonOutput) {
        $result | ConvertTo-Json -Depth 6
    }
    else {
        $displayStatus = ([string]$Status).Trim().ToLowerInvariant()
        $displayLines = Get-CondensedOutput -Lines $OutputLines -Detailed:$useDetailedOutput
        Write-Output ('[AB-LAUNCH-READY] start_file={0}' -f $StartFilePath)
        Write-Output ('[AB-LAUNCH-READY] step={0} status={1} reason={2}' -f $Step, $displayStatus, $Reason)
        foreach ($line in @($displayLines)) {
            Write-Output ('[AB-LAUNCH-READY] detail={0}' -f $line)
        }
        Write-Output ('[AB-LAUNCH-READY] result={0}' -f $displayStatus)
    }

    exit $ExitCode
}

function Get-FirstMeaningfulLine {
    param([string[]]$Lines)

    foreach ($line in @($Lines)) {
        if ([string]::IsNullOrWhiteSpace([string]$line)) {
            continue
        }

        return ([string]$line).Trim()
    }

    return 'no-output'
}

function Get-LastMatchingLine {
    param(
        [string[]]$Lines,
        [string]$Pattern
    )

    $matchedLines = @($Lines | Where-Object { ([string]$_) -match $Pattern })
    if ($matchedLines.Count -gt 0) {
        return [string]$matchedLines[$matchedLines.Count - 1]
    }

    return ''
}

function Get-RouteGuardSuiteAggregateLines {
    param([string[]]$Lines)

    $result = New-Object 'System.Collections.Generic.List[string]'
    $outDirLine = Get-LastMatchingLine -Lines $Lines -Pattern '^\[ROUTE-GUARD-SMOKE-SUITE\] out_dir='
    $exitLine = Get-LastMatchingLine -Lines $Lines -Pattern '^\[ROUTE-GUARD-SMOKE-SUITE\] trigger_exit='
    $triggerSummaryLine = Get-LastMatchingLine -Lines $Lines -Pattern '^\[ROUTE-GUARD-SMOKE-SUITE\] trigger_summary='
    $dispatchSummaryLine = Get-LastMatchingLine -Lines $Lines -Pattern '^\[ROUTE-GUARD-SMOKE-SUITE\] dispatch_summary='
    $classificationSummaryLine = Get-LastMatchingLine -Lines $Lines -Pattern '^\[ROUTE-GUARD-SMOKE-SUITE\] classification_summary='

    if (-not [string]::IsNullOrWhiteSpace($exitLine)) {
        [void]$result.Add($exitLine)
    }
    if (-not [string]::IsNullOrWhiteSpace($triggerSummaryLine)) {
        [void]$result.Add($triggerSummaryLine)
    }
    if (-not [string]::IsNullOrWhiteSpace($dispatchSummaryLine)) {
        [void]$result.Add($dispatchSummaryLine)
    }
    if (-not [string]::IsNullOrWhiteSpace($classificationSummaryLine)) {
        [void]$result.Add($classificationSummaryLine)
    }

    if (-not [string]::IsNullOrWhiteSpace($outDirLine)) {
        [void]$result.Add($outDirLine)

        $outDir = $outDirLine -replace '^\[ROUTE-GUARD-SMOKE-SUITE\] out_dir=', ''
        $summaryPath = Join-Path $outDir 'summary.json'
        if (Test-Path -LiteralPath $summaryPath) {
            try {
                $suiteSummary = Get-Content -LiteralPath $summaryPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
                [void]$result.Add(('[ROUTE-GUARD-SMOKE-SUITE] summary_json={0}' -f $summaryPath))
                [void]$result.Add(('[ROUTE-GUARD-SMOKE-SUITE] aggregate pass={0} trigger_exit={1} dispatch_exit={2} classification_exit={3}' -f [bool]$suiteSummary.pass, [int]$suiteSummary.trigger.exit_code, [int]$suiteSummary.dispatch.exit_code, [int]$suiteSummary.classification_contract.exit_code))
            }
            catch {
                [void]$result.Add(('[ROUTE-GUARD-SMOKE-SUITE] summary_json_parse_failed={0}' -f $_.Exception.Message))
            }
        }
    }

    return @($result.ToArray())
}

function Get-CondensedOutput {
    param(
        [string[]]$Lines,
        [switch]$Detailed
    )

    if ($Detailed.IsPresent) {
        return @($Lines)
    }

    $patterns = @(
        'result=FAIL',
        'result=PASS',
        'aggregate pass=',
        'trigger_exit=',
        'dispatch_exit=',
        'classification_exit=',
        'summary_json=',
        'status=FAIL',
        'severity=error',
        'severity=warn',
        'warning_gate=fail',
        'summary errors=',
        'lock=busy',
        'mutex busy',
        'lock_busy=true',
        'writeback=done',
        'dry_run=true action=no_write',
        'missing_',
        'template_',
        'entry_script_a'
    )

    $kept = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in @($Lines)) {
        $text = [string]$line
        if ([string]::IsNullOrWhiteSpace($text)) {
            continue
        }

        foreach ($pattern in $patterns) {
            if ($text -match $pattern) {
                [void]$kept.Add($text)
                break
            }
        }
    }

    $result = @($kept | Select-Object -Unique)
    if ($result.Count -eq 0) {
        return @((Get-FirstMeaningfulLine -Lines $Lines))
    }

    if ($result.Count -gt 12) {
        return @(
            @($result | Select-Object -First 12) +
            ('... condensed {0} additional line(s); rerun with -DetailedOutput for full details' -f ($result.Count - 12))
        )
    }

    return $result
}

function Invoke-PowerShellScriptStep {
    param(
        [string]$ScriptPath,
        [string[]]$Arguments
    )

    $lines = @((& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @Arguments 2>&1) | ForEach-Object { [string]$_ })
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Lines = @($lines)
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = if ([System.IO.Path]::IsPathRooted($StartFile)) {
    [System.IO.Path]::GetFullPath($StartFile)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $StartFile))
}
$startSettings = $null

try {
    $startFilePath = Resolve-RepoPath -Path $StartFile -MustExist $true
    $startSettings = Read-KeyValueFile -Path $startFilePath
}
catch {
    Write-ResultAndExit -Step 'start-file' -Status 'FAIL' -Reason $_.Exception.Message -OutputLines @() -ExitCode 1 -StartFilePath $startFilePath
}

$requiredKeys = @(
    'A_TASK_DEFINITION',
    'B_TASK_DEFINITION',
    'RUN_MODE',
    'ENTRY_MODE',
    'TASK_STATIC_PRECHECK_POLICY',
    'TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS'
)

$missingKeys = @($requiredKeys | Where-Object { -not $startSettings.Contains($_) -or [string]::IsNullOrWhiteSpace([string]$startSettings[$_]) })
if ($missingKeys.Count -gt 0) {
    Write-ResultAndExit -Step 'start-file' -Status 'FAIL' -Reason ('missing required key(s): {0}' -f ($missingKeys -join ',')) -OutputLines @() -ExitCode 1 -StartFilePath $startFilePath
}

$aTaskDefinition = [string]$startSettings.A_TASK_DEFINITION
$bTaskDefinition = [string]$startSettings.B_TASK_DEFINITION
$taskStaticPrecheckPolicy = [string]$startSettings.TASK_STATIC_PRECHECK_POLICY
$taskStaticFailOnWarnings = Convert-ToBooleanSetting -Value ([string]$startSettings.TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS) -Default $true
$taskStaticPrecheckFailureMode = if ($startSettings.Contains('TASK_STATIC_PRECHECK_FAILURE_MODE')) {
    ([string]$startSettings.TASK_STATIC_PRECHECK_FAILURE_MODE).Trim().ToLowerInvariant()
}
else {
    'block'
}
if ($taskStaticPrecheckFailureMode -notin @('block', 'runtime-ticket')) {
    Write-ResultAndExit -Step 'start-file' -Status 'FAIL' -Reason ('invalid TASK_STATIC_PRECHECK_FAILURE_MODE={0}' -f $taskStaticPrecheckFailureMode) -OutputLines @() -ExitCode 1 -StartFilePath $startFilePath
}
$expectedRunMode = [string]$startSettings.RUN_MODE
$expectedEntryMode = [string]$startSettings.ENTRY_MODE

try {
    $resolvedATask = Resolve-RepoPath -Path $aTaskDefinition -MustExist $true
    $resolvedBTask = Resolve-RepoPath -Path $bTaskDefinition -MustExist $true
}
catch {
    Write-ResultAndExit -Step 'start-file' -Status 'FAIL' -Reason $_.Exception.Message -OutputLines @(
        ('A_TASK_DEFINITION={0}' -f $aTaskDefinition),
        ('B_TASK_DEFINITION={0}' -f $bTaskDefinition)
    ) -ExitCode 1 -StartFilePath $startFilePath
}

$startFileLines = @(
    ('STAGE={0}' -f $Stage),
    ('A_TASK_DEFINITION={0}' -f $resolvedATask),
    ('B_TASK_DEFINITION={0}' -f $resolvedBTask),
    ('RUN_MODE={0}' -f $expectedRunMode),
    ('ENTRY_MODE={0}' -f $expectedEntryMode),
    ('TASK_STATIC_PRECHECK_POLICY={0}' -f $taskStaticPrecheckPolicy),
    ('TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS={0}' -f $taskStaticFailOnWarnings),
    ('TASK_STATIC_PRECHECK_FAILURE_MODE={0}' -f $taskStaticPrecheckFailureMode)
)

$staticCheckScript = Resolve-RepoPath -Path 'tools/test/check_task_definition_static.ps1' -MustExist $true
$ps51FormatGuardScript = Resolve-RepoPath -Path 'tools/test/check_ps51_format_inline_if_guard.ps1' -MustExist $true
$fieldSyncScript = Resolve-RepoPath -Path 'tools/test/check_unattended_start_field_sync.ps1' -MustExist $true
$statusMiniRegressionScript = Resolve-RepoPath -Path 'tools/test/status_ticket_mini_regression.ps1' -MustExist $true
$retryBudgetMiniRegressionScript = Resolve-RepoPath -Path 'tools/test/retry_budget_minimal_regression.ps1' -MustExist $true
$routeGuardSmokeSuiteScript = Resolve-RepoPath -Path 'tools/test/route_guard_smoke_suite.ps1' -MustExist $true
$incrementalEncodingScript = Resolve-RepoPath -Path 'tools/dev/enforce_utf8_bom_lf_changed.ps1' -MustExist $true
$encodingFormatScript = Resolve-RepoPath -Path 'tools/dev/enforce_utf8_bom_lf.ps1' -MustExist $true
$srcEncodingScript = Resolve-RepoPath -Path 'tools/dev/enforce_utf8_lf_src_changed.ps1' -MustExist $true
$precheckScript = Resolve-RepoPath -Path 'tools/test/precheck_unattended_ab_start_file.ps1' -MustExist $true

$staticCheckMessages = New-Object 'System.Collections.Generic.List[string]'
$stageTaskDefinition = if ($Stage -eq 'A') { $resolvedATask } else { $resolvedBTask }
$syntaxCheckArgs = @(
    '-TaskDefinitionFile', $stageTaskDefinition,
    '-RepoRoot', $repoRoot,
    '-Policy', $taskStaticPrecheckPolicy,
    '-SyntaxOnly'
)
if ($taskStaticFailOnWarnings) {
    $syntaxCheckArgs += '-FailOnWarnings'
}

$syntaxCheck = Invoke-PowerShellScriptStep -ScriptPath $staticCheckScript -Arguments $syntaxCheckArgs
if ($syntaxCheck.ExitCode -ne 0) {
    $reason = Get-LastMatchingLine -Lines $syntaxCheck.Lines -Pattern 'severity=error|warning_gate=fail|\[TASK-STATIC-CHECK\] invalid|\[TASK-STATIC-CHECK\] task definition|\[TASK-STATIC-CHECK\] target file'
    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = Get-FirstMeaningfulLine -Lines $syntaxCheck.Lines
    }

    Write-ResultAndExit -Step ('task-definition-syntax-check-{0}' -f $Stage.ToLowerInvariant()) -Status 'FAIL' -Reason $reason -OutputLines $syntaxCheck.Lines -ExitCode 1 -StartFilePath $startFilePath
}
else {
    [void]$staticCheckMessages.Add(('{0} task-definition SyntaxOnly load check passed: {1}' -f $Stage, $stageTaskDefinition))
}

$fieldSync = Invoke-PowerShellScriptStep -ScriptPath $fieldSyncScript -Arguments @(
    '-StartFile', $startFilePath,
    '-EnforceRunningStatusMessageTemplateMatch'
)
if ($fieldSync.ExitCode -ne 0) {
    $reason = Get-LastMatchingLine -Lines $fieldSync.Lines -Pattern 'missing_|result=fail|entry_script_a|template_'
    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = Get-FirstMeaningfulLine -Lines $fieldSync.Lines
    }

    Write-ResultAndExit -Step 'start-field-sync' -Status 'FAIL' -Reason $reason -OutputLines $fieldSync.Lines -ExitCode 1 -StartFilePath $startFilePath
}

$statusMiniRegression = Invoke-PowerShellScriptStep -ScriptPath $statusMiniRegressionScript -Arguments @()
if ($statusMiniRegression.ExitCode -ne 0) {
    $reason = Get-LastMatchingLine -Lines $statusMiniRegression.Lines -Pattern 'result=fail|missing-|case='    
    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = Get-FirstMeaningfulLine -Lines $statusMiniRegression.Lines
    }

    Write-Output ('[AB-LAUNCH-READY] step=status-ticket-mini-regression status=WARN reason={0}' -f $reason)
    foreach ($line in @($statusMiniRegression.Lines)) {
        Write-Output ('[AB-LAUNCH-READY] detail={0}' -f $line)
    }
}

$retryBudgetMiniRegressionEnabled = $true
if ($startSettings.Contains('RETRY_BUDGET_MINI_REGRESSION_ENABLED')) {
    $retryBudgetMiniRegressionEnabled = Convert-ToBooleanSetting -Value ([string]$startSettings.RETRY_BUDGET_MINI_REGRESSION_ENABLED) -Default $true
}

$retryBudgetMiniRegressionSummary = 'Retry-budget minimal regression skipped (disabled by start-file setting).'
if ($retryBudgetMiniRegressionEnabled) {
    $retryBudgetMiniRegressionArgs = @(
        '-StartFile', $startFilePath,
        '-AsJson'
    )
    $retryBudgetMiniRegression = Invoke-PowerShellScriptStep -ScriptPath $retryBudgetMiniRegressionScript -Arguments $retryBudgetMiniRegressionArgs
    if ($retryBudgetMiniRegression.ExitCode -ne 0) {
        $reason = Get-LastMatchingLine -Lines $retryBudgetMiniRegression.Lines -Pattern 'all_pass=false|ledger_status|retry-budget-receipt-missing-or-mismatch|result=FAIL'
        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = Get-FirstMeaningfulLine -Lines $retryBudgetMiniRegression.Lines
        }

        Write-Output ('[AB-LAUNCH-READY] step=retry-budget-mini-regression status=WARN reason={0}' -f $reason)
        foreach ($line in @($retryBudgetMiniRegression.Lines)) {
            Write-Output ('[AB-LAUNCH-READY] detail={0}' -f $line)
        }
        $retryBudgetMiniRegressionSummary = 'Retry-budget minimal regression warned (non-blocking).'
    }
    else {
        $retryBudgetMiniRegressionSummary = 'Retry-budget minimal regression passed.'
    }
}

$routeGuardSmokeSuiteConfigured = $null
if ($startSettings.Contains('ROUTE_GUARD_SMOKE_SUITE_ENABLED')) {
    $routeGuardSmokeSuiteConfigured = Convert-ToBooleanSetting -Value ([string]$startSettings.ROUTE_GUARD_SMOKE_SUITE_ENABLED) -Default $true
}

$ciMode = Test-IsCiEnvironment
$routeGuardSmokeSuiteEnabled = $true
if ($null -ne $routeGuardSmokeSuiteConfigured) {
    $routeGuardSmokeSuiteEnabled = [bool]$routeGuardSmokeSuiteConfigured
}
elseif ($GuardManagedLaunch.IsPresent -and -not $ciMode) {
    $routeGuardSmokeSuiteEnabled = $false
}

if ($routeGuardSmokeSuiteEnabled) {
    $routeGuardSmokeSuite = Invoke-PowerShellScriptStep -ScriptPath $routeGuardSmokeSuiteScript -Arguments @()
    if ($routeGuardSmokeSuite.ExitCode -ne 0) {
        $aggregateLines = @(Get-RouteGuardSuiteAggregateLines -Lines $routeGuardSmokeSuite.Lines)
        $reason = Get-LastMatchingLine -Lines $aggregateLines -Pattern 'trigger_exit=|dispatch_exit=|classification_exit=|classification_summary|result=fail'
        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = Get-LastMatchingLine -Lines $routeGuardSmokeSuite.Lines -Pattern 'result=fail|classification_summary|trigger_exit=|dispatch_exit='
        }
        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = Get-FirstMeaningfulLine -Lines $routeGuardSmokeSuite.Lines
        }

        $outputLines = @($aggregateLines + $routeGuardSmokeSuite.Lines)
        Write-ResultAndExit -Step 'route-guard-smoke-suite' -Status 'FAIL' -Reason $reason -OutputLines $outputLines -ExitCode 1 -StartFilePath $startFilePath
    }
}
else {
    Write-Output ('[AB-LAUNCH-READY] detail=route-guard-smoke-suite skipped guard_managed={0} ci_mode={1} configured={2}' -f [string]$GuardManagedLaunch.IsPresent, [string]$ciMode, [string]($null -ne $routeGuardSmokeSuiteConfigured))
}

$ps51FormatGuard = Invoke-PowerShellScriptStep -ScriptPath $ps51FormatGuardScript -Arguments @('-Scope', 'tracked')
if ($ps51FormatGuard.ExitCode -ne 0) {
    $reason = Get-LastMatchingLine -Lines $ps51FormatGuard.Lines -Pattern 'severity=error|inline-\$\(if\)|result=FAIL'
    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = Get-FirstMeaningfulLine -Lines $ps51FormatGuard.Lines
    }

    Write-ResultAndExit -Step 'ps51-format-guard' -Status 'FAIL' -Reason $reason -OutputLines $ps51FormatGuard.Lines -ExitCode 1 -StartFilePath $startFilePath
}

$incrementalEncodingArgs = if ($DryRun.IsPresent) {
    @('-Mode', 'check', '-Policy', 'enforce')
}
else {
    @('-Mode', 'fix', '-Policy', 'enforce')
}

$incrementalEncoding = Invoke-PowerShellScriptStep -ScriptPath $incrementalEncodingScript -Arguments $incrementalEncodingArgs
if ($incrementalEncoding.ExitCode -ne 0) {
    $reason = Get-LastMatchingLine -Lines $incrementalEncoding.Lines -Pattern 'result=fail|non_compliant|remaining=|policy=enforce|fix_failed|noncompliant|lock=busy|mutex busy|lock_busy=true'
    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = Get-FirstMeaningfulLine -Lines $incrementalEncoding.Lines
    }

    Write-ResultAndExit -Step 'encoding-incremental-fix' -Status 'FAIL' -Reason $reason -OutputLines $incrementalEncoding.Lines -ExitCode 1 -StartFilePath $startFilePath
}

$encodingCheck = Invoke-PowerShellScriptStep -ScriptPath $encodingFormatScript -Arguments @('-Mode', 'check', '-Policy', 'enforce', '-Scope', 'tracked')
if ($encodingCheck.ExitCode -ne 0) {
    $encodingRepairLines = @()
    $encodingRepairLines += '--- encoding-format-check FAILED, attempting auto-repair ---'
    foreach ($line in @($encodingCheck.Lines)) {
        $encodingRepairLines += ('  ' + [string]$line)
    }

    $encodingFix = Invoke-PowerShellScriptStep -ScriptPath $encodingFormatScript -Arguments @('-Mode', 'fix', '-Policy', 'enforce', '-Scope', 'tracked')
    if ($encodingFix.ExitCode -ne 0) {
        $reason = Get-LastMatchingLine -Lines $encodingFix.Lines -Pattern 'result=fail|non_compliant|remaining=|policy=enforce|fix_failed|noncompliant|lock=busy|mutex busy|lock_busy=true'
        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = Get-FirstMeaningfulLine -Lines $encodingFix.Lines
        }

        $encodingRepairLines += '--- auto-repair FAILED ---'
        foreach ($line in @($encodingFix.Lines)) {
            $encodingRepairLines += ('  ' + [string]$line)
        }
        Write-ResultAndExit -Step 'encoding-format-fix' -Status 'FAIL' -Reason $reason -OutputLines $encodingRepairLines -ExitCode 1 -StartFilePath $startFilePath
    }

    $encodingRecheck = Invoke-PowerShellScriptStep -ScriptPath $encodingFormatScript -Arguments @('-Mode', 'check', '-Policy', 'enforce', '-Scope', 'tracked')
    if ($encodingRecheck.ExitCode -ne 0) {
        $reason = Get-LastMatchingLine -Lines $encodingRecheck.Lines -Pattern 'result=fail|non-compliant|encoding|eol|BOM|LF|lock=busy|mutex busy|lock_busy=true'
        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = Get-FirstMeaningfulLine -Lines $encodingRecheck.Lines
        }

        $encodingRepairLines += '--- recheck after fix STILL FAILED ---'
        foreach ($line in @($encodingRecheck.Lines)) {
            $encodingRepairLines += ('  ' + [string]$line)
        }
        Write-ResultAndExit -Step 'encoding-format-recheck' -Status 'FAIL' -Reason $reason -OutputLines $encodingRepairLines -ExitCode 1 -StartFilePath $startFilePath
    }

    $encodingRepairLines += '--- auto-repair OK, recheck PASSED ---'
    foreach ($line in @($encodingFix.Lines)) {
        $encodingRepairLines += ('  ' + [string]$line)
    }
}

$srcEncodingArgs = if ($DryRun.IsPresent) {
    @('-Mode', 'check', '-Policy', 'enforce')
}
else {
    @('-Mode', 'fix', '-Policy', 'enforce', '-IncludeUntracked')
}

$srcEncodingCheck = Invoke-PowerShellScriptStep -ScriptPath $srcEncodingScript -Arguments $srcEncodingArgs
if ($srcEncodingCheck.ExitCode -ne 0) {
    $reason = Get-LastMatchingLine -Lines $srcEncodingCheck.Lines -Pattern 'result=fail|non_compliant|remaining=|policy=enforce|fix_failed|noncompliant|lock=busy|mutex busy|lock_busy=true'
    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = Get-FirstMeaningfulLine -Lines $srcEncodingCheck.Lines
    }

    Write-ResultAndExit -Step 'src-encoding-fix' -Status 'FAIL' -Reason $reason -OutputLines $srcEncodingCheck.Lines -ExitCode 1 -StartFilePath $startFilePath
}

$precheckArgs = @(
    '-StartFile', $startFilePath,
    '-Operator', $Operator,
    '-ExpectedRunMode', $expectedRunMode,
    '-ExpectedEntryMode', $expectedEntryMode
)
if ($RequireCleanWorkspace.IsPresent) {
    $precheckArgs += '-RequireCleanWorkspace'
}
if ($DryRun.IsPresent) {
    $precheckArgs += '-DryRun'
}

$precheck = Invoke-PowerShellScriptStep -ScriptPath $precheckScript -Arguments $precheckArgs
if ($precheck.ExitCode -ne 0) {
    $reason = Get-LastMatchingLine -Lines $precheck.Lines -Pattern 'result=FAIL|reason='
    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = Get-FirstMeaningfulLine -Lines $precheck.Lines
    }

    Write-ResultAndExit -Step 'precheck-writeback' -Status 'FAIL' -Reason $reason -OutputLines $precheck.Lines -ExitCode 1 -StartFilePath $startFilePath
}

$incrementalEncodingMessage = if ($DryRun.IsPresent) { 'Incremental encoding check passed.' } else { 'Incremental encoding fix/check passed.' }
$srcCodeEncodingMessage = if ($DryRun.IsPresent) { 'Src code encoding check passed (UTF-8 + LF).' } else { 'Src code encoding fix/check passed (UTF-8 + LF).' }
$precheckModeMessage = if ($DryRun.IsPresent) { 'Precheck dry-run passed.' } else { 'Precheck writeback passed.' }

$successDetails = @($staticCheckMessages.ToArray()) + @(
    'Start-file field sync passed.',
    'Status-ticket mini regression passed.',
    $retryBudgetMiniRegressionSummary,
    'Route-guard smoke suite passed.',
    'PS5.1 inline-if format guard passed.',
    $incrementalEncodingMessage,
    'Tracked file encoding format check passed (UTF-8 with BOM + LF).',
    $srcCodeEncodingMessage,
    $precheckModeMessage
)

$successOutput = @(
    $startFileLines +
    $successDetails +
    $precheck.Lines
)

Write-ResultAndExit -Step 'launch-ready' -Status 'PASS' -Reason ("stage={0} launch conditions satisfied." -f $Stage) -OutputLines $successOutput -ExitCode 0 -StartFilePath $startFilePath
exit 0
