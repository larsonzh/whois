param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [string]$Operator = 'Copilot',
    [switch]$RequireCleanWorkspace,
    [switch]$DryRun,
    [switch]$DetailedOutput,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoPath {
    param(
        [string]$RepoRoot,
        [string]$Path,
        [bool]$MustExist = $true
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    $resolved = if ([System.IO.Path]::IsPathRooted($Path)) {
        [System.IO.Path]::GetFullPath($Path)
    }
    else {
        [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
    }

    if ($MustExist -and -not (Test-Path -LiteralPath $resolved)) {
        throw ('path not found: {0}' -f $resolved)
    }

    return $resolved
}

function Read-KeyValueFile {
    param([string]$Path)

    $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
    $map = [ordered]@{}
    $lineNo = 0
    $seen = @{}

    foreach ($line in $lines) {
        $lineNo++
        if ($line -notmatch '^([^=]+)=(.*)$') {
            continue
        }

        $key = $Matches[1].Trim()
        if ($seen.ContainsKey($key)) {
            throw ('duplicate key in start-file: {0} line1={1} line2={2}' -f $key, [int]$seen[$key], $lineNo)
        }

        $seen[$key] = $lineNo
        $map[$key] = $Matches[2]
    }

    return $map
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

function New-ResultObject {
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

function Emit-ResultAndExit {
    param(
        [string]$Step,
        [string]$Status,
        [string]$Reason,
        [string[]]$OutputLines,
        [int]$ExitCode,
        [string]$StartFilePath
    )

    $result = New-ResultObject -Step $Step -Status $Status -Reason $Reason -OutputLines $OutputLines -StartFilePath $StartFilePath
    if ($AsJson.IsPresent) {
        $result | ConvertTo-Json -Depth 6
    }
    else {
        $displayLines = Get-CondensedOutputLines -Lines $OutputLines -Detailed:$DetailedOutput.IsPresent
        Write-Output ('[AB-LAUNCH-READY] start_file={0}' -f $StartFilePath)
        Write-Output ('[AB-LAUNCH-READY] result={0} step={1} reason={2}' -f $Status, $Step, $Reason)
        foreach ($line in @($displayLines)) {
            Write-Output ('[AB-LAUNCH-READY] detail={0}' -f $line)
        }
        Write-Output ('[AB-LAUNCH-READY] final_result={0} step={1} reason={2}' -f $Status, $Step, $Reason)
        Write-Output ('AB_LAUNCH_READY_RESULT={0}' -f $Status)
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

    $matches = @($Lines | Where-Object { ([string]$_) -match $Pattern })
    if ($matches.Count -gt 0) {
        return [string]$matches[$matches.Count - 1]
    }

    return ''
}

function Get-CondensedOutputLines {
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
        'status=FAIL',
        'severity=error',
        'severity=warn',
        'warning_gate=fail',
        'summary errors=',
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
$startFilePath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $StartFile))
$startSettings = $null

try {
    $startFilePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $StartFile -MustExist $true
    $startSettings = Read-KeyValueFile -Path $startFilePath
}
catch {
    Emit-ResultAndExit -Step 'start-file' -Status 'FAIL' -Reason $_.Exception.Message -OutputLines @() -ExitCode 1 -StartFilePath $startFilePath
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
    Emit-ResultAndExit -Step 'start-file' -Status 'FAIL' -Reason ('missing required key(s): {0}' -f ($missingKeys -join ',')) -OutputLines @() -ExitCode 1 -StartFilePath $startFilePath
}

$aTaskDefinition = [string]$startSettings.A_TASK_DEFINITION
$bTaskDefinition = [string]$startSettings.B_TASK_DEFINITION
$taskStaticPrecheckPolicy = [string]$startSettings.TASK_STATIC_PRECHECK_POLICY
$taskStaticFailOnWarnings = Convert-ToBooleanSetting -Value ([string]$startSettings.TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS) -Default $true
$expectedRunMode = [string]$startSettings.RUN_MODE
$expectedEntryMode = [string]$startSettings.ENTRY_MODE

try {
    $resolvedATask = Resolve-RepoPath -RepoRoot $repoRoot -Path $aTaskDefinition -MustExist $true
    $resolvedBTask = Resolve-RepoPath -RepoRoot $repoRoot -Path $bTaskDefinition -MustExist $true
}
catch {
    Emit-ResultAndExit -Step 'start-file' -Status 'FAIL' -Reason $_.Exception.Message -OutputLines @(
        ('A_TASK_DEFINITION={0}' -f $aTaskDefinition),
        ('B_TASK_DEFINITION={0}' -f $bTaskDefinition)
    ) -ExitCode 1 -StartFilePath $startFilePath
}

$startFileLines = @(
    ('A_TASK_DEFINITION={0}' -f $resolvedATask),
    ('B_TASK_DEFINITION={0}' -f $resolvedBTask),
    ('RUN_MODE={0}' -f $expectedRunMode),
    ('ENTRY_MODE={0}' -f $expectedEntryMode),
    ('TASK_STATIC_PRECHECK_POLICY={0}' -f $taskStaticPrecheckPolicy),
    ('TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS={0}' -f $taskStaticFailOnWarnings)
)

$staticCheckScript = Resolve-RepoPath -RepoRoot $repoRoot -Path 'tools/test/check_task_definition_static.ps1' -MustExist $true
$fieldSyncScript = Resolve-RepoPath -RepoRoot $repoRoot -Path 'tools/test/check_unattended_start_field_sync.ps1' -MustExist $true
$precheckScript = Resolve-RepoPath -RepoRoot $repoRoot -Path 'tools/test/precheck_unattended_ab_start_file.ps1' -MustExist $true

$aArgs = @(
    '-TaskDefinitionFile', $resolvedATask,
    '-RepoRoot', $repoRoot,
    '-Policy', $taskStaticPrecheckPolicy
)
if ($taskStaticFailOnWarnings) {
    $aArgs += '-FailOnWarnings'
}

$aCheck = Invoke-PowerShellScriptStep -ScriptPath $staticCheckScript -Arguments $aArgs
if ($aCheck.ExitCode -ne 0) {
    $reason = Get-LastMatchingLine -Lines $aCheck.Lines -Pattern 'severity=error|warning_gate=fail|\[TASK-STATIC-CHECK\] invalid|\[TASK-STATIC-CHECK\] task definition|\[TASK-STATIC-CHECK\] target file'
    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = Get-FirstMeaningfulLine -Lines $aCheck.Lines
    }

    Emit-ResultAndExit -Step 'task-static-check-a' -Status 'FAIL' -Reason $reason -OutputLines $aCheck.Lines -ExitCode 1 -StartFilePath $startFilePath
}

$bArgs = @(
    '-TaskDefinitionFile', $resolvedBTask,
    '-RepoRoot', $repoRoot,
    '-Policy', $taskStaticPrecheckPolicy
)
if ($taskStaticFailOnWarnings) {
    $bArgs += '-FailOnWarnings'
}

$bCheck = Invoke-PowerShellScriptStep -ScriptPath $staticCheckScript -Arguments $bArgs
if ($bCheck.ExitCode -ne 0) {
    $reason = Get-LastMatchingLine -Lines $bCheck.Lines -Pattern 'severity=error|warning_gate=fail|\[TASK-STATIC-CHECK\] invalid|\[TASK-STATIC-CHECK\] task definition|\[TASK-STATIC-CHECK\] target file'
    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = Get-FirstMeaningfulLine -Lines $bCheck.Lines
    }

    Emit-ResultAndExit -Step 'task-static-check-b' -Status 'FAIL' -Reason $reason -OutputLines $bCheck.Lines -ExitCode 1 -StartFilePath $startFilePath
}

$fieldSync = Invoke-PowerShellScriptStep -ScriptPath $fieldSyncScript -Arguments @()
if ($fieldSync.ExitCode -ne 0) {
    $reason = Get-LastMatchingLine -Lines $fieldSync.Lines -Pattern 'missing_|result=fail|entry_script_a|template_'
    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = Get-FirstMeaningfulLine -Lines $fieldSync.Lines
    }

    Emit-ResultAndExit -Step 'start-field-sync' -Status 'FAIL' -Reason $reason -OutputLines $fieldSync.Lines -ExitCode 1 -StartFilePath $startFilePath
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

    Emit-ResultAndExit -Step 'precheck-writeback' -Status 'FAIL' -Reason $reason -OutputLines $precheck.Lines -ExitCode 1 -StartFilePath $startFilePath
}

$successOutput = @(
    $startFileLines +
    @(
        ('A task static check passed: {0}' -f $resolvedATask),
        ('B task static check passed: {0}' -f $resolvedBTask),
        'Start-file field sync passed.',
        $(if ($DryRun.IsPresent) { 'Precheck dry-run passed.' } else { 'Precheck writeback passed.' })
    ) +
    $precheck.Lines
)

Emit-ResultAndExit -Step 'launch-ready' -Status 'PASS' -Reason 'A/B tasks meet start conditions.' -OutputLines $successOutput -ExitCode 0 -StartFilePath $startFilePath
