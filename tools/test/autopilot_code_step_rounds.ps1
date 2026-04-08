param(
    [switch]$Reset,
    [string]$StateDir = "",
    [string]$TargetFile = "",
    [string]$TaskDefinitionFile = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

if ([string]::IsNullOrWhiteSpace($TaskDefinitionFile)) {
    $TaskDefinitionFile = Join-Path $repoRoot "testdata\autopilot_code_step_tasks_default.json"
}
elseif (-not [System.IO.Path]::IsPathRooted($TaskDefinitionFile)) {
    $TaskDefinitionFile = Join-Path $repoRoot $TaskDefinitionFile
}

if (-not (Test-Path -LiteralPath $TaskDefinitionFile)) {
    throw "[CODE-STEP] task definition file not found: $TaskDefinitionFile"
}

try {
    $taskDefinition = (Get-Content -LiteralPath $TaskDefinitionFile -Raw) | ConvertFrom-Json
}
catch {
    throw "[CODE-STEP] invalid task definition json: $TaskDefinitionFile"
}

$schemaVersion = 0
if ($taskDefinition -and ($taskDefinition.PSObject.Properties.Name -contains "schemaVersion")) {
    $schemaVersion = [int]$taskDefinition.schemaVersion
}
if ($schemaVersion -ne 1) {
    throw "[CODE-STEP] unsupported task definition schemaVersion=$schemaVersion in $TaskDefinitionFile"
}
if (-not $taskDefinition.rounds) {
    throw "[CODE-STEP] task definition missing rounds in $TaskDefinitionFile"
}

if ([string]::IsNullOrWhiteSpace($StateDir)) {
    $StateDir = Join-Path $repoRoot "out\artifacts\autopilot_dev_recheck_8round\_code_step_state"
}
if ([string]::IsNullOrWhiteSpace($TargetFile)) {
    $taskTargetFile = ""
    if ($taskDefinition.PSObject.Properties.Name -contains "targetFile") {
        $taskTargetFile = [string]$taskDefinition.targetFile
    }
    if ([string]::IsNullOrWhiteSpace($taskTargetFile)) {
        $TargetFile = Join-Path $repoRoot "src\core\whois_query_exec.c"
    }
    else {
        if ([System.IO.Path]::IsPathRooted($taskTargetFile)) {
            $TargetFile = $taskTargetFile
        }
        else {
            $TargetFile = Join-Path $repoRoot $taskTargetFile
        }
    }
}
elseif (-not [System.IO.Path]::IsPathRooted($TargetFile)) {
    $TargetFile = Join-Path $repoRoot $TargetFile
}

$stateFile = Join-Path $StateDir "state.json"
$baselineFile = Join-Path $StateDir "target_baseline.c"

function Set-FileUtf8NoBom {
    param(
        [string]$Path,
        [string]$Text
    )

    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Get-NormalizedContentHash {
    param(
        [string]$Text
    )

    $normalized = ($Text -replace "`r`n", "`n") -replace "`r", "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
        $hashBytes = $sha.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hashBytes)).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Convert-ToRepoRelativePath {
    param(
        [string]$RepoRoot,
        [string]$AbsolutePath
    )

    $repoFull = [System.IO.Path]::GetFullPath($RepoRoot)
    $pathFull = [System.IO.Path]::GetFullPath($AbsolutePath)
    if (-not $pathFull.StartsWith($repoFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }

    $rel = $pathFull.Substring($repoFull.Length).TrimStart([char]'\', [char]'/')
    if ([string]::IsNullOrWhiteSpace($rel)) {
        return $null
    }

    return ($rel -replace '\\', '/')
}

function Test-BaselineMatchesHead {
    param(
        [string]$RepoRoot,
        [string]$BaselinePath,
        [string]$TargetPath
    )

    if (-not (Test-Path -LiteralPath $BaselinePath) -or -not (Test-Path -LiteralPath $TargetPath)) {
        return $false
    }

    $relativePath = Convert-ToRepoRelativePath -RepoRoot $RepoRoot -AbsolutePath $TargetPath
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        return $false
    }

    $baselineText = Get-Content -LiteralPath $BaselinePath -Raw
    $baselineHash = Get-NormalizedContentHash -Text $baselineText

    $headRaw = & git -c core.safecrlf=false -c core.autocrlf=false -C $RepoRoot show "HEAD:$relativePath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    $headLines = @()
    foreach ($item in $headRaw) {
        if ($item -is [System.Management.Automation.ErrorRecord]) {
            $headLines += $item.Exception.Message
        }
        else {
            $headLines += [string]$item
        }
    }
    $headText = $headLines -join "`n"
    $headHash = Get-NormalizedContentHash -Text $headText

    return $baselineHash -eq $headHash
}

function Invoke-RegexReplaceSingle {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Replacement,
        [string]$StepName
    )

    $rx = [regex]::new($Pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $matches = $rx.Matches($Text).Count
    if ($matches -ne 1) {
        throw "[CODE-STEP] step=$StepName expected exactly one match, actual=$matches"
    }

    return $rx.Replace($Text, $Replacement, 1)
}

function Apply-D1 {
    param([string]$Text)

    if ($Text.Contains('const char* input_label = "non-ip";')) {
        return $Text
    }

    $step = "D1-input-label-stability"
    $text1 = Invoke-RegexReplaceSingle -Text $Text -Pattern 'if \(normalized && wc_client_is_valid_ip_address\(normalized\)\)\r?\n\t\tmatch_layer = query_is_cidr \? "cidr" : "ip";\r?\n' -Replacement @"
if (normalized && wc_client_is_valid_ip_address(normalized))
		match_layer = query_is_cidr ? "cidr" : "ip";

	const char* input_label = "non-ip";
	if (strcmp(match_layer, "cidr") == 0)
		input_label = "cidr";
	else if (strcmp(match_layer, "ip") == 0)
		input_label = "ip";
"@ -StepName $step

    return Invoke-RegexReplaceSingle -Text $text1 -Pattern '\t\tquery_is_cidr \? "cidr" : "ip",' -Replacement "`t`tinput_label," -StepName $step
}

function Apply-D2 {
    param([string]$Text)

    if ($Text.Contains('[PRECLASS-DECISION] query=%s input=%s start=%s action=hint-disabled') -and
        $Text.Contains('[PRECLASS-DECISION] query=%s input=%s start=%s action=%s action_src=%s')) {
        return $Text
    }

    $step = "D2-decision-input-and-assert-friendly-fields"
    $text1 = Invoke-RegexReplaceSingle -Text $Text -Pattern '"\[PRECLASS-DECISION\] query=%s start=%s action=hint-disabled' -Replacement '"[PRECLASS-DECISION] query=%s input=%s start=%s action=hint-disabled' -StepName $step
    $text2 = Invoke-RegexReplaceSingle -Text $text1 -Pattern 'query,\r?\n[ \t]*effective_start,\r?\n[ \t]*action_source,' -Replacement @"
query,
			input_label,
			effective_start,
			action_source,
"@ -StepName $step
    $text3 = Invoke-RegexReplaceSingle -Text $text2 -Pattern '"\[PRECLASS-DECISION\] query=%s start=%s action=%s action_src=%s' -Replacement '"[PRECLASS-DECISION] query=%s input=%s start=%s action=%s action_src=%s' -StepName $step

    return Invoke-RegexReplaceSingle -Text $text3 -Pattern 'query,\r?\n[ \t]*effective_start,\r?\n[ \t]*action,' -Replacement @"
query,
		input_label,
		effective_start,
		action,
"@ -StepName $step
}

function Apply-D3 {
    param([string]$Text)

    if ($Text.Contains('fallback=%s\\n",')) {
        $Text = $Text.Replace('fallback=%s\\n",', 'fallback=%s\n",')
    }

    if ($Text.Contains('host_mode=%s action=%s action_src=%s route_change=%d match_layer=%s fallback=%s')) {
        return $Text
    }

    $step = "D3-unify-preclass-observation-fields"
    $text1 = Invoke-RegexReplaceSingle -Text $Text -Pattern '"\[PRECLASS\] query=%s input=%s family=%s class=%s rir=%s reason=%s reason_code=%s reason_key=%s confidence=%s confidence_code=%s confidence_rank=%d dict_version=%s host_mode=%s\\n",' -Replacement '"[PRECLASS] query=%s input=%s family=%s class=%s rir=%s reason=%s reason_code=%s reason_key=%s confidence=%s confidence_code=%s confidence_rank=%d dict_version=%s host_mode=%s action=%s action_src=%s route_change=%d match_layer=%s fallback=%s\n",' -StepName $step

    return Invoke-RegexReplaceSingle -Text $text1 -Pattern '\t\tdict_version,\r?\n\t\thost_mode\);' -Replacement @"
		dict_version,
		host_mode,
		action,
		action_source,
		route_change,
		match_layer,
		fallback_reason);
"@ -StepName $step
}

function Apply-D4 {
    param([string]$Text)

    if ($Text.Contains('route-change-normalized')) {
        return $Text
    }

    $step = "D4-route-change-normalization-guard"
    return Invoke-RegexReplaceSingle -Text $Text -Pattern 'if \(route_change != 0\)\r?\n\t\troute_change = 1;' -Replacement @"
if (route_change != 0)
		route_change = 1;
	if (route_change != 0 &&
		strcmp(action, "hint-applied") != 0 &&
		strcmp(action, "preclass-short-circuit-unknown") != 0 &&
		strcmp(action, "step47-short-circuit-unknown") != 0) {
		route_change = 0;
		if (strcmp(fallback_reason, "none") == 0)
			fallback_reason = "route-change-normalized";
	}
"@ -StepName $step
}

function Get-LegacyBuiltinName {
    param([string]$RoundTag)

    switch ($RoundTag) {
        "D1" { return "D1-input-label-stability" }
        "D2" { return "D2-decision-input-and-assert-friendly-fields" }
        "D3" { return "D3-unify-preclass-observation-fields" }
        "D4" { return "D4-route-change-normalization-guard" }
        default { return "" }
    }
}

function Invoke-BuiltinRoundTask {
    param(
        [string]$BuiltinName,
        [string]$Text
    )

    switch ($BuiltinName) {
        "D1-input-label-stability" { return (Apply-D1 -Text $Text) }
        "D2-decision-input-and-assert-friendly-fields" { return (Apply-D2 -Text $Text) }
        "D3-unify-preclass-observation-fields" { return (Apply-D3 -Text $Text) }
        "D4-route-change-normalization-guard" { return (Apply-D4 -Text $Text) }
        default {
            throw "[CODE-STEP] unknown builtin task: $BuiltinName"
        }
    }
}

function Get-RoundTaskDefinition {
    param(
        [object]$TaskDefinition,
        [string]$RoundTag
    )

    if (-not $TaskDefinition -or -not $TaskDefinition.rounds) {
        return $null
    }

    foreach ($prop in $TaskDefinition.rounds.PSObject.Properties) {
        if ($prop.Name -eq $RoundTag) {
            return $prop.Value
        }
    }

    return $null
}

function Apply-TaskDefinitionRound {
    param(
        [object]$RoundTask,
        [string]$RoundTag,
        [string]$Text
    )

    if (-not $RoundTask) {
        $fallbackBuiltin = Get-LegacyBuiltinName -RoundTag $RoundTag
        if ([string]::IsNullOrWhiteSpace($fallbackBuiltin)) {
            return $Text
        }
        return Invoke-BuiltinRoundTask -BuiltinName $fallbackBuiltin -Text $Text
    }

    $taskType = "builtin"
    if ($RoundTask.PSObject.Properties.Name -contains "type") {
        $candidateType = [string]$RoundTask.type
        if (-not [string]::IsNullOrWhiteSpace($candidateType)) {
            $taskType = $candidateType.Trim().ToLowerInvariant()
        }
    }

    switch ($taskType) {
        "noop" {
            return $Text
        }
        "builtin" {
            $builtinName = ""
            if ($RoundTask.PSObject.Properties.Name -contains "builtin") {
                $builtinName = [string]$RoundTask.builtin
            }
            if ([string]::IsNullOrWhiteSpace($builtinName)) {
                $builtinName = Get-LegacyBuiltinName -RoundTag $RoundTag
            }
            if ([string]::IsNullOrWhiteSpace($builtinName)) {
                throw "[CODE-STEP] builtin task missing name for round=$RoundTag"
            }
            return Invoke-BuiltinRoundTask -BuiltinName $builtinName -Text $Text
        }
        "regex-patch" {
            $markers = @()
            if ($RoundTask.PSObject.Properties.Name -contains "idempotentContains") {
                $rawMarkers = $RoundTask.idempotentContains
                if ($rawMarkers -is [string]) {
                    $markers = @($rawMarkers)
                }
                else {
                    $markers = @($rawMarkers)
                }
            }

            if ($markers.Count -gt 0) {
                $allPresent = $true
                foreach ($marker in $markers) {
                    $markerText = [string]$marker
                    if ([string]::IsNullOrWhiteSpace($markerText)) {
                        continue
                    }
                    if (-not $Text.Contains($markerText)) {
                        $allPresent = $false
                        break
                    }
                }
                if ($allPresent) {
                    return $Text
                }
            }

            $operations = @()
            if ($RoundTask.PSObject.Properties.Name -contains "operations") {
                $operations = @($RoundTask.operations)
            }
            if ($operations.Count -eq 0) {
                throw "[CODE-STEP] regex-patch task requires operations for round=$RoundTag"
            }

            $updatedText = $Text
            $opIndex = 0
            foreach ($op in $operations) {
                $opIndex++
                $pattern = [string]$op.pattern
                if ([string]::IsNullOrWhiteSpace($pattern)) {
                    throw "[CODE-STEP] regex-patch operation missing pattern round=$RoundTag index=$opIndex"
                }
                $replacement = [string]$op.replacement
                $stepName = "$RoundTag-regex-patch-$opIndex"
                $updatedText = Invoke-RegexReplaceSingle -Text $updatedText -Pattern $pattern -Replacement $replacement -StepName $stepName
            }

            return $updatedText
        }
        default {
            throw "[CODE-STEP] unsupported task type '$taskType' for round=$RoundTag"
        }
    }
}

if ($Reset) {
    $restored = $false
    $restorePolicy = "skipped-no-baseline"
    $baselineMatchesHead = $false

    if ((Test-Path -LiteralPath $baselineFile) -and (Test-Path -LiteralPath $TargetFile)) {
        $baselineMatchesHead = Test-BaselineMatchesHead -RepoRoot $repoRoot -BaselinePath $baselineFile -TargetPath $TargetFile
    }

    if ((Test-Path -LiteralPath $baselineFile) -and (Test-Path -LiteralPath $TargetFile) -and $baselineMatchesHead) {
        Copy-Item -LiteralPath $baselineFile -Destination $TargetFile -Force
        $restored = $true
        $restorePolicy = "restored-baseline-matches-head"
    }
    elseif ((Test-Path -LiteralPath $baselineFile) -and (Test-Path -LiteralPath $TargetFile)) {
        $restorePolicy = "skipped-baseline-mismatch-head"
    }

    if (Test-Path -LiteralPath $StateDir) {
        Remove-Item -LiteralPath $StateDir -Recurse -Force
    }
    Write-Output "[CODE-STEP] state_reset=true state_dir=$StateDir restored_target=$restored baseline_matches_head=$baselineMatchesHead restore_policy=$restorePolicy task_definition=$TaskDefinitionFile"
    exit 0
}

if (-not (Test-Path -LiteralPath $TargetFile)) {
    throw "[CODE-STEP] target file not found: $TargetFile"
}

New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

if (-not (Test-Path -LiteralPath $baselineFile)) {
    $baselineText = Get-Content -LiteralPath $TargetFile -Raw
    Set-FileUtf8NoBom -Path $baselineFile -Text $baselineText
}

$state = [pscustomobject]@{
    invocationCount = 0
    lastRound = ""
    lastTimestamp = ""
}

if (Test-Path -LiteralPath $stateFile) {
    try {
        $rawState = Get-Content -LiteralPath $stateFile -Raw
        if (-not [string]::IsNullOrWhiteSpace($rawState)) {
            $state = $rawState | ConvertFrom-Json
        }
    }
    catch {
        Write-Warning "[CODE-STEP] invalid state file, resetting: $stateFile"
    }
}

$next = [int]$state.invocationCount + 1
$roundTag = switch ($next) {
    1 { "D1" }
    2 { "D2" }
    3 { "D3" }
    4 { "D4" }
    default { "VERIFY_OR_EXTRA" }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

if ($next -le 4) {
    Write-Output "[CODE-STEP] task_definition=$TaskDefinitionFile round=$roundTag"
    $text = Get-Content -LiteralPath $TargetFile -Raw
    $roundTask = Get-RoundTaskDefinition -TaskDefinition $taskDefinition -RoundTag $roundTag
    $updated = Apply-TaskDefinitionRound -RoundTask $roundTask -RoundTag $roundTag -Text $text

    if ($updated -ne $text) {
        Set-FileUtf8NoBom -Path $TargetFile -Text $updated
        Write-Output "[CODE-STEP] round=$roundTag action=applied target=$TargetFile timestamp=$timestamp"
    }
    else {
        Write-Output "[CODE-STEP] round=$roundTag action=already-applied target=$TargetFile timestamp=$timestamp"
    }
}
else {
    Write-Output "[CODE-STEP] round=$roundTag action=no-op reason=dev-rounds-completed"
}

$stateOut = [pscustomobject]@{
    invocationCount = $next
    lastRound = $roundTag
    lastTimestamp = $timestamp
}

$stateOut | ConvertTo-Json | Out-File -FilePath $stateFile -Encoding utf8
