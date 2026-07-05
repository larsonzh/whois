param(
    [switch]$Reset,
    [switch]$ResetStateOnly,
    [string]$StateDir = "",
    [string]$TargetFile = "",
    [string]$TaskDefinitionFile = ""
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'AUTOPILOT-CODE-STEP-ROUNDS'

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

$schemaVersionRaw = '1'
$schemaMode = 'v1'
if ($taskDefinition -and ($taskDefinition.PSObject.Properties.Name -contains "schemaVersion")) {
    $schemaVersionRaw = [string]$taskDefinition.schemaVersion
}

$schemaVersionNormalized = $schemaVersionRaw.Trim().ToLowerInvariant()
if ($schemaVersionNormalized -eq 'vx-draft') {
    $schemaMode = 'vx-draft'
}
else {
    $schemaVersionNumeric = 0
    if (-not [int]::TryParse($schemaVersionNormalized, [ref]$schemaVersionNumeric) -or $schemaVersionNumeric -ne 1) {
        throw "[CODE-STEP] unsupported task definition schemaVersion=$schemaVersionRaw in $TaskDefinitionFile"
    }
}

if (-not $taskDefinition.rounds) {
    throw "[CODE-STEP] task definition missing rounds in $TaskDefinitionFile"
}

function Resolve-VxDefaultTargetFile {
    param(
        [object]$TaskDefinition,
        [string]$TaskDefinitionPath
    )

    if ($null -eq $TaskDefinition -or -not ($TaskDefinition.PSObject.Properties.Name -contains 'targetFiles')) {
        return ''
    }

    $targetFiles = @($TaskDefinition.targetFiles)
    if ($targetFiles.Count -lt 1) {
        return ''
    }

    $defaultTargetId = ''
    if ($TaskDefinition.PSObject.Properties.Name -contains 'defaultTarget') {
        $defaultTargetId = [string]$TaskDefinition.defaultTarget
    }

    $selectedTarget = $null
    if (-not [string]::IsNullOrWhiteSpace($defaultTargetId)) {
        foreach ($target in $targetFiles) {
            $targetId = ''
            if ($null -ne $target -and ($target.PSObject.Properties.Name -contains 'id')) {
                $targetId = [string]$target.id
            }

            if ($targetId.Trim().ToLowerInvariant() -eq $defaultTargetId.Trim().ToLowerInvariant()) {
                $selectedTarget = $target
                break
            }
        }

        if ($null -eq $selectedTarget) {
            throw "[CODE-STEP] defaultTarget '$defaultTargetId' not found in targetFiles: $TaskDefinitionPath"
        }
    }
    elseif ($targetFiles.Count -eq 1) {
        $selectedTarget = $targetFiles[0]
    }
    else {
        return ''
    }

    if ($null -eq $selectedTarget -or -not ($selectedTarget.PSObject.Properties.Name -contains 'file')) {
        throw "[CODE-STEP] targetFiles entry missing file for schema vx-draft: $TaskDefinitionPath"
    }

    $selectedFile = [string]$selectedTarget.file
    if ([string]::IsNullOrWhiteSpace($selectedFile)) {
        throw "[CODE-STEP] targetFiles entry has empty file for schema vx-draft: $TaskDefinitionPath"
    }

    return $selectedFile
}

if ([string]::IsNullOrWhiteSpace($StateDir)) {
    $StateDir = Join-Path $repoRoot "out\artifacts\autopilot_dev_recheck_8round\_code_step_state"
}
if ([string]::IsNullOrWhiteSpace($TargetFile)) {
    $taskTargetFile = ""
    if ($taskDefinition.PSObject.Properties.Name -contains "targetFile") {
        $taskTargetFile = [string]$taskDefinition.targetFile
    }

    if ([string]::IsNullOrWhiteSpace($taskTargetFile) -and $schemaMode -eq 'vx-draft') {
        $taskTargetFile = Resolve-VxDefaultTargetFile -TaskDefinition $taskDefinition -TaskDefinitionPath $TaskDefinitionFile
    }

    if ([string]::IsNullOrWhiteSpace($taskTargetFile)) {
        if ($schemaMode -eq 'vx-draft') {
            throw "[CODE-STEP] vx-draft task definition requires targetFile or resolvable targetFiles/defaultTarget: $TaskDefinitionFile"
        }

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

function Invoke-FileUtf8NoBomWrite {
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

function Restore-TargetFromHead {
    param(
        [string]$RepoRoot,
        [string]$TargetPath
    )

    $relativePath = Convert-ToRepoRelativePath -RepoRoot $RepoRoot -AbsolutePath $TargetPath
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        return [pscustomobject]@{
            Restored = $false
            Reason = "target-outside-repo"
            Detail = ""
        }
    }

    $headRaw = & git -c core.safecrlf=false -c core.autocrlf=false -C $RepoRoot show "HEAD:$relativePath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        $headLines = @()
        foreach ($item in $headRaw) {
            if ($item -is [System.Management.Automation.ErrorRecord]) {
                $headLines += $item.Exception.Message
            }
            else {
                $headLines += [string]$item
            }
        }

        return [pscustomobject]@{
            Restored = $false
            Reason = "git-show-failed"
            Detail = ($headLines -join '; ')
        }
    }

    $headTextLines = @()
    foreach ($item in $headRaw) {
        if ($item -is [System.Management.Automation.ErrorRecord]) {
            $headTextLines += $item.Exception.Message
        }
        else {
            $headTextLines += [string]$item
        }
    }

    $headText = $headTextLines -join "`n"
    Invoke-FileUtf8NoBomWrite -Path $TargetPath -Text $headText

    return [pscustomobject]@{
        Restored = $true
        Reason = "restored-from-head"
        Detail = ""
    }
}

function Invoke-RegexReplaceSingle {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Replacement,
        [string]$StepName
    )

    $rx = [regex]::new($Pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $matchCount = $rx.Matches($Text).Count
    if ($matchCount -ne 1) {
        if ($matchCount -eq 0) {
            $replacementLiteralHits = Get-LiteralOccurrenceCount -Text $Text -Literal $Replacement
            if ($replacementLiteralHits -gt 0) {
                throw "[CODE-STEP] step=$StepName expected exactly one match, actual=0 replacement_literal_hits=$replacementLiteralHits classification=ambiguous-already-present review-required"
            }
        }
        throw "[CODE-STEP] step=$StepName expected exactly one match, actual=$matchCount"
    }

    return $rx.Replace($Text, $Replacement, 1)
}

function Test-LiteralReplacementPresent {
    param(
        [string]$Text,
        [string]$Replacement
    )

    if ([string]::IsNullOrWhiteSpace($Text) -or [string]::IsNullOrWhiteSpace($Replacement)) {
        return $false
    }

    $normalizedText = (($Text -replace "`r`n", "`n") -replace "`r", "`n")
    $normalizedReplacement = (($Replacement -replace "`r`n", "`n") -replace "`r", "`n")
    return $normalizedText.Contains($normalizedReplacement)
}

function Get-LiteralOccurrenceCount {
    param(
        [string]$Text,
        [string]$Literal
    )

    if ([string]::IsNullOrWhiteSpace($Text) -or [string]::IsNullOrWhiteSpace($Literal)) {
        return 0
    }

    $normalizedText = (($Text -replace "`r`n", "`n") -replace "`r", "`n")
    $normalizedLiteral = (($Literal -replace "`r`n", "`n") -replace "`r", "`n")
    if ([string]::IsNullOrEmpty($normalizedLiteral)) {
        return 0
    }

    $count = 0
    $offset = 0
    while ($true) {
        $idx = $normalizedText.IndexOf($normalizedLiteral, $offset, [System.StringComparison]::Ordinal)
        if ($idx -lt 0) {
            break
        }

        $count++
        $offset = $idx + $normalizedLiteral.Length
        if ($offset -ge $normalizedText.Length) {
            break
        }
    }

    return $count
}

function Invoke-D1 {
    param([string]$Text)

    if ($Text.Contains('const char* input_label = "non-ip";')) {
        return $Text
    }
    if ($Text.Contains('wc_preclass_resolve_decision_fields(') -and
        $Text.Contains('decision_fields.input_label')) {
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

function Invoke-D2 {
    param([string]$Text)

    if ($Text.Contains('[PRECLASS-DECISION] query=%s input=%s start=%s action=%s action_src=%s') -and
        ($Text.Contains('[PRECLASS-DECISION] query=%s input=%s start=%s action=hint-disabled') -or
         $Text.Contains('decision_fields.action_source'))) {
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

function Invoke-D3 {
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

function Invoke-D4 {
    param([string]$Text)

    if ($Text.Contains('route-change-normalized')) {
        return $Text
    }
    if ($Text.Contains('wc_preclass_resolve_decision_fields(')) {
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
        "D1-input-label-stability" { return (Invoke-D1 -Text $Text) }
        "D2-decision-input-and-assert-friendly-fields" { return (Invoke-D2 -Text $Text) }
        "D3-unify-preclass-observation-fields" { return (Invoke-D3 -Text $Text) }
        "D4-route-change-normalization-guard" { return (Invoke-D4 -Text $Text) }
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

function Invoke-TaskDefinitionRound {
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
                $hasLiteralEscapedNewline = $replacement.Contains('\n')
                $hasActualNewline = $replacement.Contains("`n")
                if ($hasLiteralEscapedNewline -and -not $hasActualNewline) {
                    $likelyMultilineReplacement = (
                        $replacement.Contains('\n{') -or
                        $replacement.Contains('\n\t') -or
                        $replacement.Contains('}\n') -or
                        $replacement.Contains(';\n') -or
                        $replacement.Contains(')\n')
                    )
                    if ($likelyMultilineReplacement) {
                        $replacement = $replacement.Replace('\r\n', "`r`n")
                        $replacement = $replacement.Replace('\n', "`n")
                        $replacement = $replacement.Replace('\t', "`t")
                        Write-Information "[CODE-STEP-AUTOHEAL] rule=taskdef-replacement-double-escape round=$RoundTag index=$opIndex status=applied" -InformationAction Continue

                        $stillHasLiteralEscapedNewline = $replacement.Contains('\n')
                        $stillHasActualNewline = $replacement.Contains("`n")
                        if ($stillHasLiteralEscapedNewline -and -not $stillHasActualNewline) {
                            throw "[CODE-STEP] regex-patch replacement appears double-escaped after autoheal (literal \\n/\\t without actual newlines) round=$RoundTag index=$opIndex"
                        }
                    }
                }
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

function Invoke-AutoInjectForwardDecl {
    param(
        [string]$TargetFile,
        [object]$TaskDefinition,
        [string]$RoundTag,
        [string]$UpdatedText
    )

    $result = [pscustomobject]@{ Injected = $false; Needed = $false; Text = $UpdatedText; Ops = @(); Count = 0 }

    if ([string]::IsNullOrWhiteSpace($TargetFile)) { return $result }
    if (-not (Test-Path -LiteralPath $TargetFile)) { return $result }
    if ([string]::IsNullOrWhiteSpace($UpdatedText)) { return $result }

    # 1. Build map of static function definitions: name -> line number (0-based)
    $sourceLines = $UpdatedText -split '\r?\n'
    $defMap = @{}
    for ($i = 0; $i -lt $sourceLines.Count; $i++) {
        $line = $sourceLines[$i]
        if ($line -match '^\s*static\s+(const\s+)?\w[\w\s\*]*\s+(\w+)\s*\(') {
            $funcName = $matches[2]
            if (-not [string]::IsNullOrWhiteSpace($funcName) -and -not $defMap.ContainsKey($funcName)) {
                $defMap[$funcName] = $i
            }
        }
    }

    # 2. For each function, check if called before definition
    $needsFwd = @()
    foreach ($defName in $defMap.Keys) {
        $defLine = $defMap[$defName]
        if ($defLine -le 50) { continue }

        $callPattern = [regex]::new([regex]::Escape($defName) + '\s*\(', 'Compiled')
        $callMatchResults = $callPattern.Matches($UpdatedText)
        $firstCallLine = -1
        foreach ($m in $callMatchResults) {
            $charPos = $m.Index
            $lineNum = 0
            $accum = 0
            for ($j = 0; $j -lt $sourceLines.Count; $j++) {
                $accum += $sourceLines[$j].Length + 1
                if ($accum -gt $charPos) { $lineNum = $j; break }
            }
            if ($lineNum -lt $defLine) {
                if ($firstCallLine -eq -1 -or $lineNum -lt $firstCallLine) { $firstCallLine = $lineNum }
            }
        }

        if ($firstCallLine -ge 0) {
            $needsFwd += [pscustomobject]@{ Name = $defName; DefLine = $defLine; FirstCallLine = $firstCallLine }
        }
    }

    if ($needsFwd.Count -eq 0) { return $result }

    # 3. Filter to only functions introduced by this round's ops
    $roundTask = Get-RoundTaskDefinition -TaskDefinition $TaskDefinition -RoundTag $RoundTag
    if ($null -eq $roundTask) { return $result }

    $roundCallNames = @{}
    foreach ($op in $roundTask.operations) {
        $rep = [string]$op.replacement
        foreach ($item in $needsFwd) {
            if ($rep.Contains($item.Name + '(') -and -not $roundCallNames.ContainsKey($item.Name)) {
                $roundCallNames[$item.Name] = $item
            }
        }
    }

    if ($roundCallNames.Count -eq 0) { return $result }
    $result.Needed = $true

    # 4. For each function needing forward declaration, inject it
    $injectedOps = @()
    $text = $UpdatedText
    $injectCount = 0
    foreach ($funcName in $roundCallNames.Keys) {
        $info = $roundCallNames[$funcName]
        $firstLineText = $sourceLines[$info.FirstCallLine].Trim()
        if ([string]::IsNullOrWhiteSpace($firstLineText)) { continue }

        # Determine return type from definition
        $defLineIndex = $info.DefLine
        $defLineText = $sourceLines[$defLineIndex]
        $returnType = 'static const char*'
        if ($defLineText -match '^\s*(static\s+(const\s+)?[\w\s\*]+)\s+\w+\s*\(') {
            $returnType = $matches[1]
        }

        $fwdDecl = "$returnType $funcName(void);"

        # Find the line to match: the call line text
        $callLineText = $sourceLines[$info.FirstCallLine]
        # Escape for regex
        $escapedLine = [regex]::Escape($callLineText.Trim())
        $fwdPattern = "^\s*$escapedLine$"
        $fwdReplacement = "$fwdDecl`r`n$($callLineText -replace '^\s+', '')"

        try {
            $rx = [regex]::new($fwdPattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
            $matchCount = $rx.Matches($text).Count
            if ($matchCount -ge 1) {
                $text = $rx.Replace($text, $fwdReplacement, 1)
                $newOp = [ordered]@{ pattern = $fwdPattern; replacement = $fwdReplacement }
                $injectedOps += $newOp
                $injectCount++
                Write-Information "[CODE-STEP-AUTOINJECT] round=$RoundTag function=$funcName fwd_decl=$fwdDecl call_line=$($info.FirstCallLine) match_count=$matchCount" -InformationAction Continue
            }
            else {
                Write-Warning "[CODE-STEP-AUTOINJECT] no_match for $funcName at line $($info.FirstCallLine); anchor=$escapedLine"
            }
        }
        catch {
            Write-Warning "[CODE-STEP-AUTOINJECT] error for $funcName : $($_.Exception.Message)"
        }
    }

    if ($injectCount -eq 0) { return $result }

    # 5. Persist new ops to task definition JSON
    try {
        $jsonText = Get-Content -LiteralPath $TaskDefinitionFile -Raw
        if (-not [string]::IsNullOrWhiteSpace($jsonText)) {
            $taskDefObj = $jsonText | ConvertFrom-Json
            $targetRound = Get-RoundTaskDefinition -TaskDefinition $taskDefObj -RoundTag $RoundTag
            if ($null -ne $targetRound) {
                foreach ($newOp in $injectedOps) {
                    $targetRound.operations += $newOp
                }
                $taskDefObj | ConvertTo-Json -Depth 8 | Out-File -FilePath $TaskDefinitionFile -Encoding utf8
            }
        }
    }
    catch {
        Write-Warning "[CODE-STEP-AUTOINJECT] persist_error: $($_.Exception.Message)"
    }

    $result.Injected = $true
    $result.Text = $text
    $result.Ops = $injectedOps
    $result.Count = $injectCount
    return $result
}

if ($Reset) {
    $restored = $false
    $restoredFromHead = $false
    $restorePolicy = "skipped-no-baseline"
    $baselineMatchesHead = $false
    $restoreDetail = "none"

    if ($ResetStateOnly.IsPresent) {
        $restorePolicy = "state-only-no-source-restore"
        $restoreDetail = "state-only"
    }
    else {
        if ((Test-Path -LiteralPath $baselineFile) -and (Test-Path -LiteralPath $TargetFile)) {
            $baselineMatchesHead = Test-BaselineMatchesHead -RepoRoot $repoRoot -BaselinePath $baselineFile -TargetPath $TargetFile
        }

        if ((Test-Path -LiteralPath $baselineFile) -and (Test-Path -LiteralPath $TargetFile) -and $baselineMatchesHead) {
            Copy-Item -LiteralPath $baselineFile -Destination $TargetFile -Force
            $restored = $true
            $restorePolicy = "restored-baseline-matches-head"
        }
        elseif ((Test-Path -LiteralPath $baselineFile) -and (Test-Path -LiteralPath $TargetFile)) {
            $headRestore = Restore-TargetFromHead -RepoRoot $repoRoot -TargetPath $TargetFile
            if ($headRestore.Restored) {
                $restored = $true
                $restoredFromHead = $true
                $restorePolicy = "restored-head-due-baseline-mismatch"
            }
            else {
                $restorePolicy = "skipped-baseline-mismatch-head"
                if (-not [string]::IsNullOrWhiteSpace($headRestore.Detail)) {
                    $restoreDetail = $headRestore.Detail
                }
                elseif (-not [string]::IsNullOrWhiteSpace($headRestore.Reason)) {
                    $restoreDetail = $headRestore.Reason
                }
            }
        }

        $restoreDetail = ($restoreDetail -replace '\s+', '_')
    }

    if (Test-Path -LiteralPath $StateDir) {
        Remove-Item -LiteralPath $StateDir -Recurse -Force
    }
    $resetMode = if ($ResetStateOnly.IsPresent) { "state-only" } else { "restore-source" }
    Write-Output "[CODE-STEP] state_reset=true state_dir=$StateDir reset_mode=$resetMode restored_target=$restored restored_from_head=$restoredFromHead baseline_matches_head=$baselineMatchesHead restore_policy=$restorePolicy restore_detail=$restoreDetail task_definition=$TaskDefinitionFile"
    exit 0
}

try {
    if (-not (Test-Path -LiteralPath $TargetFile)) {
        throw "[CODE-STEP] target file not found: $TargetFile"
    }

    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

    if (-not (Test-Path -LiteralPath $baselineFile)) {
        $baselineText = Get-Content -LiteralPath $TargetFile -Raw
        Invoke-FileUtf8NoBomWrite -Path $baselineFile -Text $baselineText
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
        $updatedOutputs = @(Invoke-TaskDefinitionRound -RoundTask $roundTask -RoundTag $roundTag -Text $text)
        if ($updatedOutputs.Count -ne 1 -or -not ($updatedOutputs[0] -is [string])) {
            throw "[CODE-STEP] task round produced unexpected output count=$($updatedOutputs.Count) round=$roundTag; refusing to write target file"
        }

        $updated = [string]$updatedOutputs[0]

        if ($updated -ne $text) {
            # Auto-inject forward declarations for literal functions
            # called before their definition (conflicting types in strict builds)
            $autoInjectResult = Invoke-AutoInjectForwardDecl -TargetFile $TargetFile -TaskDefinition $taskDefinition -RoundTag $roundTag -UpdatedText $updated

            if ($autoInjectResult.Injected) {
                $updated = $autoInjectResult.Text
                Invoke-FileUtf8NoBomWrite -Path $TargetFile -Text $updated
                Write-Output "[CODE-STEP-AUTOINJECT] round=$roundTag injected=$($autoInjectResult.Count) functions=$($autoInjectResult.Ops.ForEach({ '''' + $_.pattern.Substring(0, [math]::Min(40, $_.pattern.Length)) + '''' }) -join ',')"
            }
            elseif ($autoInjectResult.Needed) {
                throw "[CODE-STEP] auto-inject failed for round=${roundTag}: forward declarations needed but could not be applied; aborting to avoid certain compile failure"
            }

            Invoke-FileUtf8NoBomWrite -Path $TargetFile -Text $updated
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
}
catch {
    Write-Output "[CODE-STEP] fatal_error=$($_.Exception.Message.Replace("`r",'').Replace("`n",' '))"
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason ("code-step fatal error: {0}" -f $_.Exception.Message) -ExitCode 1
}
