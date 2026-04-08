param(
    [switch]$Reset,
    [string]$StateDir = "",
    [string]$TargetFile = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

if ([string]::IsNullOrWhiteSpace($StateDir)) {
    $StateDir = Join-Path $repoRoot "out\artifacts\autopilot_dev_recheck_8round\_code_step_state"
}
if ([string]::IsNullOrWhiteSpace($TargetFile)) {
    $TargetFile = Join-Path $repoRoot "src\core\whois_query_exec.c"
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

if ($Reset) {
    $restored = $false
    if ((Test-Path -LiteralPath $baselineFile) -and (Test-Path -LiteralPath $TargetFile)) {
        Copy-Item -LiteralPath $baselineFile -Destination $TargetFile -Force
        $restored = $true
    }

    if (Test-Path -LiteralPath $StateDir) {
        Remove-Item -LiteralPath $StateDir -Recurse -Force
    }
    Write-Output "[CODE-STEP] state_reset=true state_dir=$StateDir restored_target=$restored"
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
    $text = Get-Content -LiteralPath $TargetFile -Raw
    $updated = switch ($roundTag) {
        "D1" { Apply-D1 -Text $text }
        "D2" { Apply-D2 -Text $text }
        "D3" { Apply-D3 -Text $text }
        "D4" { Apply-D4 -Text $text }
        default { $text }
    }

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
