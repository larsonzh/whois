param(
    [switch]$DryRun,
    [switch]$SkipUpdate,
    [switch]$SimulateNoChange,
    [ValidateSet('all', 'core', 'minimal', 'none')][string]$GateProfile = 'core',
    [string[]]$Gates = @(),
    [string]$BinaryPath = '',
    [string]$OutputDirectory = '',
    [string]$ReviewRecordPath = '',
    [switch]$GatesOnNoChange
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:UnhandledExitTag = 'UPDATE-AND-VERIFY-PRECLASS-TABLE'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$updateScript = Join-Path $PSScriptRoot 'update_iana_registry_snapshots.ps1'
$genScript = Join-Path $PSScriptRoot 'gen_preclass_table.py'
$generatedManifestRel = 'out\generated\preclass_manifest.json'
$generatedManifestPath = Join-Path $repoRoot $generatedManifestRel
$tableHeaderRel = 'include\wc\wc_preclass_table.h'
$tableSourceRel = 'src\core\preclass_table.c'
$snapshotManifestRel = 'docs\registry-snapshots\manifest.json'
$snapshotManifestPath = Join-Path $repoRoot $snapshotManifestRel

$gateDefinitions = [ordered]@{
    guard   = @{ Script = 'tools/test/preclass_table_guard.ps1';            Desc = 'schema/table guard' }
    p0      = @{ Script = 'tools/test/preclass_min_matrix.ps1';              Desc = 'P0 min matrix 12/12' }
    p1      = @{ Script = 'tools/test/preclass_p1_gate_matrix.ps1';          Desc = 'P1 gate matrix 232/232' }
    special = @{ Script = 'tools/test/preclass_special_registry_matrix.ps1'; Desc = 'special registry 17/17' }
    phasec  = @{ Script = 'tools/test/preclass_phasec_default_review.ps1';   Desc = 'Phase C default review 26/26' }
    cidr    = @{ Script = 'tools/test/run_cidr_contract_bundle.ps1';         Desc = 'CIDR contract bundle 4/4 + 9/9' }
    step47  = @{ Script = 'tools/test/step47_preclass_preflight_check.ps1';  Desc = 'Step47 preclass preflight' }
    matrix  = @{ Script = 'tools/test/redirect_matrix_10x6.ps1';             Desc = 'Redirect Matrix 12x6 authority empty' }
}
$profileAll = @('guard', 'p0', 'p1', 'special', 'phasec', 'cidr', 'step47', 'matrix')
$profileCore = @('guard', 'p0', 'p1', 'special', 'phasec', 'cidr', 'step47')
$profileMinimal = @('guard', 'p0', 'p1')

function Write-UpdateLog {
    param([string]$Message)
    Write-Output ("[PRECLASS-UPDATE] {0}" -f $Message)
}

function Get-FileSha256Lower {
    param([string]$PathValue)
    if (-not (Test-Path -LiteralPath $PathValue -PathType Leaf)) {
        return ''
    }
    return (Get-FileHash -Algorithm SHA256 -Path $PathValue).Hash.ToLowerInvariant()
}

function Get-JsonPropertyString {
    param(
        [object]$Object,
        [string]$PropertyName
    )
    if ($null -eq $Object -or ($Object.PSObject.Properties.Name -notcontains $PropertyName)) {
        return ''
    }
    return [string]$Object.$PropertyName
}

# Snapshot state = stored SHA-256 of the four CSV snapshots + snapshot manifest.
function Get-SnapshotStateHash {
    $hashes = New-Object 'System.Collections.Generic.List[string]'
    if (Test-Path -LiteralPath $snapshotManifestPath -PathType Leaf) {
        try {
            $manifest = Get-Content -LiteralPath $snapshotManifestPath -Raw | ConvertFrom-Json
            foreach ($fileEntry in @($manifest.files)) {
                $stored = Get-JsonPropertyString -Object $fileEntry -PropertyName 'stored_sha256'
                if (-not [string]::IsNullOrWhiteSpace($stored)) {
                    $hashes.Add($stored.ToLowerInvariant())
                }
            }
        }
        catch {
            $null = $_
        }
    }
    if ($hashes.Count -eq 0) {
        foreach ($name in @('iana-ipv4-address-space.csv', 'iana-ipv6-address-space.csv', 'iana-ipv4-special-registry.csv', 'iana-ipv6-special-registry.csv')) {
            $csvPath = Join-Path $repoRoot ("docs\registry-snapshots\{0}" -f $name)
            $h = Get-FileSha256Lower -PathValue $csvPath
            if (-not [string]::IsNullOrWhiteSpace($h)) {
                $hashes.Add($h)
            }
        }
    }
    if ($hashes.Count -eq 0) {
        return 'no-snapshot'
    }
    $joined = ($hashes -join '').ToLowerInvariant()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

# Generated state = preclass_manifest.json + generated C table files.
function Get-GeneratedStateHash {
    $paths = @($generatedManifestPath, (Join-Path $repoRoot $tableHeaderRel), (Join-Path $repoRoot $tableSourceRel))
    $hashes = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in $paths) {
        $h = Get-FileSha256Lower -PathValue $p
        if (-not [string]::IsNullOrWhiteSpace($h)) {
            $hashes.Add($h)
        }
    }
    if ($hashes.Count -eq 0) {
        return 'no-generated'
    }
    $joined = ($hashes -join '').ToLowerInvariant()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Resolve-GateNameList {
    param(
        [string[]]$RequestedGates = @(),
        [ValidateSet('all', 'core', 'minimal', 'none')][string]$ProfileName = 'core'
    )

    $effective = @()
    if (@($RequestedGates).Count -gt 0) {
        foreach ($g in @($RequestedGates)) {
            $name = $g.Trim().ToLowerInvariant()
            if ($gateDefinitions.Contains($name)) {
                $effective += $name
            }
            else {
                throw "Unknown gate name: $g (valid: $($gateDefinitions.Keys -join ','))"
            }
        }
    }
    else {
        switch ($ProfileName) {
            'all' { $effective = @($profileAll) }
            'core' { $effective = @($profileCore) }
            'minimal' { $effective = @($profileMinimal) }
            'none' { $effective = @() }
        }
    }
    return @($effective)
}

function Invoke-Gate {
    param(
        [string]$Name,
        [string]$GateScript,
        [string]$GateDesc
    )

    $gatePath = Join-Path $repoRoot $GateScript
    if (-not (Test-Path -LiteralPath $gatePath -PathType Leaf)) {
        throw "Gate script missing: $GateScript"
    }

    if ($DryRun) {
        Write-UpdateLog ("gate name={0} desc={1} action=dry-verify script={2} exit=skipped" -f $Name, $GateDesc, $GateScript)
        return $true
    }

    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $gatePath)
    if (-not [string]::IsNullOrWhiteSpace($BinaryPath) -and (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        $argList += @('-BinaryPath', $BinaryPath)
    }
    Write-UpdateLog ("gate name={0} desc={1} action=start script={2}" -f $Name, $GateDesc, $GateScript)
    $gateOutput = @(& powershell @argList 2>&1)
    $gateExit = $LASTEXITCODE
    $gateOutput | ForEach-Object { Write-Output ("  [GATE:{0}] {1}" -f $Name, $_) }
    if ($gateExit -ne 0) {
        Write-UpdateLog ("gate name={0} desc={1} action=fail exit={2}" -f $Name, $GateDesc, $gateExit)
        return $false
    }
    Write-UpdateLog ("gate name={0} desc={1} action=pass exit=0" -f $Name, $GateDesc)
    return $true
}

function Write-ReviewRecord {
    param(
        [string]$RecordPath,
        [string]$BodyText
    )
    $dir = Split-Path -Parent $RecordPath
    if (-not [string]::IsNullOrWhiteSpace($dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $utf8Bom = [System.Text.UTF8Encoding]::new($true)
    [System.IO.File]::WriteAllText($RecordPath, $BodyText, $utf8Bom)
}

# ---- Resolve effective gates ------------------------------------------------
$effectiveGates = @(Resolve-GateNameList -RequestedGates $Gates -ProfileName $GateProfile)
$binaryResolved = $BinaryPath
if ([string]::IsNullOrWhiteSpace($binaryResolved)) {
    $binaryResolved = Join-Path $repoRoot 'release\lzispro\whois\whois-win64.exe'
}

# ---- Preflight: required tooling --------------------------------------------
foreach ($required in @($updateScript, $genScript, (Join-Path $repoRoot $gateDefinitions.guard.Script))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required tool missing: $required"
    }
}
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if ($null -eq $pythonCmd) {
    throw 'Python interpreter not found (required by gen_preclass_table.py).'
}

# ---- Before state -----------------------------------------------------------
$snapshotBefore = Get-SnapshotStateHash
$generatedBefore = Get-GeneratedStateHash
Write-UpdateLog ("state_before snapshot={0} generated={1}" -f $snapshotBefore, $generatedBefore)

$dryMode = if ($DryRun) { if ($SimulateNoChange) { 'dry-no-change' } else { 'dry-simulate-change' } } else { 'live' }
Write-UpdateLog ("start mode={0} profile={1} gates={2} skip_update={3} gates_on_no_change={4}" -f $dryMode, $GateProfile, ($effectiveGates -join ','), [bool]$SkipUpdate, [bool]$GatesOnNoChange)

# ---- Stage 1: snapshot update ------------------------------------------------
$snapshotAfter = $snapshotBefore
if (-not $SkipUpdate) {
    if ($DryRun) {
        Write-UpdateLog "stage=snapshot-update action=dry-skip (DryRun: no download/replace)"
        if ($SimulateNoChange) {
            $snapshotAfter = $snapshotBefore
        }
        else {
            $snapshotAfter = 'simulated-change-' + $snapshotBefore
        }
    }
    else {
        $updateArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $updateScript)
        if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
            $updateArgs += @('-OutputDirectory', $OutputDirectory)
        }
        Write-UpdateLog 'stage=snapshot-update action=start'
        $updateOutput = @(& powershell @updateArgs 2>&1)
        $updateExit = $LASTEXITCODE
        $updateOutput | ForEach-Object { Write-Output ("  [UPDATE] {0}" -f $_) }
        if ($updateExit -ne 0) {
            throw "Snapshot update failed (exit=$updateExit)."
        }
        Write-UpdateLog 'stage=snapshot-update action=pass'
        $snapshotAfter = Get-SnapshotStateHash
    }
}

# ---- Stage 2: regenerate table ----------------------------------------------
$generatedAfter = $generatedBefore
if (-not $DryRun) {
    Write-UpdateLog 'stage=table-generate action=start'
    $genOutput = @(& $pythonCmd.Source 'tools\preclass\gen_preclass_table.py' 2>&1)
    $genExit = $LASTEXITCODE
    $genOutput | ForEach-Object { Write-Output ("  [GEN] {0}" -f $_) }
    if ($genExit -ne 0) {
        throw "Table generation failed (exit=$genExit)."
    }
    $generatedAfter = Get-GeneratedStateHash
    Write-UpdateLog ("stage=table-generate action=pass generated_hash={0}" -f $generatedAfter)
}

# ---- Stage 3: change detection ----------------------------------------------
$snapshotChanged = ($snapshotAfter -ne $snapshotBefore)
$generatedChanged = ($generatedAfter -ne $generatedBefore)
$changed = ($snapshotChanged -or $generatedChanged -or ($DryRun -and -not $SimulateNoChange))

Write-UpdateLog ("change_detection snapshot_before={0} snapshot_after={1} snapshot_changed={2} generated_before={3} generated_after={4} generated_changed={5} overall_changed={6}" -f $snapshotBefore, $snapshotAfter, [bool]$snapshotChanged, $generatedBefore, $generatedAfter, [bool]$generatedChanged, [bool]$changed)

$reviewOutRoot = if (-not [string]::IsNullOrWhiteSpace($ReviewRecordPath)) {
    $ReviewRecordPath
}
else {
    Join-Path $repoRoot ("out\artifacts\preclass_table_review\{0}\review.md" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

if (-not $changed) {
    # No-change path: keep generator output stable and only run gates on request.
    Write-UpdateLog 'result=no-change'
    $gatePass = $true
    if ($GatesOnNoChange -or ($effectiveGates -contains 'guard' -and $DryRun -and $SimulateNoChange)) {
        foreach ($g in $effectiveGates) {
            $def = $gateDefinitions[$g]
            if (-not (Invoke-Gate -Name $g -GateScript ([string]$def.Script) -GateDesc ([string]$def.Desc))) {
                $gatePass = $false
            }
        }
    }
    else {
        Write-UpdateLog ('gates action=skipped reason=no-change (force with -GatesOnNoChange)')
    }
    $generatedStable = (-not $DryRun -or -not $SimulateNoChange -or $generatedAfter -eq $generatedBefore)
    Write-UpdateLog ("result=pass no_change=true generated_stable={0} gates_pass={1}" -f [bool]$generatedStable, [bool]$gatePass)
    if (-not $gatePass) { exit 1 }
    exit 0
}

# ---- Changed path: diff summary + gates + review record ---------------------
$diffSummary = New-Object 'System.Collections.Generic.List[string]'
[void]$diffSummary.Add("Preclass table snapshot/generated change review - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$diffSummary.Add('')
[void]$diffSummary.Add('## Snapshot state')
[void]$diffSummary.Add(("- before: {0}" -f $snapshotBefore))
[void]$diffSummary.Add(("- after : {0}" -f $snapshotAfter))
if (Test-Path -LiteralPath $snapshotManifestPath -PathType Leaf) {
    try {
        $manifest = Get-Content -LiteralPath $snapshotManifestPath -Raw | ConvertFrom-Json
        [void]$diffSummary.Add('')
        [void]$diffSummary.Add('## Pinned snapshot files (manifest)')
        foreach ($fileEntry in @($manifest.files)) {
            $name = Get-JsonPropertyString -Object $fileEntry -PropertyName 'file'
            $stored = Get-JsonPropertyString -Object $fileEntry -PropertyName 'stored_sha256'
            $rows = Get-JsonPropertyString -Object $fileEntry -PropertyName 'row_count'
            [void]$diffSummary.Add(("- {0} sha256={1} rows={2}" -f $name, $stored, $rows))
        }
    }
    catch {
        [void]$diffSummary.Add('(snapshot manifest unreadable)')
    }
}
[void]$diffSummary.Add('')
[void]$diffSummary.Add('## Generated table')
[void]$diffSummary.Add(("- preclass_manifest.json : {0}" -f (Get-FileSha256Lower -PathValue $generatedManifestPath)))
[void]$diffSummary.Add(("- wc_preclass_table.h     : {0}" -f (Get-FileSha256Lower -PathValue (Join-Path $repoRoot $tableHeaderRel))))
[void]$diffSummary.Add(("- preclass_table.c       : {0}" -f (Get-FileSha256Lower -PathValue (Join-Path $repoRoot $tableSourceRel))))
[void]$diffSummary.Add('')
[void]$diffSummary.Add('## Gate results')
foreach ($g in $effectiveGates) {
    $def = $gateDefinitions[$g]
    $ok = Invoke-Gate -Name $g -GateScript ([string]$def.Script) -GateDesc ([string]$def.Desc)
    [void]$diffSummary.Add(("- {0} ({1}): {2}" -f $g, $def.Desc, $(if ($ok) { 'PASS' } else { 'FAIL' })))
    if (-not $ok) {
        Write-UpdateLog ("result=fail gate={0}" -f $g)
        exit 1
    }
}
[void]$diffSummary.Add('')
[void]$diffSummary.Add('## Review requirement')
[void]$diffSummary.Add('- Snapshot or generated table changed; MUST review diff and confirm classification expectations before release.')
[void]$diffSummary.Add('- Approved differences must be re-frozen in wc_preclass_verify_hardcoded_consistency if affected.')

if ($DryRun) {
    $reviewOutRoot = Join-Path $repoRoot ("out\artifacts\preclass_table_review\dryrun-{0}\review.md" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$reviewBody = ($diffSummary -join "`n") + "`n"
Write-ReviewRecord -RecordPath $reviewOutRoot -BodyText $reviewBody
Write-UpdateLog ("review_record={0}" -f $reviewOutRoot)
Write-UpdateLog 'result=pass changed=true review_required=true'
exit 0
