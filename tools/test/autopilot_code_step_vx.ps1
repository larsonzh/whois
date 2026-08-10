param(
    [Parameter(Mandatory = $true)][string]$TaskDefinitionFile,
    [Parameter(Mandatory = $true)][string]$StateDir,
    [AllowEmptyString()][string]$ValidatedArtifactDirectory = '',
    [switch]$Reset,
    [switch]$ResetStateOnly,
    [AllowEmptyString()][string]$FaultInjectionAfterTargetId = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $PSScriptRoot 'task_definition_target_registry.ps1')

function Get-VxSha256Bytes {
    param([byte[]]$Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-VxFileFacts {
    param([string]$Path)

    $exists = Test-Path -LiteralPath $Path -PathType Leaf
    $bytes = if ($exists) { [IO.File]::ReadAllBytes($Path) } else { $null }
    return [pscustomobject]@{
        Exists = [bool]$exists
        Length = if ($exists) { [long]$bytes.Length } else { $null }
        Sha256 = if ($exists) { Get-VxSha256Bytes $bytes } else { $null }
        Bytes = $bytes
    }
}

function Write-VxJsonAtomic {
    param([string]$Path, [object]$Value)

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $temporary = Join-Path $parent ('.{0}.{1}.tmp' -f (Split-Path -Leaf $Path), [guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
        if ([IO.File]::Exists($Path)) {
            $backup = Join-Path $parent ('.{0}.{1}.bak' -f (Split-Path -Leaf $Path), [guid]::NewGuid().ToString('N'))
            try { [IO.File]::Replace($temporary, $Path, $backup, $true) }
            finally { if ([IO.File]::Exists($backup)) { [IO.File]::Delete($backup) } }
        }
        else {
            [IO.File]::Move($temporary, $Path)
        }
    }
    finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Test-VxExpectedFacts {
    param([string]$Path, [bool]$Exists, [AllowNull()][object]$Length, [AllowNull()][object]$Sha256)

    $facts = Get-VxFileFacts $Path
    if ($facts.Exists -ne $Exists) { return $false }
    if (-not $Exists) { return $true }
    return ($facts.Length -eq [long]$Length -and $facts.Sha256 -eq ([string]$Sha256).ToLowerInvariant())
}

function Assert-VxNoReparseEscape {
    param([string]$Root, [string]$Path, [string]$Label)

    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $pathFull = [IO.Path]::GetFullPath($Path)
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $pathFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "validated artifact path binding mismatch $Label escapes root: $pathFull"
    }
    $cursor = $pathFull
    while (-not [string]::IsNullOrWhiteSpace($cursor) -and $cursor.Length -ge $rootFull.Length) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "validated artifact path binding mismatch $Label uses reparse point: $cursor"
            }
        }
        if ($cursor.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) { break }
        $cursor = Split-Path -Parent $cursor
    }
}

function Remove-VxTransactionFiles {
    param([object]$Journal, [string]$JournalPath)

    foreach ($entry in @($Journal.targets)) {
        foreach ($path in @([string]$entry.temp_path, [string]$entry.backup_path)) {
            if (-not [string]::IsNullOrWhiteSpace($path) -and [IO.File]::Exists($path)) {
                [IO.File]::Delete($path)
            }
        }
    }
    if ([IO.File]::Exists($JournalPath)) { [IO.File]::Delete($JournalPath) }
}

function Test-VxJournalVector {
    param([object]$Journal, [ValidateSet('baseline', 'effective')][string]$Vector)

    foreach ($entry in @($Journal.targets)) {
        $existsName = "${Vector}_exists"
        $lengthName = "${Vector}_length"
        $shaName = "${Vector}_sha256"
        if (-not (Test-VxExpectedFacts -Path ([string]$entry.path) -Exists ([bool]$entry.$existsName) -Length $entry.$lengthName -Sha256 $entry.$shaName)) {
            return $false
        }
    }
    return $true
}

function Invoke-VxRollback {
    param([object]$Journal, [string]$JournalPath)

    $errors = New-Object 'Collections.Generic.List[string]'
    $entries = @($Journal.targets)
    [array]::Reverse($entries)
    foreach ($entry in $entries) {
        try {
            $targetPath = [string]$entry.path
            $backupPath = [string]$entry.backup_path
            if ([bool]$entry.baseline_exists) {
                if ([IO.File]::Exists($backupPath)) {
                    if ([IO.File]::Exists($targetPath)) {
                        $discard = Join-Path (Split-Path -Parent $targetPath) ('.code-step-vx-rollback-{0}.bin' -f [guid]::NewGuid().ToString('N'))
                        try { [IO.File]::Replace($backupPath, $targetPath, $discard, $true) }
                        finally { if ([IO.File]::Exists($discard)) { [IO.File]::Delete($discard) } }
                    }
                    else {
                        [IO.File]::Move($backupPath, $targetPath)
                    }
                }
                elseif (-not (Test-VxExpectedFacts -Path $targetPath -Exists $true -Length $entry.baseline_length -Sha256 $entry.baseline_sha256)) {
                    throw 'backup missing and target does not match baseline'
                }
            }
            elseif ([IO.File]::Exists($targetPath)) {
                [IO.File]::Delete($targetPath)
            }
            $entry.status = 'rolled-back'
            Write-VxJsonAtomic -Path $JournalPath -Value $Journal
            Write-Output "[CODE-STEP] round=$($Journal.round) rollback=restored target=$targetPath target_id=$($entry.target_id)"
        }
        catch {
            $errors.Add("target_id=$($entry.target_id) detail=$($_.Exception.Message)")
        }
    }

    if ($errors.Count -eq 0 -and (Test-VxJournalVector -Journal $Journal -Vector baseline)) {
        $Journal.rollback_status = 'complete'
        Write-VxJsonAtomic -Path $JournalPath -Value $Journal
        return $true
    }
    $Journal.rollback_status = 'incomplete'
    $Journal.rollback_errors = @($errors)
    Write-VxJsonAtomic -Path $JournalPath -Value $Journal
    return $false
}

function Complete-VxRecoveredReceiptState {
    param([string]$ReceiptPath, [string]$StatePath)

    $receipt = Get-Content -LiteralPath $ReceiptPath -Raw -Encoding utf8 | ConvertFrom-Json
    if ([string]$receipt.schema -ne 'CODE_STEP_VX_COMMIT_RECEIPT_V1' -or -not [bool]$receipt.success) {
        throw 'commit journal effective vector has no valid success receipt'
    }
    Write-VxJsonAtomic -Path $StatePath -Value $receipt.state
}

function Resolve-VxPendingJournal {
    param([string]$JournalPath, [string]$StatePath, [string]$ReceiptPath)

    if (-not (Test-Path -LiteralPath $JournalPath -PathType Leaf)) { return }
    $journal = Get-Content -LiteralPath $JournalPath -Raw -Encoding utf8 | ConvertFrom-Json
    if ([string]$journal.schema -ne 'CODE_STEP_VX_COMMIT_JOURNAL_V1') {
        throw 'unresolved commit journal has unsupported schema'
    }
    if (Test-VxJournalVector -Journal $journal -Vector baseline) {
        Remove-VxTransactionFiles -Journal $journal -JournalPath $JournalPath
        Write-Output '[CODE-STEP] journal_recovery=baseline-cleanup'
        return
    }
    if ((Test-VxJournalVector -Journal $journal -Vector effective) -and (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)) {
        $receipt = Get-Content -LiteralPath $ReceiptPath -Raw -Encoding utf8 | ConvertFrom-Json
        if ([string]$receipt.transaction_id -eq [string]$journal.transaction_id -and [bool]$receipt.success) {
            Complete-VxRecoveredReceiptState -ReceiptPath $ReceiptPath -StatePath $StatePath
            Remove-VxTransactionFiles -Journal $journal -JournalPath $JournalPath
            Write-Output '[CODE-STEP] journal_recovery=effective-receipt-converged'
            return
        }
    }
    if (Invoke-VxRollback -Journal $journal -JournalPath $JournalPath) {
        Remove-VxTransactionFiles -Journal $journal -JournalPath $JournalPath
        Write-Output '[CODE-STEP] journal_recovery=rollback-complete'
        return
    }
    throw 'unresolved commit journal rollback incomplete hard_block=true'
}

function New-VxBaselineIfNeeded {
    param([object]$Registry, [string]$TaskPath, [string]$Directory)

    $manifestPath = Join-Path $Directory 'baseline-manifest.json'
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) { return }
    $baselineDirectory = Join-Path $Directory 'baseline'
    New-Item -ItemType Directory -Path $baselineDirectory -Force | Out-Null
    $targets = @()
    foreach ($target in @($Registry.Targets | Sort-Object File)) {
        $facts = Get-VxFileFacts $target.FullPath
        $payload = $null
        if ($facts.Exists) {
            $payload = "baseline/$($target.Id).bin"
            [IO.File]::WriteAllBytes((Join-Path $baselineDirectory "$($target.Id).bin"), $facts.Bytes)
        }
        $targets += [ordered]@{
            id = $target.Id; path = $target.FullPath; file = $target.File; lifecycle = $target.Lifecycle
            exists = $facts.Exists; length = $facts.Length; sha256 = $facts.Sha256; payload = $payload
        }
    }
    $manifest = [ordered]@{
        schema = 'CODE_STEP_VX_BASELINE_V1'
        task_definition_path = $TaskPath
        task_definition_sha256 = (Get-FileHash -LiteralPath $TaskPath -Algorithm SHA256).Hash.ToLowerInvariant()
        target_set_sha256 = $Registry.TargetSetSha256
        captured_at = [DateTimeOffset]::UtcNow.ToString('o')
        targets = $targets
    }
    Write-VxJsonAtomic -Path $manifestPath -Value $manifest
}

function Get-VxState {
    param([string]$Path, [string]$TargetSetSha256)

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $state = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json
        if ([string]$state.schema -ne 'CODE_STEP_VX_STATE_V1' -or [string]$state.targetSetSha256 -ne $TargetSetSha256) {
            throw 'validated artifact contract mismatch state schema or target set'
        }
        return $state
    }
    return [pscustomobject]@{
        schema = 'CODE_STEP_VX_STATE_V1'; invocationCount = 0; lastRound = ''; lastTransactionId = ''
        lastManifestSha256 = ''; targetSetSha256 = $TargetSetSha256; lastTimestamp = ''
    }
}

function Assert-VxManifestAndBuildEntries {
    param([object]$Registry, [string]$ArtifactDirectory, [string]$TaskPath, [string]$Round)

    if ([string]::IsNullOrWhiteSpace($ArtifactDirectory)) { throw "validated artifact required round=$Round" }
    $artifactRoot = [IO.Path]::GetFullPath($ArtifactDirectory).TrimEnd('\', '/')
    $manifestPath = Join-Path $artifactRoot 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'validated artifact or manifest not found' }
    Assert-VxNoReparseEscape -Root $repoRoot -Path $artifactRoot -Label 'artifact-directory'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 | ConvertFrom-Json
    if ([string]$manifest.schema -ne 'TASK_STATIC_VALIDATED_ARTIFACT_VX1' -or [string]$manifest.round -ne $Round) {
        throw "validated artifact manifest mismatch round=$Round"
    }
    if ([IO.Path]::GetFullPath([string]$manifest.task_definition) -ne [IO.Path]::GetFullPath($TaskPath)) {
        throw "validated artifact path binding mismatch round=$Round"
    }
    $taskHash = (Get-FileHash -LiteralPath $TaskPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string]$manifest.task_definition_sha256 -ne $taskHash -or [string]$manifest.target_set_sha256 -ne $Registry.TargetSetSha256) {
        throw "validated artifact hash binding mismatch round=$Round"
    }
    $manifestTargets = @($manifest.targets)
    if ($manifestTargets.Count -ne @($Registry.Targets).Count) { throw 'validated artifact contract mismatch target count' }
    $entries = @()
    foreach ($target in @($Registry.Targets | Sort-Object File)) {
        $foundTargets = @($manifestTargets | Where-Object { [string]$_.id -eq $target.Id })
        if ($foundTargets.Count -ne 1) { throw "validated artifact contract mismatch target_id=$($target.Id)" }
        $item = $foundTargets[0]
        if ([string]$item.path -ne $target.File -or [string]$item.kind -ne $target.Kind -or [string]$item.lifecycle -ne $target.Lifecycle) {
            throw "validated artifact path binding mismatch target_id=$($target.Id) path=$($target.FullPath)"
        }
        Assert-VxNoReparseEscape -Root $repoRoot -Path $target.FullPath -Label "target_id=$($target.Id)"
        if (-not (Test-VxExpectedFacts -Path $target.FullPath -Exists ([bool]$item.baseline_exists) -Length $item.baseline_length -Sha256 $item.baseline_sha256)) {
            throw "validated artifact hash binding mismatch target_id=$($target.Id) path=$($target.FullPath)"
        }
        $effectiveBytes = $null
        if ([bool]$item.changed -and [bool]$item.effective_exists) {
            $payloadRelative = [string]$item.payload
            if ([string]::IsNullOrWhiteSpace($payloadRelative) -or [IO.Path]::IsPathRooted($payloadRelative) -or @($payloadRelative.Replace('\', '/').Split('/') | Where-Object { $_ -eq '..' }).Count -gt 0) {
                throw "validated artifact path binding mismatch payload target_id=$($target.Id)"
            }
            $payloadPath = [IO.Path]::GetFullPath((Join-Path $artifactRoot $payloadRelative))
            Assert-VxNoReparseEscape -Root $artifactRoot -Path $payloadPath -Label "payload target_id=$($target.Id)"
            if (-not (Test-Path -LiteralPath $payloadPath -PathType Leaf)) { throw "validated artifact or manifest not found target_id=$($target.Id)" }
            $effectiveBytes = [IO.File]::ReadAllBytes($payloadPath)
            $payloadHash = Get-VxSha256Bytes $effectiveBytes
            if ($effectiveBytes.Length -ne [long]$item.effective_length -or $payloadHash -ne ([string]$item.effective_sha256).ToLowerInvariant() -or
                $payloadHash -ne ([string]$item.payload_sha256).ToLowerInvariant()) {
                throw "validated artifact hash binding mismatch payload target_id=$($target.Id)"
            }
        }
        elseif ([bool]$item.changed -and -not [bool]$item.effective_exists) {
            if (-not [string]::IsNullOrWhiteSpace([string]$item.payload)) { throw "validated artifact contract mismatch deleted payload target_id=$($target.Id)" }
        }
        elseif (-not [bool]$item.changed) {
            if ([bool]$item.baseline_exists -ne [bool]$item.effective_exists -or
                ([bool]$item.baseline_exists -and ([long]$item.baseline_length -ne [long]$item.effective_length -or [string]$item.baseline_sha256 -ne [string]$item.effective_sha256))) {
                throw "validated artifact contract mismatch unchanged target_id=$($target.Id)"
            }
        }
        $entries += [pscustomobject]@{ Target = $target; Manifest = $item; EffectiveBytes = $effectiveBytes }
    }
    return [pscustomobject]@{ Manifest = $manifest; ManifestPath = $manifestPath; Entries = $entries }
}

function Invoke-VxTransaction {
    param(
        [object[]]$Entries,
        [string]$Round,
        [string]$JournalPath,
        [string]$ReceiptPath,
        [object]$ReceiptState,
        [string]$ManifestSha256,
        [string]$TargetSetSha256,
        [AllowEmptyString()][string]$InjectAfterTargetId = ''
    )

    $transactionId = [guid]::NewGuid().ToString('N')
    $journalTargets = @()
    foreach ($entry in @($Entries | Sort-Object { $_.Target.File })) {
        $target = $entry.Target
        $item = $entry.Manifest
        $parent = Split-Path -Parent $target.FullPath
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "code-step parent missing target_id=$($target.Id) path=$parent" }
        $tempPath = Join-Path $parent ('.code-step-vx-{0}-{1}.tmp' -f $transactionId, $target.Id)
        $backupPath = Join-Path $parent ('.code-step-vx-{0}-{1}.bak' -f $transactionId, $target.Id)
        if ([bool]$item.effective_exists -and [bool]$item.changed) {
            [IO.File]::WriteAllBytes($tempPath, $entry.EffectiveBytes)
            if (-not (Test-VxExpectedFacts -Path $tempPath -Exists $true -Length $item.effective_length -Sha256 $item.effective_sha256)) {
                throw "code-step temp verification failed target_id=$($target.Id)"
            }
        }
        $journalTargets += [pscustomobject]@{
            target_id = $target.Id; path = $target.FullPath; status = 'prepared'
            baseline_exists = [bool]$item.baseline_exists; baseline_length = $item.baseline_length; baseline_sha256 = $item.baseline_sha256
            effective_exists = [bool]$item.effective_exists; effective_length = $item.effective_length; effective_sha256 = $item.effective_sha256
            changed = [bool]$item.changed; temp_path = $tempPath; backup_path = $backupPath
        }
    }
    $journal = [pscustomobject]@{
        schema = 'CODE_STEP_VX_COMMIT_JOURNAL_V1'; transaction_id = $transactionId; round = $Round
        manifest_sha256 = $ManifestSha256; target_set_sha256 = $TargetSetSha256
        rollback_status = 'not-started'; targets = $journalTargets
    }
    Write-VxJsonAtomic -Path $JournalPath -Value $journal

    try {
        if (-not (Test-VxJournalVector -Journal $journal -Vector baseline)) { throw 'validated artifact hash binding mismatch during commit baseline recheck' }
        foreach ($entry in @($journal.targets)) {
            if (-not [bool]$entry.changed) {
                $entry.status = 'unchanged'
                Write-VxJsonAtomic -Path $JournalPath -Value $journal
                Write-Output "[CODE-STEP] round=$Round action=already-applied target=$($entry.path) target_id=$($entry.target_id)"
                continue
            }
            if ([bool]$entry.effective_exists) {
                if ([bool]$entry.baseline_exists) {
                    [IO.File]::Replace([string]$entry.temp_path, [string]$entry.path, [string]$entry.backup_path, $true)
                    $action = 'applied'
                }
                else {
                    if ([IO.File]::Exists([string]$entry.path)) { throw "create target appeared during commit target_id=$($entry.target_id)" }
                    [IO.File]::Move([string]$entry.temp_path, [string]$entry.path)
                    $action = 'created'
                }
            }
            elseif ([bool]$entry.baseline_exists) {
                [IO.File]::Move([string]$entry.path, [string]$entry.backup_path)
                $action = 'deleted'
            }
            else { $action = 'already-absent' }
            $entry.status = 'committed'
            Write-VxJsonAtomic -Path $JournalPath -Value $journal
            Write-Output "[CODE-STEP] round=$Round action=$action target=$($entry.path) target_id=$($entry.target_id)"
            if (-not [string]::IsNullOrWhiteSpace($InjectAfterTargetId) -and [string]$entry.target_id -eq $InjectAfterTargetId) {
                throw "injected code-step failure after target_id=$InjectAfterTargetId"
            }
        }
        if (-not (Test-VxJournalVector -Journal $journal -Vector effective)) { throw 'code-step write-after effective verification failed' }
        $ReceiptState.lastTransactionId = $transactionId
        $receipt = [ordered]@{
            schema = 'CODE_STEP_VX_COMMIT_RECEIPT_V1'; success = $true; transaction_id = $transactionId; round = $Round
            manifest_sha256 = $ManifestSha256; target_set_sha256 = $TargetSetSha256
            committed_at = [DateTimeOffset]::UtcNow.ToString('o'); state = $ReceiptState; targets = $journal.targets
        }
        Write-VxJsonAtomic -Path $ReceiptPath -Value $receipt
        return [pscustomobject]@{ TransactionId = $transactionId; Journal = $journal }
    }
    catch {
        $failure = $_
        $rollbackComplete = Invoke-VxRollback -Journal $journal -JournalPath $JournalPath
        $failureReceipt = Join-Path (Split-Path -Parent $JournalPath) ("failure-receipt-$transactionId.json")
        Write-VxJsonAtomic -Path $failureReceipt -Value ([ordered]@{
            schema = 'CODE_STEP_VX_FAILURE_RECEIPT_V1'; success = $false; transaction_id = $transactionId; round = $Round
            rollback_status = if ($rollbackComplete) { 'complete' } else { 'incomplete' }
            failure = $failure.Exception.Message; created_at = [DateTimeOffset]::UtcNow.ToString('o')
        })
        if ($rollbackComplete) { Remove-VxTransactionFiles -Journal $journal -JournalPath $JournalPath }
        else { throw "rollback incomplete hard_block=true original=$($failure.Exception.Message)" }
        throw $failure
    }
}

function Invoke-VxReset {
    param([object]$Registry, [string]$Directory, [bool]$StateOnly, [string]$TaskPath)

    if ($StateOnly) {
        if (Test-Path -LiteralPath $Directory) { Remove-Item -LiteralPath $Directory -Recurse -Force }
        Write-Output "[CODE-STEP] state_reset=true state_dir=$Directory reset_mode=state-only schema=vx-draft"
        return
    }
    $baselineManifestPath = Join-Path $Directory 'baseline-manifest.json'
    if (-not (Test-Path -LiteralPath $baselineManifestPath -PathType Leaf)) {
        if (Test-Path -LiteralPath $Directory) { Remove-Item -LiteralPath $Directory -Recurse -Force }
        Write-Output "[CODE-STEP] state_reset=true state_dir=$Directory reset_mode=restore-source restore_policy=skipped-no-baseline schema=vx-draft"
        return
    }
    $baseline = Get-Content -LiteralPath $baselineManifestPath -Raw -Encoding utf8 | ConvertFrom-Json
    $taskHash = (Get-FileHash -LiteralPath $TaskPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string]$baseline.schema -ne 'CODE_STEP_VX_BASELINE_V1' -or
        [string]$baseline.target_set_sha256 -ne $Registry.TargetSetSha256 -or
        [IO.Path]::GetFullPath([string]$baseline.task_definition_path) -ne [IO.Path]::GetFullPath($TaskPath)) {
        throw 'reset baseline manifest target set mismatch'
    }
    if ([string]$baseline.task_definition_sha256 -ne $taskHash) {
        Write-Output "[CODE-STEP] reset_task_definition_sha_drift=true baseline_sha256=$($baseline.task_definition_sha256) current_sha256=$taskHash target_set_sha256=$($Registry.TargetSetSha256)"
    }
    $entries = @()
    foreach ($target in @($Registry.Targets | Sort-Object File)) {
        $foundTargets = @($baseline.targets | Where-Object { [string]$_.id -eq $target.Id })
        if ($foundTargets.Count -ne 1 -or [IO.Path]::GetFullPath([string]$foundTargets[0].path) -ne $target.FullPath) { throw "reset baseline target mismatch target_id=$($target.Id)" }
        $stored = $foundTargets[0]
        $current = Get-VxFileFacts $target.FullPath
        $bytes = $null
        if ([bool]$stored.exists) {
            $payloadPath = [IO.Path]::GetFullPath((Join-Path $Directory ([string]$stored.payload)))
            Assert-VxNoReparseEscape -Root $Directory -Path $payloadPath -Label "reset baseline target_id=$($target.Id)"
            if (-not (Test-VxExpectedFacts -Path $payloadPath -Exists $true -Length $stored.length -Sha256 $stored.sha256)) { throw "reset baseline payload mismatch target_id=$($target.Id)" }
            $bytes = [IO.File]::ReadAllBytes($payloadPath)
        }
        $manifestItem = [pscustomobject]@{
            baseline_exists = $current.Exists; baseline_length = $current.Length; baseline_sha256 = $current.Sha256
            effective_exists = [bool]$stored.exists; effective_length = $stored.length; effective_sha256 = $stored.sha256
            changed = ($current.Exists -ne [bool]$stored.exists) -or ($current.Exists -and $current.Sha256 -ne [string]$stored.sha256)
        }
        $entries += [pscustomobject]@{ Target = $target; Manifest = $manifestItem; EffectiveBytes = $bytes }
    }
    $resetState = [pscustomobject]@{ schema = 'CODE_STEP_VX_STATE_V1'; invocationCount = 0; lastRound = ''; lastTransactionId = ''; lastManifestSha256 = ''; targetSetSha256 = $Registry.TargetSetSha256; lastTimestamp = '' }
    $transactionOutput = @(Invoke-VxTransaction -Entries $entries -Round 'RESET' -JournalPath (Join-Path $Directory 'commit-journal.json') -ReceiptPath (Join-Path $Directory 'reset-receipt.json') -ReceiptState $resetState -ManifestSha256 '' -TargetSetSha256 $Registry.TargetSetSha256)
    foreach ($line in @($transactionOutput | Select-Object -SkipLast 1)) { Write-Output $line }
    $result = $transactionOutput[$transactionOutput.Count - 1]
    Remove-VxTransactionFiles -Journal $result.Journal -JournalPath (Join-Path $Directory 'commit-journal.json')
    Remove-Item -LiteralPath $Directory -Recurse -Force
    Write-Output "[CODE-STEP] state_reset=true state_dir=$Directory reset_mode=restore-source restore_policy=restored-baseline schema=vx-draft"
}

try {
    $TaskDefinitionFile = [IO.Path]::GetFullPath($TaskDefinitionFile)
    $StateDir = [IO.Path]::GetFullPath($StateDir)
    $journalPath = Join-Path $StateDir 'commit-journal.json'
    $statePath = Join-Path $StateDir 'state.json'
    $receiptPath = Join-Path $StateDir 'commit-receipt.json'
    if (Test-Path -LiteralPath $StateDir) { Resolve-VxPendingJournal -JournalPath $journalPath -StatePath $statePath -ReceiptPath $receiptPath }

    $definition = Get-Content -LiteralPath $TaskDefinitionFile -Raw -Encoding utf8 | ConvertFrom-Json
    $registry = Resolve-TaskDefinitionTargetRegistry -TaskDefinition $definition -TaskDefinitionPath $TaskDefinitionFile -RepositoryRoot $repoRoot
    if ($registry.SchemaVersion -ne 'vx-draft') { throw 'Vx code-step requires schemaVersion=vx-draft' }

    if ($Reset) {
        Invoke-VxReset -Registry $registry -Directory $StateDir -StateOnly $ResetStateOnly.IsPresent -TaskPath $TaskDefinitionFile
        exit 0
    }

    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    New-VxBaselineIfNeeded -Registry $registry -TaskPath $TaskDefinitionFile -Directory $StateDir
    $state = Get-VxState -Path $statePath -TargetSetSha256 $registry.TargetSetSha256
    $next = [int]$state.invocationCount + 1
    $round = switch ($next) { 1 { 'D1' } 2 { 'D2' } 3 { 'D3' } 4 { 'D4' } default { 'VERIFY_OR_EXTRA' } }
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    if ($next -gt 4) {
        $state.invocationCount = $next; $state.lastRound = $round; $state.lastTimestamp = $timestamp
        $state.lastTransactionId = [guid]::NewGuid().ToString('N')
        $receipt = [ordered]@{ schema = 'CODE_STEP_VX_COMMIT_RECEIPT_V1'; success = $true; transaction_id = $state.lastTransactionId; round = $round; state = $state }
        Write-VxJsonAtomic -Path $receiptPath -Value $receipt
        Write-VxJsonAtomic -Path $statePath -Value $state
        Write-Output "[CODE-STEP] round=$round action=no-op reason=dev-rounds-completed"
        exit 0
    }

    Write-Output "[CODE-STEP] task_definition=$TaskDefinitionFile round=$round schema=vx-draft"
    $validated = Assert-VxManifestAndBuildEntries -Registry $registry -ArtifactDirectory $ValidatedArtifactDirectory -TaskPath $TaskDefinitionFile -Round $round
    if (Test-Path -LiteralPath $journalPath) { throw 'unresolved commit journal blocks validated artifact consumption' }
    $manifestSha = (Get-FileHash -LiteralPath $validated.ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $stateOut = [pscustomobject]@{
        schema = 'CODE_STEP_VX_STATE_V1'; invocationCount = $next; lastRound = $round; lastTransactionId = ''
        lastManifestSha256 = $manifestSha; targetSetSha256 = $registry.TargetSetSha256; lastTimestamp = $timestamp
    }
    $transactionOutput = @(Invoke-VxTransaction -Entries $validated.Entries -Round $round -JournalPath $journalPath -ReceiptPath $receiptPath -ReceiptState $stateOut -ManifestSha256 $manifestSha -TargetSetSha256 $registry.TargetSetSha256 -InjectAfterTargetId $FaultInjectionAfterTargetId)
    foreach ($line in @($transactionOutput | Select-Object -SkipLast 1)) { Write-Output $line }
    $transaction = $transactionOutput[$transactionOutput.Count - 1]
    Write-VxJsonAtomic -Path $statePath -Value $stateOut
    Remove-VxTransactionFiles -Journal $transaction.Journal -JournalPath $journalPath
    $changedCount = @($validated.Entries | Where-Object { [bool]$_.Manifest.changed }).Count
    $touchedCount = @($validated.Entries | Where-Object { [bool]$_.Manifest.touched }).Count
    Write-Output "[CODE-STEP] round=$round validated_artifact=accepted manifest=$($validated.ManifestPath)"
    Write-Output "[CODE-STEP] round=$round transaction=$($transaction.TransactionId) targets_declared=$(@($validated.Entries).Count) targets_touched=$touchedCount targets_changed=$changedCount commit=success"
    exit 0
}
catch {
    $message = $_.Exception.Message.Replace("`r", '').Replace("`n", ' ')
    $faultCode = if ($message -match 'rollback incomplete|unresolved commit journal') { 'code-step-journal-blocked' }
        elseif ($message -match 'not found|required') { 'validated-artifact-missing' }
        elseif ($message -match 'hash binding mismatch|baseline recheck|payload mismatch') { 'validated-artifact-stale' }
        elseif ($message -match 'path binding mismatch|target mismatch|escapes|reparse') { 'validated-artifact-path-mismatch' }
        elseif ($message -match 'manifest mismatch|contract mismatch|target set mismatch') { 'validated-artifact-contract-mismatch' }
        else { 'code-step-io-failure' }
    Write-Output "[CODE-STEP] fault_code=$faultCode failure_kind=environment-transient failure_category=noncode-transient"
    Write-Output "[CODE-STEP] fatal_error=$message"
    exit 1
}