param(
    [Parameter(Mandatory = $true)][ValidateSet('Prepare', 'Validate', 'Promote', 'Abandon', 'Quarantine')][string]$Mode,
    [Parameter(Mandatory = $true)][string]$TaskDefinitionFile,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$TicketId,
    [ValidateSet('A', 'B')][string]$Stage = 'A',
    [AllowEmptyString()][string]$RoundTag = '',
    [ValidateRange(0, 256)][int]$OperationIndex = 0,
    [AllowEmptyString()][string]$ArtifactRoot = '',
    [AllowEmptyString()][string]$Reason = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$checkerPath = Join-Path $PSScriptRoot 'check_task_definition_static.ps1'
if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
    $ArtifactRoot = Join-Path $repoRoot 'out\artifacts\task_definition_repair'
}
elseif (-not [System.IO.Path]::IsPathRooted($ArtifactRoot)) {
    $ArtifactRoot = Join-Path $repoRoot $ArtifactRoot
}

$officialPath = if ([System.IO.Path]::IsPathRooted($TaskDefinitionFile)) {
    [System.IO.Path]::GetFullPath($TaskDefinitionFile)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $TaskDefinitionFile))
}
$transactionDir = Join-Path $ArtifactRoot $TicketId
$baselinePath = Join-Path $transactionDir 'baseline.json'
$candidatePath = Join-Path $transactionDir 'candidate.json'
$manifestPath = Join-Path $transactionDir 'manifest.json'
$receiptPath = Join-Path $transactionDir 'promotion-receipt.json'

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-JsonAtomically {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Value
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $temporaryPath = Join-Path $directory ('.task-definition-transaction-{0}.tmp' -f ([guid]::NewGuid().ToString('N')))
    try {
        $json = ($Value | ConvertTo-Json -Depth 16) + "`n"
        [System.IO.File]::WriteAllText($temporaryPath, $json, [System.Text.UTF8Encoding]::new($true))
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $backupPath = Join-Path $directory ('.task-definition-transaction-{0}.bak' -f ([guid]::NewGuid().ToString('N')))
            try {
                [System.IO.File]::Replace($temporaryPath, $Path, $backupPath, $true)
            }
            finally {
                Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
            }
        }
        else {
            [System.IO.File]::Move($temporaryPath, $Path)
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Read-Manifest {
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "[TASK-DEFINITION-TRANSACTION] manifest not found: $manifestPath"
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    if ([string]$manifest.schema -ne 'TASK_DEFINITION_REPAIR_TRANSACTION_V1') {
        throw '[TASK-DEFINITION-TRANSACTION] manifest schema mismatch'
    }
    if ([System.IO.Path]::GetFullPath([string]$manifest.official_path) -ne $officialPath -or
        [System.IO.Path]::GetFullPath([string]$manifest.candidate_path) -ne [System.IO.Path]::GetFullPath($candidatePath)) {
        throw '[TASK-DEFINITION-TRANSACTION] manifest path binding mismatch'
    }
    return $manifest
}

function Set-ManifestState {
    param(
        [Parameter(Mandatory = $true)][object]$Manifest,
        [Parameter(Mandatory = $true)][string]$State,
        [AllowEmptyString()][string]$Detail = ''
    )
    $Manifest.state = $State
    $Manifest.updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $Manifest.detail = $Detail
    Write-JsonAtomically -Path $manifestPath -Value $Manifest
}

function Assert-BaselineBinding {
    param([Parameter(Mandatory = $true)][object]$Manifest)
    if (-not (Test-Path -LiteralPath $officialPath -PathType Leaf)) {
        throw '[TASK-DEFINITION-TRANSACTION] official task definition missing'
    }
    $currentOfficialHash = Get-Sha256 -Path $officialPath
    if ($currentOfficialHash -ne [string]$Manifest.baseline_sha256) {
        throw "[TASK-DEFINITION-TRANSACTION] baseline drift detected expected=$($Manifest.baseline_sha256) actual=$currentOfficialHash"
    }
}

function Invoke-Checker {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][hashtable]$Arguments
    )
    $logPath = Join-Path $transactionDir ("validation-{0}.log" -f $Name)
    $output = @(& $checkerPath @Arguments 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    [System.IO.File]::WriteAllLines($logPath, $output, [System.Text.UTF8Encoding]::new($true))
    if ($exitCode -ne 0) {
        throw "[TASK-DEFINITION-TRANSACTION] checker failed step=$Name exit=$exitCode log=$logPath"
    }
    return $logPath
}

if ($Mode -eq 'Prepare') {
    if (-not (Test-Path -LiteralPath $officialPath -PathType Leaf)) {
        throw "[TASK-DEFINITION-TRANSACTION] official task definition not found: $officialPath"
    }
    if (Test-Path -LiteralPath $transactionDir) {
        throw "[TASK-DEFINITION-TRANSACTION] transaction already exists: $transactionDir"
    }
    New-Item -ItemType Directory -Path $transactionDir -Force | Out-Null
    [System.IO.File]::WriteAllBytes($baselinePath, [System.IO.File]::ReadAllBytes($officialPath))
    [System.IO.File]::WriteAllBytes($candidatePath, [System.IO.File]::ReadAllBytes($officialPath))
    $baselineHash = Get-Sha256 -Path $officialPath
    $manifest = [ordered]@{
        schema = 'TASK_DEFINITION_REPAIR_TRANSACTION_V1'
        ticket_id = $TicketId
        stage = $Stage
        round = $RoundTag.Trim().ToUpperInvariant()
        operation_index = $OperationIndex
        official_path = $officialPath
        baseline_path = $baselinePath
        candidate_path = $candidatePath
        baseline_sha256 = $baselineHash
        prepared_candidate_sha256 = $baselineHash
        validated_candidate_sha256 = ''
        validation_at = ''
        validation_logs = @()
        promoted_sha256 = ''
        promoted_at = ''
        state = 'prepared'
        created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        detail = ''
    }
    Write-JsonAtomically -Path $manifestPath -Value $manifest
    Write-Output ("[TASK-DEFINITION-TRANSACTION] status=prepared ticket={0} candidate={1} baseline_sha256={2}" -f $TicketId, $candidatePath, $baselineHash)
    exit 0
}

$manifest = Read-Manifest

if ($Mode -eq 'Abandon' -or $Mode -eq 'Quarantine') {
    $state = if ($Mode -eq 'Quarantine') { 'quarantined' } else { 'abandoned' }
    Set-ManifestState -Manifest $manifest -State $state -Detail $Reason
    Write-Output ("[TASK-DEFINITION-TRANSACTION] status={0} ticket={1} candidate_retained=true" -f $state, $TicketId)
    exit 0
}

if ($Mode -eq 'Validate') {
    try {
        Assert-BaselineBinding -Manifest $manifest
        if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            throw '[TASK-DEFINITION-TRANSACTION] candidate task definition missing'
        }
        $syntaxLog = Invoke-Checker -Name 'syntax' -Arguments @{
            TaskDefinitionFile = $candidatePath
            RepoRoot = $repoRoot
            Policy = 'enforce'
            SyntaxOnly = $true
        }
        $focusedLog = ''
        $effectiveRound = ([string]$manifest.round).Trim().ToUpperInvariant()
        $effectiveOperation = [int]$manifest.operation_index
        if ([string]::IsNullOrWhiteSpace($effectiveRound)) {
            throw '[TASK-DEFINITION-TRANSACTION] validation requires round binding'
        }
        if ($effectiveOperation -gt 0) {
            $focusedLog = Invoke-Checker -Name 'focused-op' -Arguments @{
                TaskDefinitionFile = $candidatePath
                RepoRoot = $repoRoot
                Policy = 'enforce'
                RoundTag = $effectiveRound
                RequestedOperationIndex = $effectiveOperation
            }
        }
        $roundLog = Invoke-Checker -Name 'round' -Arguments @{
            TaskDefinitionFile = $candidatePath
            RepoRoot = $repoRoot
            Policy = 'enforce'
            RoundTag = $effectiveRound
        }
        $manifest.validated_candidate_sha256 = Get-Sha256 -Path $candidatePath
        $manifest.validation_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $manifest.validation_logs = @($syntaxLog, $focusedLog, $roundLog | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        Set-ManifestState -Manifest $manifest -State 'validated'
        Write-Output ("[TASK-DEFINITION-TRANSACTION] status=validated ticket={0} candidate_sha256={1}" -f $TicketId, $manifest.validated_candidate_sha256)
        exit 0
    }
    catch {
        Set-ManifestState -Manifest $manifest -State 'validation_failed' -Detail $_.Exception.Message
        throw
    }
}

if ($Mode -eq 'Promote') {
    if ([string]$manifest.state -ne 'validated') {
        throw "[TASK-DEFINITION-TRANSACTION] promote requires validated state actual=$($manifest.state)"
    }
    Assert-BaselineBinding -Manifest $manifest
    if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
        throw '[TASK-DEFINITION-TRANSACTION] candidate task definition missing'
    }
    $candidateHash = Get-Sha256 -Path $candidatePath
    if ($candidateHash -ne [string]$manifest.validated_candidate_sha256) {
        throw "[TASK-DEFINITION-TRANSACTION] candidate drift detected expected=$($manifest.validated_candidate_sha256) actual=$candidateHash"
    }

    $officialDirectory = Split-Path -Parent $officialPath
    $temporaryPath = Join-Path $officialDirectory ('.task-definition-promote-{0}.tmp' -f ([guid]::NewGuid().ToString('N')))
    $backupPath = Join-Path $transactionDir 'promotion-backup.json'
    try {
        [System.IO.File]::WriteAllBytes($temporaryPath, [System.IO.File]::ReadAllBytes($candidatePath))
        [System.IO.File]::Replace($temporaryPath, $officialPath, $backupPath, $true)
        $writtenHash = Get-Sha256 -Path $officialPath
        if ($writtenHash -ne $candidateHash) {
            throw "[TASK-DEFINITION-TRANSACTION] write verification hash mismatch expected=$candidateHash actual=$writtenHash"
        }
        $postCheckLog = Invoke-Checker -Name 'post-promote-syntax' -Arguments @{
            TaskDefinitionFile = $officialPath
            RepoRoot = $repoRoot
            Policy = 'enforce'
            SyntaxOnly = $true
        }
        $receipt = [ordered]@{
            schema = 'TASK_DEFINITION_REPAIR_PROMOTION_RECEIPT_V1'
            ticket_id = $TicketId
            official_path = $officialPath
            baseline_sha256 = [string]$manifest.baseline_sha256
            promoted_sha256 = $writtenHash
            validation_at = [string]$manifest.validation_at
            promoted_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            post_check_log = $postCheckLog
            success = $true
        }
        Write-JsonAtomically -Path $receiptPath -Value $receipt
        $manifest.promoted_sha256 = $writtenHash
        $manifest.promoted_at = [string]$receipt.promoted_at
        Set-ManifestState -Manifest $manifest -State 'promoted'
    }
    catch {
        Remove-Item -LiteralPath $receiptPath -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            [System.IO.File]::WriteAllBytes($officialPath, [System.IO.File]::ReadAllBytes($backupPath))
        }
        Set-ManifestState -Manifest $manifest -State 'promotion_failed' -Detail $_.Exception.Message
        throw
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }

    $candidateCleaned = $false
    $baselineCleaned = $false
    try {
        Remove-Item -LiteralPath $candidatePath -Force
        $candidateCleaned = $true
    }
    catch {
        Write-Output ("[TASK-DEFINITION-TRANSACTION] cleanup_warning=true file=candidate detail={0}" -f $_.Exception.Message)
    }
    try {
        Remove-Item -LiteralPath $baselinePath -Force
        $baselineCleaned = $true
    }
    catch {
        Write-Output ("[TASK-DEFINITION-TRANSACTION] cleanup_warning=true file=baseline detail={0}" -f $_.Exception.Message)
    }
    Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    Write-Output ("[TASK-DEFINITION-TRANSACTION] status=promoted ticket={0} promoted_sha256={1} candidate_cleaned={2} baseline_cleaned={3} receipt={4}" -f $TicketId, $writtenHash, $candidateCleaned.ToString().ToLowerInvariant(), $baselineCleaned.ToString().ToLowerInvariant(), $receiptPath)
    exit 0
}