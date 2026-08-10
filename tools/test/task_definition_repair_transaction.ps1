param(
    [Parameter(Mandatory = $true)][ValidateSet('Prepare', 'Inspect', 'Validate', 'Promote', 'Abandon', 'Quarantine')][string]$Mode,
    [Parameter(Mandatory = $true)][string]$TaskDefinitionFile,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$TicketId,
    [ValidateSet('A', 'B')][string]$Stage = 'A',
    [AllowEmptyString()][string]$RoundTag = '',
    [ValidateSet('', 'D1', 'D2', 'D3', 'D4')][string]$ValidateThroughRound = '',
    [ValidateRange(0, 256)][int]$OperationIndex = 0,
    [AllowEmptyString()][string]$ArtifactRoot = '',
    [AllowEmptyString()][string]$Reason = '',
    [switch]$ChainRounds
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$checkerPath = Join-Path $PSScriptRoot 'check_task_definition_static.ps1'
. (Join-Path $PSScriptRoot 'task_definition_target_registry.ps1')
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
$previewJsonPath = Join-Path $transactionDir 'operation-preview.json'
$previewTextPath = Join-Path $transactionDir 'operation-preview.txt'
$patchContextPath = Join-Path $transactionDir 'apply-patch-context.txt'

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-BytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function ConvertTo-RegistryBinding {
    param([Parameter(Mandatory = $true)][object]$Registry)

    return @($Registry.Targets | Sort-Object File | ForEach-Object {
        $exists = Test-Path -LiteralPath $_.FullPath -PathType Leaf
        [ordered]@{
            id = [string]$_.Id
            path = [string]$_.File
            kind = [string]$_.Kind
            lifecycle = [string]$_.Lifecycle
            baseline_exists = [bool]$exists
            baseline_sha256 = if ($exists) { Get-Sha256 -Path $_.FullPath } else { $null }
        }
    })
}

function Get-TaskRegistry {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Task
    )

    return Resolve-TaskDefinitionTargetRegistry -TaskDefinition $Task -TaskDefinitionPath $Path -RepositoryRoot $repoRoot
}

function Assert-RegistryBinding {
    param(
        [Parameter(Mandatory = $true)][object]$Manifest,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Task,
        [Parameter(Mandatory = $true)][string]$Role
    )

    $registry = Get-TaskRegistry -Path $Path -Task $Task
    $actualTargets = @($registry.Targets | Sort-Object File | ForEach-Object {
        [ordered]@{ id = [string]$_.Id; path = [string]$_.File; kind = [string]$_.Kind; lifecycle = [string]$_.Lifecycle }
    })
    $expectedTargets = @($Manifest.targets | ForEach-Object {
        [ordered]@{ id = [string]$_.id; path = [string]$_.path; kind = [string]$_.kind; lifecycle = [string]$_.lifecycle }
    })
    $actualJson = $actualTargets | ConvertTo-Json -Compress -Depth 8
    $expectedJson = $expectedTargets | ConvertTo-Json -Compress -Depth 8
    if ([string]$registry.SchemaVersion -ne [string]$Manifest.schema_version -or
        [string]$registry.TargetSetSha256 -ne [string]$Manifest.target_set_sha256 -or
        $actualJson -ne $expectedJson) {
        throw "[TASK-DEFINITION-TRANSACTION] target registry drift detected role=$Role"
    }
    return $registry
}

function Set-CanonicalTaskDefinitionEncoding {
    param([Parameter(Mandatory = $true)][string]$Path)

    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $text = $utf8.GetString([System.IO.File]::ReadAllBytes($Path))
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        $text = $text.Substring(1)
    }
    $text = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    [System.IO.File]::WriteAllText($Path, $text, [System.Text.UTF8Encoding]::new($true))
}

function Get-ValidationRoundSequence {
    param(
        [Parameter(Mandatory = $true)][string]$StartRound,
        [AllowEmptyString()][string]$ThroughRound = ''
    )

    $start = $StartRound.Trim().ToUpperInvariant()
    $through = $ThroughRound.Trim().ToUpperInvariant()
    if ($start -notmatch '^D[1-4]$') {
        throw '[TASK-DEFINITION-TRANSACTION] validation requires D1-D4 round binding'
    }
    if ([string]::IsNullOrWhiteSpace($through)) {
        return @($start)
    }

    $startNumber = [int]$start.Substring(1)
    $throughNumber = [int]$through.Substring(1)
    if ($throughNumber -lt $startNumber) {
        throw "[TASK-DEFINITION-TRANSACTION] validation range cannot move backward start=$start through=$through"
    }

    return @($startNumber..$throughNumber | ForEach-Object { "D$_" })
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

function Write-TextAtomically {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $temporaryPath = Join-Path $directory ('.task-definition-preview-{0}.tmp' -f ([guid]::NewGuid().ToString('N')))
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $Text, [System.Text.UTF8Encoding]::new($true))
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $backupPath = Join-Path $directory ('.task-definition-preview-{0}.bak' -f ([guid]::NewGuid().ToString('N')))
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

function ConvertTo-VisibleText {
    param([AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace("`r", '<CR>').Replace("`n", "<LF>`n").Replace("`t", '<TAB>')
}

function Get-LineNumber {
    param([string]$Text, [int]$Index)
    if ($Index -le 0) { return 1 }
    return 1 + ([regex]::Matches($Text.Substring(0, $Index), "`n")).Count
}

function Get-SourceExcerpt {
    param(
        [string[]]$Lines,
        [int]$LineNumber,
        [int]$Radius = 8
    )
    $start = [Math]::Max(1, $LineNumber - $Radius)
    $end = [Math]::Min($Lines.Count, $LineNumber + $Radius)
    $result = New-Object System.Collections.Generic.List[string]
    for ($line = $start; $line -le $end; $line++) {
        $result.Add(('{0,6}: {1}' -f $line, $Lines[$line - 1]))
    }
    return ($result -join "`n")
}

function Resolve-TaskTargetPath {
    param([Parameter(Mandatory = $true)][object]$Task)
    $targetFile = [string]$Task.targetFile
    if ([string]::IsNullOrWhiteSpace($targetFile)) {
        throw '[TASK-DEFINITION-TRANSACTION] preview targetFile is empty'
    }
    if ([System.IO.Path]::IsPathRooted($targetFile)) {
        return [System.IO.Path]::GetFullPath($targetFile)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $targetFile))
}

function Write-VxOperationPreview {
    param(
        [Parameter(Mandatory = $true)][object]$Manifest,
        [Parameter(Mandatory = $true)][object]$Task,
        [Parameter(Mandatory = $true)][object]$Registry,
        [Parameter(Mandatory = $true)][string]$EffectiveRound,
        [Parameter(Mandatory = $true)][int]$EffectiveOperation,
        [Parameter(Mandatory = $true)][object[]]$Operations
    )

    $slots = @{}
    foreach ($target in $Registry.Targets) {
        $exists = Test-Path -LiteralPath $target.FullPath -PathType Leaf
        $bytes = if ($exists) { [System.IO.File]::ReadAllBytes($target.FullPath) } else { $null }
        $slots[$target.Id] = [pscustomobject]@{
            Target = $target
            Exists = [bool]$exists
            Text = if ($exists) { [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes) } else { '' }
        }
    }

    $simulation = New-Object System.Collections.Generic.List[object]
    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::Singleline
    $regexTimeout = [TimeSpan]::FromMilliseconds(2000)
    for ($index = 0; $index -lt ($effectiveOperation - 1); $index++) {
        $operation = $Operations[$index]
        $operationType = if ($operation.PSObject.Properties.Name -contains 'type') { ([string]$operation.type).Trim().ToLowerInvariant() } else { 'regex-patch' }
        $targetId = if ($operation.PSObject.Properties.Name -contains 'target') { ([string]$operation.target).Trim() } else { [string]$Registry.DefaultTargetId }
        $slot = $slots[$targetId]
        $existsBefore = [bool]$slot.Exists
        $beforeBytes = if ($slot.Exists) { [System.Text.UTF8Encoding]::new($false).GetBytes([string]$slot.Text) } else { $null }
        $beforeHash = if ($slot.Exists) { Get-BytesSha256 -Bytes $beforeBytes } else { $null }
        $matchCount = $null
        $status = 'not-applied'
        $declaredContentHash = $null
        $calculatedContentHash = $null
        if ($operationType -eq 'create-file') {
            $content = [string]$operation.content
            $contentBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($content)
            $declaredContentHash = ([string]$operation.contentSha256).Trim().ToLowerInvariant()
            $calculatedContentHash = Get-BytesSha256 -Bytes $contentBytes
            if ($declaredContentHash -ne $calculatedContentHash) {
                $status = 'content-hash-mismatch'
            }
            elseif ($slot.Exists) {
                $status = if ((Get-BytesSha256 -Bytes $beforeBytes) -eq $calculatedContentHash) { 'already-exists' } else { 'already-exists-content-mismatch' }
            }
            else {
                $slot.Text = $content
                $slot.Exists = $true
                $status = 'created'
            }
        }
        else {
            $regex = [regex]::new([string]$operation.pattern, $regexOptions, $regexTimeout)
            $matches = $regex.Matches([string]$slot.Text)
            $matchCount = $matches.Count
            if ($matches.Count -eq 1) {
                $slot.Text = $regex.Replace([string]$slot.Text, [string]$operation.replacement, 1)
                $status = 'applied'
            }
            elseif ($matches.Count -eq 0) {
                foreach ($marker in @($operation.idempotentContains | ForEach-Object { [string]$_ })) {
                    if (-not [string]::IsNullOrWhiteSpace($marker) -and ([string]$slot.Text).Contains($marker)) {
                        $status = 'idempotent-marker-found'
                        break
                    }
                }
            }
        }
        $afterBytes = if ($slot.Exists) { [System.Text.UTF8Encoding]::new($false).GetBytes([string]$slot.Text) } else { $null }
        $simulation.Add([ordered]@{
            operation_index = $index + 1
            type = $operationType
            target_id = $targetId
            target_path = [string]$slot.Target.File
            target_kind = [string]$slot.Target.Kind
            target_lifecycle = [string]$slot.Target.Lifecycle
            exists_before = $existsBefore
            exists_after = [bool]$slot.Exists
            target_sha256_before = $beforeHash
            target_sha256_after = if ($slot.Exists) { Get-BytesSha256 -Bytes $afterBytes } else { $null }
            match_count = $matchCount
            create_content_sha256_declared = $declaredContentHash
            create_content_sha256_calculated = $calculatedContentHash
            status = $status
        })
        if ($status -in @('not-applied', 'content-hash-mismatch', 'already-exists-content-mismatch')) { break }
    }

    $targetOperation = $Operations[$EffectiveOperation - 1]
    $targetType = if ($targetOperation.PSObject.Properties.Name -contains 'type') { ([string]$targetOperation.type).Trim().ToLowerInvariant() } else { 'regex-patch' }
    $targetId = if ($targetOperation.PSObject.Properties.Name -contains 'target') { ([string]$targetOperation.target).Trim() } else { [string]$Registry.DefaultTargetId }
    $targetSlot = $slots[$targetId]
    $existsBefore = [bool]$targetSlot.Exists
    $beforeBytes = if ($targetSlot.Exists) { [System.Text.UTF8Encoding]::new($false).GetBytes([string]$targetSlot.Text) } else { $null }
    $beforeHash = if ($targetSlot.Exists) { Get-BytesSha256 -Bytes $beforeBytes } else { $null }
    $targetMatches = @()
    $matchDetails = New-Object System.Collections.Generic.List[object]
    $postReplacementRemaining = $null
    $replacementPreview = ''
    $declaredContentHash = $null
    $calculatedContentHash = $null
    $createStatus = $null
    $targetPattern = ''
    $targetReplacement = ''
    if ($targetType -eq 'create-file') {
        $targetReplacement = [string]$targetOperation.content
        $contentBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($targetReplacement)
        $declaredContentHash = ([string]$targetOperation.contentSha256).Trim().ToLowerInvariant()
        $calculatedContentHash = Get-BytesSha256 -Bytes $contentBytes
        if ($declaredContentHash -ne $calculatedContentHash) { $createStatus = 'content-hash-mismatch' }
        elseif ($targetSlot.Exists) { $createStatus = if ($beforeHash -eq $calculatedContentHash) { 'already-exists' } else { 'already-exists-content-mismatch' } }
        else { $targetSlot.Text = $targetReplacement; $targetSlot.Exists = $true; $createStatus = 'created' }
    }
    else {
        $targetPattern = [string]$targetOperation.pattern
        $targetReplacement = [string]$targetOperation.replacement
        $targetRegex = [regex]::new($targetPattern, $regexOptions, $regexTimeout)
        $targetMatches = @($targetRegex.Matches([string]$targetSlot.Text))
        $sourceLines = [regex]::Split([string]$targetSlot.Text, "\r?\n")
        foreach ($match in $targetMatches) {
            $lineNumber = Get-LineNumber -Text ([string]$targetSlot.Text) -Index $match.Index
            $matchDetails.Add([ordered]@{ line = $lineNumber; index = $match.Index; length = $match.Length; excerpt = Get-SourceExcerpt -Lines $sourceLines -LineNumber $lineNumber })
        }
        if ($targetMatches.Count -eq 1) {
            $targetSlot.Text = $targetRegex.Replace([string]$targetSlot.Text, $targetReplacement, 1)
            $postReplacementRemaining = $targetRegex.Matches([string]$targetSlot.Text).Count
            $replacementLine = Get-LineNumber -Text ([string]$targetSlot.Text) -Index $targetMatches[0].Index
            $replacementPreview = Get-SourceExcerpt -Lines ([regex]::Split([string]$targetSlot.Text, "\r?\n")) -LineNumber $replacementLine -Radius 12
        }
    }
    $afterBytes = if ($targetSlot.Exists) { [System.Text.UTF8Encoding]::new($false).GetBytes([string]$targetSlot.Text) } else { $null }
    $candidateHash = Get-Sha256 -Path $candidatePath
    $preview = [ordered]@{
        schema = 'TASK_DEFINITION_OPERATION_PREVIEW_VX1'
        generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        ticket_id = $TicketId
        json_path = ('rounds.{0}.operations[{1}]' -f $EffectiveRound, ($EffectiveOperation - 1))
        round = $EffectiveRound
        operation_index = $EffectiveOperation
        operation_type = $targetType
        candidate_path = $candidatePath
        candidate_sha256 = $candidateHash
        baseline_sha256 = [string]$Manifest.baseline_sha256
        target_set_sha256 = [string]$Manifest.target_set_sha256
        target_id = $targetId
        target_path = [string]$targetSlot.Target.File
        target_kind = [string]$targetSlot.Target.Kind
        target_lifecycle = [string]$targetSlot.Target.Lifecycle
        target_exists_before = $existsBefore
        target_exists_after = [bool]$targetSlot.Exists
        target_sha256_before = $beforeHash
        target_sha256_after = if ($targetSlot.Exists) { Get-BytesSha256 -Bytes $afterBytes } else { $null }
        prerequisite_simulation = $simulation.ToArray()
        pattern_match_count = if ($targetType -eq 'create-file') { $null } else { $targetMatches.Count }
        matches = $matchDetails.ToArray()
        post_replacement_pattern_match_count = $postReplacementRemaining
        create_content_sha256_declared = $declaredContentHash
        create_content_sha256_calculated = $calculatedContentHash
        create_status = $createStatus
        replacement_contains_actual_newline = ($targetReplacement.Contains("`n") -or $targetReplacement.Contains("`r"))
        replacement_contains_actual_tab = $targetReplacement.Contains("`t")
        replacement_contains_literal_backslash_n = $targetReplacement.Contains('\n')
        replacement_contains_literal_backslash_t = $targetReplacement.Contains('\t')
        possible_double_escape = (($targetReplacement.Contains('\n') -or $targetReplacement.Contains('\t')) -and -not ($targetReplacement.Contains("`n") -or $targetReplacement.Contains("`t")))
    }
    Write-JsonAtomically -Path $previewJsonPath -Value $preview
    $textSections = @(
        '[BINDING]',
        ('schema={0}' -f $preview.schema),
        ('candidate_sha256={0}' -f $candidateHash),
        ('target_set_sha256={0}' -f $preview.target_set_sha256),
        ('target_id={0}' -f $targetId),
        ('target_path={0}' -f $preview.target_path),
        ('target_kind={0}' -f $preview.target_kind),
        ('target_lifecycle={0}' -f $preview.target_lifecycle),
        ('target_exists_before={0}' -f ([string]$preview.target_exists_before).ToLowerInvariant()),
        ('target_exists_after={0}' -f ([string]$preview.target_exists_after).ToLowerInvariant()),
        ('target_sha256_before={0}' -f $preview.target_sha256_before),
        ('target_sha256_after={0}' -f $preview.target_sha256_after),
        ('create_content_sha256_declared={0}' -f $preview.create_content_sha256_declared),
        ('create_content_sha256_calculated={0}' -f $preview.create_content_sha256_calculated),
        ('create_status={0}' -f $preview.create_status),
        '', '[PATTERN DECODED]', (ConvertTo-VisibleText -Text $targetPattern),
        '', '[REPLACEMENT DECODED]', (ConvertTo-VisibleText -Text $targetReplacement),
        '', '[SOURCE MATCHES]', (($matchDetails | ForEach-Object { "line=$($_.line)`n$($_.excerpt)" }) -join "`n---`n"),
        '', '[POST REPLACEMENT LOCAL PREVIEW]', $replacementPreview, ''
    )
    Write-TextAtomically -Path $previewTextPath -Text (($textSections -join "`n") + "`n")
    $previousOperation = if ($EffectiveOperation -gt 1) { $Operations[$EffectiveOperation - 2] } else { $null }
    $nextOperation = if ($EffectiveOperation -lt $Operations.Count) { $Operations[$EffectiveOperation] } else { $null }
    $patchContext = @(
        '# Read-only apply_patch context. candidate.json remains the only editable source.',
        ('candidate_sha256={0}' -f $candidateHash), ('json_path={0}' -f $preview.json_path), '',
        '[PREVIOUS OPERATION]', $(if ($null -eq $previousOperation) { '<none>' } else { $previousOperation | ConvertTo-Json -Depth 16 }), '',
        '[TARGET OPERATION]', ($targetOperation | ConvertTo-Json -Depth 16), '',
        '[NEXT OPERATION]', $(if ($null -eq $nextOperation) { '<none>' } else { $nextOperation | ConvertTo-Json -Depth 16 }), ''
    )
    Write-TextAtomically -Path $patchContextPath -Text (($patchContext -join "`n") + "`n")
    $Manifest.preview_candidate_sha256 = $candidateHash
    $Manifest.preview_baseline_sha256 = [string]$Manifest.baseline_sha256
    $Manifest.preview_target_sha256 = [string]$preview.target_sha256_before
    $Manifest.preview_generated_at = [string]$preview.generated_at
    $Manifest.preview_stale = $false
    $Manifest.preview_files = @($previewJsonPath, $previewTextPath, $patchContextPath)
    Write-JsonAtomically -Path $manifestPath -Value $Manifest
    return $preview
}

function Write-OperationPreview {
    param([Parameter(Mandatory = $true)][object]$Manifest)

    if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
        throw '[TASK-DEFINITION-TRANSACTION] preview candidate task definition missing'
    }
    $task = Get-Content -LiteralPath $candidatePath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    $effectiveRound = ([string]$Manifest.round).Trim().ToUpperInvariant()
    $effectiveOperation = [int]$Manifest.operation_index
    if ([string]::IsNullOrWhiteSpace($effectiveRound) -or $effectiveOperation -le 0) {
        throw '[TASK-DEFINITION-TRANSACTION] preview requires round and operation bindings'
    }
    $roundProperty = $task.rounds.PSObject.Properties[$effectiveRound]
    if ($null -eq $roundProperty) {
        throw "[TASK-DEFINITION-TRANSACTION] preview round not found: $effectiveRound"
    }
    $operations = @($roundProperty.Value.operations)
    if ($effectiveOperation -gt $operations.Count) {
        throw "[TASK-DEFINITION-TRANSACTION] preview operation out of range op=$effectiveOperation total=$($operations.Count)"
    }

    $registry = Get-TaskRegistry -Path $candidatePath -Task $task
    if ($registry.SchemaVersion -eq 'vx-draft') {
        return Write-VxOperationPreview -Manifest $Manifest -Task $task -Registry $registry -EffectiveRound $effectiveRound -EffectiveOperation $effectiveOperation -Operations $operations
    }

    $targetPath = Resolve-TaskTargetPath -Task $task
    if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
        throw "[TASK-DEFINITION-TRANSACTION] preview target file not found: $targetPath"
    }
    $sourceText = [System.IO.File]::ReadAllText($targetPath)
    $workingText = $sourceText
    $simulation = New-Object System.Collections.Generic.List[object]
    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::Singleline
    $regexTimeout = [TimeSpan]::FromMilliseconds(2000)

    for ($index = 0; $index -lt ($effectiveOperation - 1); $index++) {
        $operation = $operations[$index]
        $pattern = [string]$operation.pattern
        $replacement = [string]$operation.replacement
        $regex = [regex]::new($pattern, $regexOptions, $regexTimeout)
        $operationMatches = $regex.Matches($workingText)
        $status = 'not-applied'
        if ($operationMatches.Count -eq 1) {
            $workingText = $regex.Replace($workingText, $replacement, 1)
            $status = 'applied'
        }
        elseif ($operationMatches.Count -eq 0) {
            $markers = @($operation.idempotentContains | ForEach-Object { [string]$_ })
            $markerFound = $false
            foreach ($marker in $markers) {
                if (-not [string]::IsNullOrWhiteSpace($marker) -and $workingText.Contains($marker)) {
                    $markerFound = $true
                    break
                }
            }
            if ($markerFound) { $status = 'idempotent-marker-found' }
        }
        $simulation.Add([ordered]@{
            operation_index = $index + 1
            match_count = $operationMatches.Count
            status = $status
        })
        if ($status -eq 'not-applied') { break }
    }

    $targetOperation = $operations[$effectiveOperation - 1]
    $targetPattern = [string]$targetOperation.pattern
    $targetReplacement = [string]$targetOperation.replacement
    $targetRegex = [regex]::new($targetPattern, $regexOptions, $regexTimeout)
    $targetMatches = $targetRegex.Matches($workingText)
    $sourceLines = [regex]::Split($workingText, "\r?\n")
    $matchDetails = New-Object System.Collections.Generic.List[object]
    foreach ($match in $targetMatches) {
        $lineNumber = Get-LineNumber -Text $workingText -Index $match.Index
        $matchDetails.Add([ordered]@{
            line = $lineNumber
            index = $match.Index
            length = $match.Length
            excerpt = Get-SourceExcerpt -Lines $sourceLines -LineNumber $lineNumber
        })
    }

    $postReplacementRemaining = $null
    $replacementPreview = ''
    if ($targetMatches.Count -eq 1) {
        $effectiveText = $targetRegex.Replace($workingText, $targetReplacement, 1)
        $postReplacementRemaining = $targetRegex.Matches($effectiveText).Count
        $replacementLine = Get-LineNumber -Text $effectiveText -Index $targetMatches[0].Index
        $replacementPreview = Get-SourceExcerpt -Lines ([regex]::Split($effectiveText, "\r?\n")) -LineNumber $replacementLine -Radius 12
    }

    $candidateHash = Get-Sha256 -Path $candidatePath
    $preview = [ordered]@{
        schema = 'TASK_DEFINITION_OPERATION_PREVIEW_V1'
        generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        ticket_id = $TicketId
        json_path = ('rounds.{0}.operations[{1}]' -f $effectiveRound, ($effectiveOperation - 1))
        round = $effectiveRound
        operation_index = $effectiveOperation
        candidate_path = $candidatePath
        candidate_sha256 = $candidateHash
        baseline_sha256 = [string]$Manifest.baseline_sha256
        target_path = $targetPath
        target_sha256 = Get-Sha256 -Path $targetPath
        prerequisite_simulation = $simulation.ToArray()
        pattern_match_count = $targetMatches.Count
        matches = $matchDetails.ToArray()
        post_replacement_pattern_match_count = $postReplacementRemaining
        replacement_contains_actual_newline = ($targetReplacement.Contains("`n") -or $targetReplacement.Contains("`r"))
        replacement_contains_actual_tab = $targetReplacement.Contains("`t")
        replacement_contains_literal_backslash_n = $targetReplacement.Contains('\n')
        replacement_contains_literal_backslash_t = $targetReplacement.Contains('\t')
        possible_double_escape = (($targetReplacement.Contains('\n') -or $targetReplacement.Contains('\t')) -and -not ($targetReplacement.Contains("`n") -or $targetReplacement.Contains("`t")))
    }
    Write-JsonAtomically -Path $previewJsonPath -Value $preview

    $textSections = @(
        '[BINDING]',
        ('candidate_sha256={0}' -f $candidateHash),
        ('baseline_sha256={0}' -f $Manifest.baseline_sha256),
        ('target_sha256={0}' -f $preview.target_sha256),
        ('json_path={0}' -f $preview.json_path),
        ('pattern_match_count={0}' -f $targetMatches.Count),
        ('post_replacement_pattern_match_count={0}' -f $postReplacementRemaining),
        ('possible_double_escape={0}' -f ([string]$preview.possible_double_escape).ToLowerInvariant()),
        '',
        '[PATTERN DECODED]',
        (ConvertTo-VisibleText -Text $targetPattern),
        '',
        '[REPLACEMENT DECODED]',
        (ConvertTo-VisibleText -Text $targetReplacement),
        '',
        '[SOURCE MATCHES]',
        (($matchDetails | ForEach-Object { "line=$($_.line)`n$($_.excerpt)" }) -join "`n---`n"),
        '',
        '[POST REPLACEMENT LOCAL PREVIEW]',
        $replacementPreview,
        ''
    )
    Write-TextAtomically -Path $previewTextPath -Text (($textSections -join "`n") + "`n")

    $previousOperation = if ($effectiveOperation -gt 1) { $operations[$effectiveOperation - 2] } else { $null }
    $nextOperation = if ($effectiveOperation -lt $operations.Count) { $operations[$effectiveOperation] } else { $null }
    $patchContext = @(
        '# Read-only apply_patch context. candidate.json remains the only editable source.',
        ('candidate_sha256={0}' -f $candidateHash),
        ('json_path={0}' -f $preview.json_path),
        '',
        '[PREVIOUS OPERATION]',
        $(if ($null -eq $previousOperation) { '<none>' } else { $previousOperation | ConvertTo-Json -Depth 16 }),
        '',
        '[TARGET OPERATION]',
        ($targetOperation | ConvertTo-Json -Depth 16),
        '',
        '[NEXT OPERATION]',
        $(if ($null -eq $nextOperation) { '<none>' } else { $nextOperation | ConvertTo-Json -Depth 16 }),
        ''
    )
    Write-TextAtomically -Path $patchContextPath -Text (($patchContext -join "`n") + "`n")

    $Manifest.preview_candidate_sha256 = $candidateHash
    $Manifest.preview_baseline_sha256 = [string]$Manifest.baseline_sha256
    $Manifest.preview_target_sha256 = [string]$preview.target_sha256
    $Manifest.preview_generated_at = [string]$preview.generated_at
    $Manifest.preview_stale = $false
    $Manifest.preview_files = @($previewJsonPath, $previewTextPath, $patchContextPath)
    Write-JsonAtomically -Path $manifestPath -Value $Manifest
    return $preview
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
    Set-CanonicalTaskDefinitionEncoding -Path $candidatePath
    $baselineHash = Get-Sha256 -Path $officialPath
    $preparedCandidateHash = Get-Sha256 -Path $candidatePath
    $officialTask = Get-Content -LiteralPath $officialPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    $officialRegistry = Get-TaskRegistry -Path $officialPath -Task $officialTask
    $registryTargets = ConvertTo-RegistryBinding -Registry $officialRegistry
    if ($ChainRounds.IsPresent -and ($RoundTag -notmatch '^D[1-4]$' -or $ValidateThroughRound -ne 'D4')) {
        throw '[TASK-DEFINITION-TRANSACTION] ChainRounds Prepare requires RoundTag D1-D4 and ValidateThroughRound D4'
    }
    $roundSequence = if ([string]::IsNullOrWhiteSpace($RoundTag)) { @() } else { @(Get-ValidationRoundSequence -StartRound $RoundTag -ThroughRound $ValidateThroughRound) }
    $manifest = [ordered]@{
        schema = 'TASK_DEFINITION_REPAIR_TRANSACTION_V1'
        schema_version = [string]$officialRegistry.SchemaVersion
        target_set_sha256 = [string]$officialRegistry.TargetSetSha256
        targets = @($registryTargets)
        ticket_id = $TicketId
        stage = $Stage
        round = $RoundTag.Trim().ToUpperInvariant()
        round_sequence = @($roundSequence)
        chain_rounds = $ChainRounds.IsPresent
        operation_index = $OperationIndex
        official_path = $officialPath
        baseline_path = $baselinePath
        candidate_path = $candidatePath
        baseline_sha256 = $baselineHash
        prepared_candidate_sha256 = $preparedCandidateHash
        validated_candidate_sha256 = ''
        validated_rounds = @()
        validation_at = ''
        validation_logs = @()
        preview_candidate_sha256 = ''
        preview_baseline_sha256 = ''
        preview_target_sha256 = ''
        preview_generated_at = ''
        preview_stale = $true
        preview_files = @()
        promoted_sha256 = ''
        promoted_at = ''
        state = 'prepared'
        created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        detail = ''
    }
    Write-JsonAtomically -Path $manifestPath -Value $manifest
    if (-not [string]::IsNullOrWhiteSpace([string]$manifest.round) -and [int]$manifest.operation_index -gt 0) {
        try {
            $preview = Write-OperationPreview -Manifest $manifest
            Write-Output ("[TASK-DEFINITION-TRANSACTION] status=prepared ticket={0} candidate={1} baseline_sha256={2} preview={3} pattern_match_count={4}" -f $TicketId, $candidatePath, $baselineHash, $previewJsonPath, $preview.pattern_match_count)
        }
        catch {
            $manifest.preview_stale = $true
            $manifest.detail = "preview unavailable: $($_.Exception.Message)"
            Write-JsonAtomically -Path $manifestPath -Value $manifest
            Write-Output ("[TASK-DEFINITION-TRANSACTION] status=prepared ticket={0} candidate={1} baseline_sha256={2} preview_unavailable=true detail={3}" -f $TicketId, $candidatePath, $baselineHash, $_.Exception.Message)
        }
    }
    else {
        Write-Output ("[TASK-DEFINITION-TRANSACTION] status=prepared ticket={0} candidate={1} baseline_sha256={2} preview_unavailable=true detail=round-and-operation-binding-required" -f $TicketId, $candidatePath, $baselineHash)
    }
    exit 0
}

$manifest = Read-Manifest

if ($Mode -eq 'Abandon' -or $Mode -eq 'Quarantine') {
    $state = if ($Mode -eq 'Quarantine') { 'quarantined' } else { 'abandoned' }
    Set-ManifestState -Manifest $manifest -State $state -Detail $Reason
    Write-Output ("[TASK-DEFINITION-TRANSACTION] status={0} ticket={1} candidate_retained=true" -f $state, $TicketId)
    exit 0
}

if ($Mode -eq 'Inspect') {
    Assert-BaselineBinding -Manifest $manifest
    if ($OperationIndex -gt 0 -and [int]$manifest.operation_index -eq 0) {
        if (-not [string]::IsNullOrWhiteSpace($RoundTag) -and $RoundTag.Trim().ToUpperInvariant() -ne [string]$manifest.round) {
            throw '[TASK-DEFINITION-TRANSACTION] Inspect operation binding round mismatch'
        }
        $manifest.operation_index = $OperationIndex
        $manifest.updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Write-JsonAtomically -Path $manifestPath -Value $manifest
    }
    elseif ($OperationIndex -gt 0 -and [int]$manifest.operation_index -ne $OperationIndex) {
        throw '[TASK-DEFINITION-TRANSACTION] Inspect operation binding conflicts with manifest'
    }
    $preview = Write-OperationPreview -Manifest $manifest
    Write-Output ("[TASK-DEFINITION-TRANSACTION] status=inspected ticket={0} candidate_sha256={1} preview={2} pattern_match_count={3} post_replacement_pattern_match_count={4}" -f $TicketId, $preview.candidate_sha256, $previewJsonPath, $preview.pattern_match_count, $preview.post_replacement_pattern_match_count)
    exit 0
}

if ([string]$manifest.state -in @('abandoned', 'quarantined')) {
    throw "[TASK-DEFINITION-TRANSACTION] terminal transaction state blocks mode=$Mode state=$($manifest.state)"
}

if ($Mode -eq 'Validate') {
    try {
        Assert-BaselineBinding -Manifest $manifest
        if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            throw '[TASK-DEFINITION-TRANSACTION] candidate task definition missing'
        }
        Set-CanonicalTaskDefinitionEncoding -Path $candidatePath
        $candidateTask = Get-Content -LiteralPath $candidatePath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
        $officialTask = Get-Content -LiteralPath $officialPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
        [void](Assert-RegistryBinding -Manifest $manifest -Path $officialPath -Task $officialTask -Role 'official')
        $candidateRegistry = Assert-RegistryBinding -Manifest $manifest -Path $candidatePath -Task $candidateTask -Role 'candidate'
        $currentCandidateHash = Get-Sha256 -Path $candidatePath
        $manifest.preview_stale = ($currentCandidateHash -ne [string]$manifest.preview_candidate_sha256)
        Write-JsonAtomically -Path $manifestPath -Value $manifest
        Write-Output ("[TASK-DEFINITION-TRANSACTION] preview_stale={0} preview_candidate_sha256={1} current_candidate_sha256={2}" -f $manifest.preview_stale.ToString().ToLowerInvariant(), $manifest.preview_candidate_sha256, $currentCandidateHash)
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
        $storedThroughRound = ''
        if ([string]::IsNullOrWhiteSpace($ValidateThroughRound) -and
            $manifest.PSObject.Properties.Name -contains 'round_sequence' -and
            @($manifest.round_sequence).Count -gt 0) {
            $storedThroughRound = [string]@($manifest.round_sequence)[-1]
        }
        $effectiveThroughRound = if ([string]::IsNullOrWhiteSpace($ValidateThroughRound)) { $storedThroughRound } else { $ValidateThroughRound }
        $roundSequence = @(Get-ValidationRoundSequence -StartRound $effectiveRound -ThroughRound $effectiveThroughRound)
        $manifestChainRounds = ($manifest.PSObject.Properties.Name -contains 'chain_rounds' -and [bool]$manifest.chain_rounds)
        if ($ChainRounds.IsPresent -ne $manifestChainRounds) {
            throw "[TASK-DEFINITION-TRANSACTION] ChainRounds binding mismatch prepared=$manifestChainRounds requested=$($ChainRounds.IsPresent)"
        }
        if ($manifestChainRounds -and $effectiveThroughRound -ne 'D4') {
            throw '[TASK-DEFINITION-TRANSACTION] ChainRounds Validate requires ValidateThroughRound D4'
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
        $roundLogs = New-Object System.Collections.Generic.List[string]
        if ($manifestChainRounds) {
            $chainRoundLog = Invoke-Checker -Name 'chain-rounds' -Arguments @{
                TaskDefinitionFile = $candidatePath
                RepoRoot = $repoRoot
                Policy = 'enforce'
                RoundTag = $effectiveRound
                ChainRounds = $true
            }
            $roundLogs.Add($chainRoundLog)
        }
        else {
            foreach ($validationRound in $roundSequence) {
                $roundLog = Invoke-Checker -Name ("round-{0}" -f $validationRound.ToLowerInvariant()) -Arguments @{
                    TaskDefinitionFile = $candidatePath
                    RepoRoot = $repoRoot
                    Policy = 'enforce'
                    RoundTag = $validationRound
                }
                $roundLogs.Add($roundLog)
            }
        }
        $manifest.round_sequence = @($roundSequence)
        $manifest.validated_rounds = @($roundSequence)
        $manifest.validated_candidate_sha256 = Get-Sha256 -Path $candidatePath
        $manifest.validation_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $manifest.validation_logs = @(@($syntaxLog, $focusedLog) + @($roundLogs) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        Set-ManifestState -Manifest $manifest -State 'validated'
        Write-Output ("[TASK-DEFINITION-TRANSACTION] status=validated ticket={0} candidate_sha256={1} validated_rounds={2} preview_stale={3}" -f $TicketId, $manifest.validated_candidate_sha256, ([string]::Join(',', @($manifest.validated_rounds))), $manifest.preview_stale.ToString().ToLowerInvariant())
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
    $expectedValidatedRounds = @($manifest.round_sequence | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() })
    $actualValidatedRounds = @($manifest.validated_rounds | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() })
    if ($expectedValidatedRounds.Count -lt 1 -or
        [string]::Join(',', $actualValidatedRounds) -ne [string]::Join(',', $expectedValidatedRounds)) {
        throw ("[TASK-DEFINITION-TRANSACTION] promote validation coverage incomplete expected={0} actual={1}" -f
            ([string]::Join(',', $expectedValidatedRounds)),
            ([string]::Join(',', $actualValidatedRounds)))
    }
    $manifestChainRounds = ($manifest.PSObject.Properties.Name -contains 'chain_rounds' -and [bool]$manifest.chain_rounds)
    if ($manifestChainRounds -and $expectedValidatedRounds[-1] -ne 'D4') {
        throw "[TASK-DEFINITION-TRANSACTION] promote chain coverage must end at D4 actual=$([string]::Join(',', $expectedValidatedRounds))"
    }
    Assert-BaselineBinding -Manifest $manifest
    if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
        throw '[TASK-DEFINITION-TRANSACTION] candidate task definition missing'
    }
    $candidateHash = Get-Sha256 -Path $candidatePath
    if ($candidateHash -ne [string]$manifest.validated_candidate_sha256) {
        throw "[TASK-DEFINITION-TRANSACTION] candidate drift detected expected=$($manifest.validated_candidate_sha256) actual=$candidateHash"
    }
    $candidateTask = Get-Content -LiteralPath $candidatePath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    $officialTask = Get-Content -LiteralPath $officialPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    [void](Assert-RegistryBinding -Manifest $manifest -Path $officialPath -Task $officialTask -Role 'official')
    [void](Assert-RegistryBinding -Manifest $manifest -Path $candidatePath -Task $candidateTask -Role 'candidate')

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
            schema_version = [string]$manifest.schema_version
            target_set_sha256 = [string]$manifest.target_set_sha256
            targets = @($manifest.targets)
            official_path = $officialPath
            baseline_sha256 = [string]$manifest.baseline_sha256
            promoted_sha256 = $writtenHash
            round_sequence = @($manifest.round_sequence)
            validated_rounds = @($manifest.validated_rounds)
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