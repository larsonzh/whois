Set-StrictMode -Version Latest

function Get-TaskDefinitionSha256Text {
    param([Parameter(Mandatory = $true)][string]$Text)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([System.BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Resolve-TaskDefinitionTargetRegistry {
    param(
        [Parameter(Mandatory = $true)][object]$TaskDefinition,
        [Parameter(Mandatory = $true)][string]$TaskDefinitionPath,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [switch]$AllowMissingExistingTargets
    )

    $repositoryRootFull = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([char]92, [char]47)
    $schemaRaw = if ($TaskDefinition.PSObject.Properties.Name -contains 'schemaVersion') { [string]$TaskDefinition.schemaVersion } else { '1' }
    $schemaVersion = $schemaRaw.Trim().ToLowerInvariant()
    if ($schemaVersion -eq '1') {
        if (-not ($TaskDefinition.PSObject.Properties.Name -contains 'targetFile') -or
            [string]::IsNullOrWhiteSpace([string]$TaskDefinition.targetFile)) {
            throw "task definition missing targetFile: $TaskDefinitionPath"
        }

        $targetFile = ([string]$TaskDefinition.targetFile).Trim().Replace('\', '/')
        $targetFullPath = if ([System.IO.Path]::IsPathRooted($targetFile)) {
            [System.IO.Path]::GetFullPath($targetFile)
        }
        else {
            [System.IO.Path]::GetFullPath((Join-Path $repositoryRootFull $targetFile))
        }
        $target = [pscustomobject]@{
            Id = 'legacy_target'
            File = $targetFile
            FullPath = $targetFullPath
            Kind = 'text'
            Lifecycle = 'existing'
        }
        return [pscustomobject]@{
            SchemaVersion = '1'
            Targets = @($target)
            DefaultTargetId = $target.Id
            PrimaryTarget = $target
            TargetSetSha256 = ''
        }
    }

    if ($schemaVersion -ne 'vx-draft') {
        throw "unsupported task definition schemaVersion=$schemaRaw in $TaskDefinitionPath"
    }
    if (-not ($TaskDefinition.PSObject.Properties.Name -contains 'targetFiles')) {
        throw "vx-draft task definition missing targetFiles: $TaskDefinitionPath"
    }

    $targetEntries = @($TaskDefinition.targetFiles)
    if ($targetEntries.Count -eq 0) {
        throw "vx-draft targetFiles is empty: $TaskDefinitionPath"
    }

    $targets = New-Object 'System.Collections.Generic.List[object]'
    $targetsById = @{}
    $paths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $targetEntries) {
        if ($null -eq $entry) {
            throw "vx-draft targetFiles contains null entry: $TaskDefinitionPath"
        }
        $id = if ($entry.PSObject.Properties.Name -contains 'id') { ([string]$entry.id).Trim() } else { '' }
        if ($id -notmatch '^[a-z][a-z0-9_]{0,63}$') {
            throw "vx-draft target id is invalid: '$id'"
        }
        if ($targetsById.ContainsKey($id)) {
            throw "vx-draft duplicate target id: $id"
        }
        if (-not ($entry.PSObject.Properties.Name -contains 'file')) {
            throw "vx-draft target '$id' missing file"
        }
        $file = ([string]$entry.file).Trim().Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($file) -or [System.IO.Path]::IsPathRooted($file) -or
            @($file.Split('/') | Where-Object { $_ -eq '..' }).Count -gt 0) {
            throw "vx-draft target '$id' has unsafe file path: $file"
        }
        $fullPath = [System.IO.Path]::GetFullPath((Join-Path $repositoryRootFull $file))
        $repositoryPrefix = $repositoryRootFull + [System.IO.Path]::DirectorySeparatorChar
        if (-not $fullPath.StartsWith($repositoryPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "vx-draft target '$id' escapes repository: $file"
        }
        $relativePath = $fullPath.Substring($repositoryPrefix.Length).Replace('\', '/')
        if (-not $paths.Add($relativePath)) {
            throw "vx-draft duplicate target path: $relativePath"
        }

        $kind = if ($entry.PSObject.Properties.Name -contains 'kind') { ([string]$entry.kind).Trim().ToLowerInvariant() } else { 'text' }
        if ($kind -notin @('c-source', 'c-header', 'text')) {
            throw "vx-draft target '$id' has invalid kind: $kind"
        }
        $lifecycle = if ($entry.PSObject.Properties.Name -contains 'lifecycle') { ([string]$entry.lifecycle).Trim().ToLowerInvariant() } else { 'existing' }
        if ($lifecycle -notin @('existing', 'create')) {
            throw "vx-draft target '$id' has invalid lifecycle: $lifecycle"
        }
        if ($lifecycle -eq 'existing' -and -not $AllowMissingExistingTargets.IsPresent) {
            if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
                throw "vx-draft existing target '$id' not found: $relativePath"
            }
        }
        else {
            $parent = Split-Path -Parent $fullPath
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                throw "vx-draft create target '$id' parent not found: $relativePath"
            }
            if ((Test-Path -LiteralPath $fullPath) -and -not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
                throw "vx-draft create target '$id' is not a file: $relativePath"
            }
        }

        $target = [pscustomobject]@{
            Id = $id
            File = $relativePath
            FullPath = $fullPath
            Kind = $kind
            Lifecycle = $lifecycle
        }
        $targets.Add($target)
        $targetsById[$id] = $target
    }

    $defaultTargetId = if ($TaskDefinition.PSObject.Properties.Name -contains 'defaultTarget') { ([string]$TaskDefinition.defaultTarget).Trim() } else { '' }
    if ([string]::IsNullOrWhiteSpace($defaultTargetId) -and $targets.Count -eq 1) {
        $defaultTargetId = $targets[0].Id
    }
    if (-not [string]::IsNullOrWhiteSpace($defaultTargetId) -and -not $targetsById.ContainsKey($defaultTargetId)) {
        throw "vx-draft defaultTarget '$defaultTargetId' not found in targetFiles"
    }
    $primaryTarget = if ([string]::IsNullOrWhiteSpace($defaultTargetId)) { $null } else { $targetsById[$defaultTargetId] }
    if ($TaskDefinition.PSObject.Properties.Name -contains 'targetFile' -and
        -not [string]::IsNullOrWhiteSpace([string]$TaskDefinition.targetFile)) {
        if ($null -eq $primaryTarget) {
            throw 'vx-draft targetFile requires a resolvable defaultTarget'
        }
        $legacyFile = ([string]$TaskDefinition.targetFile).Trim().Replace('\', '/')
        if ($legacyFile -ne $primaryTarget.File) {
            throw "vx-draft targetFile does not match defaultTarget file: targetFile=$legacyFile default=$($primaryTarget.File)"
        }
    }

    $createCounts = @{}
    $createdTargets = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $ownedMarkers = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($target in $targets) {
        if ($target.Lifecycle -eq 'existing' -or (Test-Path -LiteralPath $target.FullPath -PathType Leaf)) {
            [void]$createdTargets.Add($target.Id)
        }
        $createCounts[$target.Id] = 0
    }
    foreach ($roundProperty in @($TaskDefinition.rounds.PSObject.Properties | Sort-Object Name)) {
        $round = $roundProperty.Value
        $roundOperations = if ($round.PSObject.Properties.Name -contains 'operations') { @($round.operations) } else { @() }
        foreach ($operation in $roundOperations) {
            if ($null -eq $operation) {
                throw "vx-draft round $($roundProperty.Name) contains null operation"
            }
            $operationType = if ($operation.PSObject.Properties.Name -contains 'type') { ([string]$operation.type).Trim().ToLowerInvariant() } else { 'regex-patch' }
            $targetId = if ($operation.PSObject.Properties.Name -contains 'target') { ([string]$operation.target).Trim() } else { $defaultTargetId }
            if ([string]::IsNullOrWhiteSpace($targetId)) {
                throw "vx-draft round $($roundProperty.Name) operation target is ambiguous"
            }
            if (-not $targetsById.ContainsKey($targetId)) {
                throw "vx-draft round $($roundProperty.Name) operation has unknown target: $targetId"
            }
            $target = $targetsById[$targetId]
            if ($operationType -eq 'create-file') {
                if ($target.Lifecycle -ne 'create') {
                    throw "vx-draft create-file target '$targetId' must declare lifecycle=create"
                }
                $createCounts[$targetId]++
                [void]$createdTargets.Add($targetId)
            }
            elseif ($operationType -eq 'regex-patch') {
                if (-not $createdTargets.Contains($targetId)) {
                    throw "vx-draft regex-patch targets missing create target before create-file: $targetId"
                }
            }
            else {
                throw "vx-draft unsupported operation type: $operationType"
            }
            $markerOwnerText = if ($operationType -eq 'create-file') {
                if ($operation.PSObject.Properties.Name -contains 'content') { [string]$operation.content } else { '' }
            }
            else {
                if ($operation.PSObject.Properties.Name -contains 'replacement') { [string]$operation.replacement } else { '' }
            }
            foreach ($marker in @($operation.idempotentContains)) {
                $markerText = [string]$marker
                if ([string]::IsNullOrWhiteSpace($markerText) -or -not $ownedMarkers.Add($markerText)) {
                    throw "vx-draft operation marker is empty or reused: $markerText"
                }
                if (-not $markerOwnerText.Contains($markerText)) {
                    throw "vx-draft operation marker is not owned by its replacement/content: $markerText"
                }
            }
        }
        $roundAssertions = if ($round.PSObject.Properties.Name -contains 'postApplyAssertions') { @($round.postApplyAssertions) } else { @() }
        foreach ($assertion in $roundAssertions) {
            if ($null -eq $assertion -or -not ($assertion.PSObject.Properties.Name -contains 'target') -or
                [string]::IsNullOrWhiteSpace([string]$assertion.target)) {
                throw "vx-draft round $($roundProperty.Name) assertion missing target"
            }
            if (-not $targetsById.ContainsKey(([string]$assertion.target).Trim())) {
                throw "vx-draft round $($roundProperty.Name) assertion has unknown target: $($assertion.target)"
            }
        }
        if ($round.PSObject.Properties.Name -contains 'idempotentContainsByTarget') {
            foreach ($markerProperty in @($round.idempotentContainsByTarget.PSObject.Properties)) {
                if (-not $targetsById.ContainsKey([string]$markerProperty.Name)) {
                    throw "vx-draft round $($roundProperty.Name) marker map has unknown target: $($markerProperty.Name)"
                }
            }
        }
    }
    foreach ($target in $targets) {
        if ($target.Lifecycle -eq 'create' -and $createCounts[$target.Id] -ne 1) {
            throw "vx-draft create target '$($target.Id)' must have exactly one create-file operation"
        }
    }

    $targetArray = $targets.ToArray()
    $targetSetText = (($targetArray | Sort-Object File | ForEach-Object {
        "{0}`0{1}`0{2}`0{3}`n" -f $_.Id, $_.File, $_.Kind, $_.Lifecycle
    }) -join '')
    return [pscustomobject]@{
        SchemaVersion = 'vx-draft'
        Targets = $targetArray
        DefaultTargetId = $defaultTargetId
        PrimaryTarget = $primaryTarget
        TargetSetSha256 = Get-TaskDefinitionSha256Text -Text $targetSetText
    }
}
