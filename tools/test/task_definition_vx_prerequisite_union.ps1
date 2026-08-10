function Get-VxUnionPathKey {
    param([object]$Target)
    return ([IO.Path]::GetFullPath([string]$Target.FullPath)).ToLowerInvariant()
}

function Add-VxUnionRegistrySlots {
    param([object]$Registry, [hashtable]$Slots)

    foreach ($target in $Registry.Targets) {
        $key = Get-VxUnionPathKey $target
        if ($Slots.ContainsKey($key)) { continue }
        $exists = Test-Path -LiteralPath $target.FullPath -PathType Leaf
        $bytes = if ($exists) { [IO.File]::ReadAllBytes($target.FullPath) } else { $null }
        try { $text = if ($exists) { [Text.UTF8Encoding]::new($false, $true).GetString($bytes) } else { '' } }
        catch { Add-ErrorIssue "target_id=$($target.Id) is not valid UTF-8"; $text = '' }
        $Slots[$key] = [pscustomobject]@{
            RelativePath = $target.File
            BaselineExists = [bool]$exists
            BaselineLength = if ($exists) { [long]$bytes.Length } else { $null }
            BaselineHash = if ($exists) { Get-VxSha256 $bytes } else { $null }
            WorkingExists = [bool]$exists
            WorkingText = $text
        }
    }
}

function Test-VxUnionSlotChanged {
    param([object]$Slot)

    if ($Slot.BaselineExists -ne $Slot.WorkingExists) { return $true }
    if (-not $Slot.BaselineExists) { return $false }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$Slot.WorkingText)
    return $Slot.BaselineHash -ne (Get-VxSha256 $bytes)
}

function Invoke-VxUnionDefinition {
    param(
        [object]$Definition,
        [object]$Registry,
        [hashtable]$Slots,
        [object]$TouchedPaths,
        [AllowEmptyString()][string]$ScopeRound = '',
        [int]$ScopeOperationIndex = 0,
        [switch]$ScopeChainRounds,
        [string]$Label = 'current'
    )

    $targetsById = @{}
    foreach ($target in $Registry.Targets) {
        $targetsById[$target.Id] = $target
        $slot = $Slots[(Get-VxUnionPathKey $target)]
        if ($target.Lifecycle -eq 'existing' -and -not $slot.WorkingExists) {
            Add-ErrorIssue "definition=$Label target_id=$($target.Id) target_path=$($target.File) existing target unavailable in effective mapping"
            return 0
        }
    }

    $chainStart = if ($ScopeChainRounds.IsPresent) { [int]$ScopeRound.Substring(1) } else { 0 }
    $visited = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $roundFound = $false
    $operationCount = 0
    foreach ($roundProperty in @($Definition.rounds.PSObject.Properties | Sort-Object Name)) {
        $round = ([string]$roundProperty.Name).Trim().ToUpperInvariant()
        if (-not [string]::IsNullOrWhiteSpace($ScopeRound)) {
            if ($ScopeChainRounds.IsPresent) {
                if ($round -notmatch '^D[1-4]$' -or [int]$round.Substring(1) -lt $chainStart) { continue }
            }
            elseif ($round -ne $ScopeRound) { continue }
        }
        $roundFound = $true
        if ($ScopeChainRounds.IsPresent) { [void]$visited.Add($round) }
        $before = $errors.Count
        $roundTask = $roundProperty.Value
        $roundType = Get-RoundTaskType $roundTask
        if ($roundType -eq 'noop') { Add-InfoIssue "definition=$Label round=$round type=noop skip=true"; continue }
        if ($roundType -ne 'regex-patch') { Add-ErrorIssue "definition=$Label round=$round unsupported vx round type=$roundType"; break }
        $operations = @($roundTask.operations)
        if ($operations.Count -eq 0) { Add-ErrorIssue "definition=$Label round=$round regex-patch missing operations"; break }
        if ($ScopeOperationIndex -gt $operations.Count) { Add-ErrorIssue "definition=$Label round=$round operation index out of range"; break }

        $roundTouched = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        for ($index = 0; $index -lt $operations.Count; $index++) {
            $ordinal = $index + 1
            if ($ScopeOperationIndex -gt 0 -and $ordinal -gt $ScopeOperationIndex) { break }
            $operation = $operations[$index]
            $targetId = Get-VxTargetId $operation $Registry $round $ordinal
            $target = $targetsById[$targetId]
            $pathKey = Get-VxUnionPathKey $target
            $slot = $Slots[$pathKey]
            $type = if ($operation.PSObject.Properties.Name -contains 'type') { ([string]$operation.type).Trim().ToLowerInvariant() } else { 'regex-patch' }
            [void]$TouchedPaths.Add($pathKey)
            [void]$roundTouched.Add($targetId)
            $operationCount++

            if ($type -eq 'create-file') {
                $content = [string]$operation.content
                $actualHash = Get-VxSha256 ([Text.UTF8Encoding]::new($false).GetBytes($content))
                $declaredHash = ([string]$operation.contentSha256).Trim().ToLowerInvariant()
                if (([string]$operation.existingPolicy).Trim().ToLowerInvariant() -ne 'skip' -or
                    $declaredHash -notmatch '^[0-9a-f]{64}$' -or $declaredHash -ne $actualHash) {
                    Add-ErrorIssue "definition=$Label round=$round op=$ordinal target_id=$targetId create-file binding invalid"; break
                }
                if ($slot.WorkingExists) {
                    $workingHash = Get-VxSha256 ([Text.UTF8Encoding]::new($false).GetBytes([string]$slot.WorkingText))
                    if ($workingHash -ne $declaredHash) { Add-ErrorIssue "definition=$Label round=$round op=$ordinal target_id=$targetId already-exists content mismatch"; break }
                    Add-InfoIssue "definition=$Label round=$round op=$ordinal target_id=$targetId action=already-exists target_path=$($target.File)"
                }
                else {
                    $slot.WorkingExists = $true
                    $slot.WorkingText = $content
                    Add-InfoIssue "definition=$Label round=$round op=$ordinal target_id=$targetId action=created target_path=$($target.File)"
                }
            }
            elseif ($type -eq 'regex-patch') {
                if (-not $slot.WorkingExists) { Add-ErrorIssue "definition=$Label round=$round op=$ordinal target_id=$targetId target does not exist"; break }
                $pattern = [string]$operation.pattern
                if ([string]::IsNullOrWhiteSpace($pattern) -or (Test-UnsafeNestedQuantifier $pattern)) { Add-ErrorIssue "definition=$Label round=$round op=$ordinal target_id=$targetId invalid or unsafe pattern"; break }
                try { $regex = New-TaskRegex $pattern ([Text.RegularExpressions.RegexOptions]::Singleline); $matchCount = $regex.Matches([string]$slot.WorkingText).Count }
                catch { Add-ErrorIssue "definition=$Label round=$round op=$ordinal target_id=$targetId regex failed detail=$($_.Exception.Message)"; break }
                if ($matchCount -gt 1) { Add-ErrorIssue "definition=$Label round=$round op=$ordinal target_id=$targetId pattern not unique match_count=$matchCount"; break }
                if ($matchCount -eq 1) {
                    $slot.WorkingText = $regex.Replace([string]$slot.WorkingText, [string]$operation.replacement, 1)
                    if ($regex.Matches([string]$slot.WorkingText).Count -ne 0) { Add-OperationSafetyIssue "definition=$Label round=$round op=$ordinal target_id=$targetId pattern remains matchable" }
                    Add-InfoIssue "definition=$Label round=$round op=$ordinal target_id=$targetId target_path=$($target.File) pattern_match=1"
                }
                elseif (-not (Test-VxMarkers $operation ([string]$slot.WorkingText))) { Add-ErrorIssue "definition=$Label round=$round op=$ordinal target_id=$targetId pattern unmatched and marker absent"; break }
            }
            else { Add-ErrorIssue "definition=$Label round=$round op=$ordinal unsupported operation type=$type"; break }

            if (-not (Test-VxMarkers $operation ([string]$slot.WorkingText))) { Add-OperationSafetyIssue "definition=$Label round=$round op=$ordinal target_id=$targetId target-local marker absent" }
            if ($errors.Count -gt $before) { break }
        }

        if ($errors.Count -eq $before -and $ScopeOperationIndex -eq 0) {
            $mappingSnapshot = @{}
            foreach ($key in $Slots.Keys) { $mappingSnapshot[$key] = "$($Slots[$key].WorkingExists)`0$($Slots[$key].WorkingText)" }
            foreach ($operation in $operations) {
                $targetId = Get-VxTargetId $operation $Registry $round 0
                $target = $targetsById[$targetId]
                $slot = $Slots[(Get-VxUnionPathKey $target)]
                $type = if ($operation.PSObject.Properties.Name -contains 'type') { ([string]$operation.type).Trim().ToLowerInvariant() } else { 'regex-patch' }
                if ($type -eq 'create-file') {
                    $hash = Get-VxSha256 ([Text.UTF8Encoding]::new($false).GetBytes([string]$slot.WorkingText))
                    if (-not $slot.WorkingExists -or $hash -ne ([string]$operation.contentSha256).ToLowerInvariant()) { Add-OperationSafetyIssue "definition=$Label round=$round target_id=$targetId create replay failed" }
                }
                else {
                    $regex = New-TaskRegex ([string]$operation.pattern) ([Text.RegularExpressions.RegexOptions]::Singleline)
                    if ($regex.Matches([string]$slot.WorkingText).Count -ne 0 -or -not (Test-VxMarkers $operation ([string]$slot.WorkingText))) { Add-OperationSafetyIssue "definition=$Label round=$round target_id=$targetId regex replay failed" }
                }
            }
            foreach ($key in $Slots.Keys) {
                if ($mappingSnapshot[$key] -ne "$($Slots[$key].WorkingExists)`0$($Slots[$key].WorkingText)") { Add-OperationSafetyIssue "definition=$Label round=$round replay changed mapping target_path=$($Slots[$key].RelativePath)" }
            }
            if ($roundTask.PSObject.Properties.Name -contains 'idempotentContainsByTarget') {
                foreach ($property in @($roundTask.idempotentContainsByTarget.PSObject.Properties)) {
                    $target = $targetsById[$property.Name]
                    $slot = $Slots[(Get-VxUnionPathKey $target)]
                    foreach ($marker in @(Get-StringArray $property.Value)) { if (-not ([string]$slot.WorkingText).Contains($marker.Trim())) { Add-OperationSafetyIssue "definition=$Label round=$round target_id=$($property.Name) round marker absent" } }
                }
            }
            foreach ($assertion in @($roundTask.postApplyAssertions)) {
                $targetId = ([string]$assertion.target).Trim()
                $target = $targetsById[$targetId]
                $slot = $Slots[(Get-VxUnionPathKey $target)]
                try { $actual = (New-TaskRegex ([string]$assertion.pattern) ([Text.RegularExpressions.RegexOptions]::Singleline)).Matches([string]$slot.WorkingText).Count }
                catch { Add-OperationSafetyIssue "definition=$Label round=$round assertion=$($assertion.name) target_id=$targetId invalid regex"; continue }
                if ($actual -ne [int]$assertion.expectedCount) { Add-OperationSafetyIssue "definition=$Label round=$round assertion=$($assertion.name) target_id=$targetId expected=$($assertion.expectedCount) actual=$actual" }
            }
        }

        if ($errors.Count -eq $before -and $ScopeOperationIndex -eq 0) {
            $roundJson = $roundTask | ConvertTo-Json -Depth 64 -Compress
            $effectiveHeaders = @{}
            foreach ($candidateSlot in $Slots.Values) {
                if ($candidateSlot.WorkingExists -and ([string]$candidateSlot.RelativePath).EndsWith('.h', [StringComparison]::OrdinalIgnoreCase)) {
                    $effectiveHeaders[$candidateSlot.RelativePath] = [string]$candidateSlot.WorkingText
                }
            }
            foreach ($targetId in $roundTouched) {
                $target = $targetsById[$targetId]
                if ($target.Kind -eq 'c-source') { Test-EffectiveCSourceSyntax ([string]$Slots[(Get-VxUnionPathKey $target)].WorkingText) $target.FullPath $roundJson $round $effectiveHeaders }
            }
        }
        if ($errors.Count -gt $before) { if ($ScopeChainRounds.IsPresent) { Add-InfoIssue "definition=$Label round=$round chain_stop=true reason=round-failed" }; break }
    }

    if (-not [string]::IsNullOrWhiteSpace($ScopeRound) -and -not $roundFound) {
        if ($ScopeRound -match '^V[1-4]$') { Add-InfoIssue "definition=$Label round=$ScopeRound not found (V-round has no JSON definition)" } else { Add-ErrorIssue "definition=$Label round=$ScopeRound not found" }
    }
    if ($ScopeChainRounds.IsPresent -and $errors.Count -eq 0) {
        foreach ($number in $chainStart..4) { if (-not $visited.Contains("D$number")) { Add-ErrorIssue "definition=$Label chain round missing round=D$number"; break } }
    }
    return $operationCount
}

function Publish-VxUnionArtifact {
    param([string]$Directory, [object]$Registry, [hashtable]$Slots, [object]$TouchedPaths, [object[]]$Prerequisites, [string]$Round, [int]$OperationCount)

    $destination = if ([IO.Path]::IsPathRooted($Directory)) { $Directory } else { Join-Path $RepoRoot $Directory }
    if (Test-Path -LiteralPath $destination) { throw "validated artifact directory already exists: $destination" }
    $parent = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $staging = Join-Path $parent ('.task-static-vx-{0}' -f [guid]::NewGuid().ToString('N'))
    $payloadRoot = Join-Path $staging 'payload'
    New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null
    try {
        $manifestTargets = @()
        foreach ($target in @($Registry.Targets | Sort-Object File)) {
            $key = Get-VxUnionPathKey $target
            $slot = $Slots[$key]
            $effectiveBytes = if ($slot.WorkingExists) { [Text.UTF8Encoding]::new($false).GetBytes([string]$slot.WorkingText) } else { $null }
            $effectiveHash = if ($slot.WorkingExists) { Get-VxSha256 $effectiveBytes } else { $null }
            $changed = Test-VxUnionSlotChanged $slot
            $payload = $null
            if ($changed -and $slot.WorkingExists) { $payload = "payload/$($target.Id).bin"; [IO.File]::WriteAllBytes((Join-Path $payloadRoot "$($target.Id).bin"), $effectiveBytes) }
            $manifestTargets += [ordered]@{
                id = $target.Id; path = $target.File; kind = $target.Kind; lifecycle = $target.Lifecycle
                touched = [bool]$TouchedPaths.Contains($key); changed = [bool]$changed
                baseline_exists = [bool]$slot.BaselineExists
                baseline_length = if ($slot.BaselineExists) { [long]$slot.BaselineLength } else { $null }
                baseline_sha256 = if ($slot.BaselineExists) { $slot.BaselineHash } else { $null }
                effective_exists = [bool]$slot.WorkingExists
                effective_length = if ($slot.WorkingExists) { [long]$effectiveBytes.Length } else { $null }
                effective_sha256 = $effectiveHash; payload = $payload
                payload_sha256 = if ($null -ne $payload) { $effectiveHash } else { $null }
            }
        }
        $manifest = [ordered]@{
            schema = 'TASK_STATIC_VALIDATED_ARTIFACT_VX1'; stage = $Stage; round = $Round
            task_definition = $resolvedTaskDefinition
            task_definition_sha256 = (Get-FileHash -LiteralPath $resolvedTaskDefinition -Algorithm SHA256).Hash.ToLowerInvariant()
            target_set_sha256 = $Registry.TargetSetSha256; operation_count = $OperationCount
            checker_policy = $Policy; generated_at = [DateTimeOffset]::UtcNow.ToString('o')
            prerequisites = @($Prerequisites); targets = $manifestTargets
        }
        [IO.File]::WriteAllText((Join-Path $staging 'manifest.json.tmp'), ($manifest | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
        [IO.File]::Move((Join-Path $staging 'manifest.json.tmp'), (Join-Path $staging 'manifest.json'))
        [IO.Directory]::Move($staging, $destination)
        Add-InfoIssue "vx artifact published directory=$destination"
    }
    finally { if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue } }
}

function Invoke-VxTaskStaticCheckCore {
    param([object]$Definition, [object]$Registry)

    if (-not [string]::IsNullOrWhiteSpace($BaselineTargetFile) -or -not [string]::IsNullOrWhiteSpace($OutputEffectiveTargetFile)) { Add-ErrorIssue 'vx-draft rejects V1 BaselineTargetFile and OutputEffectiveTargetFile parameters' }
    $prerequisites = New-Object 'Collections.Generic.List[object]'
    $order = 0
    foreach ($rawPath in @($PrerequisiteTaskDefinitionFiles)) {
        $inputPath = ([string]$rawPath).Trim()
        if ([string]::IsNullOrWhiteSpace($inputPath)) { continue }
        $order++
        try {
            $candidate = if ([IO.Path]::IsPathRooted($inputPath)) { $inputPath } else { Join-Path $RepoRoot $inputPath }
            $path = (Resolve-Path -LiteralPath $candidate).Path
            $definitionNode = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
            $registryNode = Resolve-TaskDefinitionTargetRegistry -TaskDefinition $definitionNode -TaskDefinitionPath $path -RepositoryRoot $RepoRoot -AllowMissingExistingTargets
            if ($registryNode.SchemaVersion -ne 'vx-draft') { throw 'Vx current definition requires Vx prerequisites' }
            $prerequisites.Add([pscustomobject]@{ Order = $order; Path = $path; Definition = $definitionNode; Registry = $registryNode; Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() })
        }
        catch { Add-ErrorIssue "prerequisite resolve failed order=$order task=$inputPath detail=$($_.Exception.Message)"; break }
    }

    $slots = @{}
    foreach ($entry in $prerequisites) { Add-VxUnionRegistrySlots $entry.Registry $slots }
    Add-VxUnionRegistrySlots $Registry $slots
    $prerequisiteMetadata = New-Object 'Collections.Generic.List[object]'
    $prerequisiteTouched = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($errors.Count -eq 0) {
        foreach ($entry in $prerequisites) {
            Add-InfoIssue "prerequisite check start order=$($entry.Order) task=$($entry.Path) targets=$($entry.Registry.Targets.Count)"
            $before = $errors.Count
            [void](Invoke-VxUnionDefinition $entry.Definition $entry.Registry $slots $prerequisiteTouched -Label "prerequisite-$($entry.Order)")
            if ($errors.Count -gt $before) { Add-InfoIssue "prerequisite check stop order=$($entry.Order) reason=first-error"; break }
            $prerequisiteMetadata.Add([ordered]@{ order = [int]$entry.Order; path = [string]$entry.Path; sha256 = [string]$entry.Sha256; target_set_sha256 = [string]$entry.Registry.TargetSetSha256 })
            Add-InfoIssue "prerequisite check passed order=$($entry.Order) task=$($entry.Path)"
        }
    }

    $currentPaths = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($target in $Registry.Targets) { [void]$currentPaths.Add((Get-VxUnionPathKey $target)) }
    if ($errors.Count -eq 0) {
        foreach ($key in $slots.Keys) {
            if ((Test-VxUnionSlotChanged $slots[$key]) -and -not $currentPaths.Contains($key)) {
                Add-ErrorIssue "prerequisite changed target outside current registry target_path=$($slots[$key].RelativePath); current registry must cover commit closure"
                break
            }
        }
    }

    $currentTouched = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $operationCount = 0
    if ($errors.Count -eq 0) {
        $operationCount = Invoke-VxUnionDefinition $Definition $Registry $slots $currentTouched -ScopeRound $effectiveRoundTag `
            -ScopeOperationIndex $RequestedOperationIndex -ScopeChainRounds:$ChainRounds.IsPresent -Label 'current'
    }

    $warningFailed = $warnings.Count -gt 0 -and $FailOnWarnings.IsPresent -and $Policy -eq 'enforce'
    $errorFailed = $errors.Count -gt 0 -and $Policy -eq 'enforce'
    if (-not [string]::IsNullOrWhiteSpace($OutputValidatedArtifactDirectory) -and -not $warningFailed -and -not $errorFailed) {
        $artifactRound = if ([string]::IsNullOrWhiteSpace($effectiveRoundTag)) { 'all' } elseif ($ChainRounds.IsPresent) { "$effectiveRoundTag-D4" } else { $effectiveRoundTag }
        Publish-VxUnionArtifact $OutputValidatedArtifactDirectory $Registry $slots $currentTouched $prerequisiteMetadata.ToArray() $artifactRound $operationCount
    }
    $scope = if ([string]::IsNullOrWhiteSpace($effectiveRoundTag)) { 'all' } elseif ($RequestedOperationIndex -gt 0) { "$effectiveRoundTag`:op$RequestedOperationIndex" } elseif ($ChainRounds.IsPresent) { "$effectiveRoundTag-D4:chain" } else { $effectiveRoundTag }
    Write-Output "[TASK-STATIC-CHECK] policy=$Policy scope=$scope task=$resolvedTaskDefinition schema=vx-draft targets=$($Registry.Targets.Count) target_set_sha256=$($Registry.TargetSetSha256) prerequisites_requested=$($prerequisites.Count) prerequisites_applied=$($prerequisiteMetadata.Count)"
    foreach ($item in $infos) { Write-Output "[TASK-STATIC-CHECK] severity=info detail=$item" }
    foreach ($item in $warnings) { Write-Output "[TASK-STATIC-CHECK] severity=warn detail=$item" }
    foreach ($item in $errors) { Write-Output "[TASK-STATIC-CHECK] severity=error detail=$item" }
    Write-Output "[TASK-STATIC-CHECK] summary errors=$($errors.Count) warnings=$($warnings.Count) infos=$($infos.Count)"
    if ($warningFailed) { Exit-TaskStaticCheck 3 }
    if ($errorFailed) { Exit-TaskStaticCheck 2 }
    Exit-TaskStaticCheck 0
}