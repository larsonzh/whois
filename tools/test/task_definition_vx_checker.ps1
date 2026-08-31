function Get-VxSha256 {
    param([byte[]]$Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha256.Dispose() }
}

function Get-VxTargetId {
    param([object]$Operation, [object]$Registry, [string]$Round, [int]$Ordinal)
    $id = if ($Operation.PSObject.Properties.Name -contains 'target') { ([string]$Operation.target).Trim() } else { [string]$Registry.DefaultTargetId }
    if ([string]::IsNullOrWhiteSpace($id)) { throw "round=$Round op=$Ordinal operation target is ambiguous" }
    return $id
}

function Test-VxMarkers {
    param([object]$Operation, [string]$Text)
    return Test-OperationIdempotentMarkerPresent -Operation $Operation -Text $Text
}

function Get-VxRegexOccurrenceCount {
    param([Text.RegularExpressions.Regex]$Regex, [string]$Text)

    $count = 0
    $currentResult = $Regex.Match($Text)
    while ($currentResult.Success) {
        $count++
        $currentResult = $currentResult.NextMatch()
    }
    return $count
}

function Move-VxArtifactDirectory {
    param([string]$Staging, [string]$Destination)

    $retryDelaysMs = @(50, 100, 200)
    for ($attempt = 1; $attempt -le ($retryDelaysMs.Count + 1); $attempt++) {
        try {
            [IO.Directory]::Move($Staging, $Destination)
            return
        }
        catch {
            if (Test-Path -LiteralPath $Destination) {
                throw "validated artifact directory already exists: $Destination"
            }
            if ($attempt -gt $retryDelaysMs.Count) {
                throw
            }
            Add-InfoIssue ("vx artifact publish retry attempt={0} destination={1} detail={2}" -f $attempt, $Destination, $_.Exception.Message)
            [Threading.Thread]::Sleep($retryDelaysMs[$attempt - 1])
        }
    }
}

function Publish-VxArtifact {
    param([string]$Directory, [object]$Registry, [hashtable]$Slots, [object]$Touched, [string]$Round, [int]$OperationCount)

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
            $slot = $Slots[$target.Id]
            $effectiveBytes = if ($slot.WorkingExists) { [Text.UTF8Encoding]::new($false).GetBytes([string]$slot.WorkingText) } else { $null }
            $effectiveHash = if ($slot.WorkingExists) { Get-VxSha256 $effectiveBytes } else { $null }
            $changed = ($slot.BaselineExists -ne $slot.WorkingExists) -or ($slot.BaselineExists -and $slot.BaselineHash -ne $effectiveHash)
            $payload = $null
            if ($changed -and $slot.WorkingExists) {
                $payload = "payload/$($target.Id).bin"
                [IO.File]::WriteAllBytes((Join-Path $payloadRoot "$($target.Id).bin"), $effectiveBytes)
            }
            $manifestTargets += [ordered]@{
                id = $target.Id; path = $target.File; kind = $target.Kind; lifecycle = $target.Lifecycle
                touched = [bool]$Touched.Contains($target.Id); changed = [bool]$changed
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
            prerequisites = @(); targets = $manifestTargets
        }
        $temporaryManifest = Join-Path $staging 'manifest.json.tmp'
        [IO.File]::WriteAllText($temporaryManifest, ($manifest | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporaryManifest, (Join-Path $staging 'manifest.json'))
        Move-VxArtifactDirectory -Staging $staging -Destination $destination
        Add-InfoIssue "vx artifact published directory=$destination"
    }
    finally {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-VxTaskStaticCheckLegacy {
    param([object]$Definition, [object]$Registry)

    if (-not [string]::IsNullOrWhiteSpace($BaselineTargetFile) -or -not [string]::IsNullOrWhiteSpace($OutputEffectiveTargetFile)) {
        Add-ErrorIssue 'vx-draft rejects V1 BaselineTargetFile and OutputEffectiveTargetFile parameters'
    }

    $slots = @{}
    foreach ($target in $Registry.Targets) {
        $exists = Test-Path -LiteralPath $target.FullPath -PathType Leaf
        $bytes = if ($exists) { [IO.File]::ReadAllBytes($target.FullPath) } else { $null }
        try { $text = if ($exists) { [Text.UTF8Encoding]::new($false, $true).GetString($bytes) } else { '' } }
        catch { Add-ErrorIssue "target_id=$($target.Id) is not valid UTF-8"; $text = '' }
        $slots[$target.Id] = [pscustomobject]@{
            Target = $target; BaselineExists = [bool]$exists
            BaselineLength = if ($exists) { [long]$bytes.Length } else { $null }
            BaselineHash = if ($exists) { Get-VxSha256 $bytes } else { $null }
            WorkingExists = [bool]$exists; WorkingText = $text
        }
    }

    $touched = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $visited = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $chainStart = if ($ChainRounds.IsPresent) { [int]$effectiveRoundTag.Substring(1) } else { 0 }
    $roundFound = $false
    $operationCount = 0

    if ($errors.Count -eq 0) {
        foreach ($roundProperty in @($Definition.rounds.PSObject.Properties | Sort-Object Name)) {
            $round = ([string]$roundProperty.Name).Trim().ToUpperInvariant()
            if (-not [string]::IsNullOrWhiteSpace($effectiveRoundTag)) {
                if ($ChainRounds.IsPresent) {
                    if (-not [regex]::IsMatch($round, '^D[1-4]$') -or [int]$round.Substring(1) -lt $chainStart) { continue }
                }
                elseif ($round -ne $effectiveRoundTag) { continue }
            }
            $roundFound = $true
            if ($ChainRounds.IsPresent) { [void]$visited.Add($round) }
            $before = $errors.Count
            $roundTask = $roundProperty.Value
            $roundType = Get-RoundTaskType $roundTask
            if ($roundType -eq 'noop') { Add-InfoIssue "round=$round type=noop skip=true"; continue }
            if ($roundType -ne 'regex-patch') { Add-ErrorIssue "round=$round unsupported vx round type=$roundType"; break }
            $operations = @($roundTask.operations)
            if ($operations.Count -eq 0) { Add-ErrorIssue "round=$round regex-patch missing operations"; break }
            if ($RequestedOperationIndex -gt $operations.Count) { Add-ErrorIssue "round=$round operation index out of range"; break }

            $roundTouched = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            for ($index = 0; $index -lt $operations.Count; $index++) {
                $ordinal = $index + 1
                if ($RequestedOperationIndex -gt 0 -and $ordinal -gt $RequestedOperationIndex) { break }
                $operation = $operations[$index]
                $targetId = Get-VxTargetId $operation $Registry $round $ordinal
                $slot = $slots[$targetId]
                $type = if ($operation.PSObject.Properties.Name -contains 'type') { ([string]$operation.type).Trim().ToLowerInvariant() } else { 'regex-patch' }
                [void]$touched.Add($targetId); [void]$roundTouched.Add($targetId); $operationCount++

                if ($type -eq 'create-file') {
                    $content = [string]$operation.content
                    $contentHash = Get-VxSha256 ([Text.UTF8Encoding]::new($false).GetBytes($content))
                    $declaredHash = ([string]$operation.contentSha256).Trim().ToLowerInvariant()
                    $existingPolicy = ([string]$operation.existingPolicy).Trim().ToLowerInvariant()
                    if ($existingPolicy -ne 'skip' -or -not [regex]::IsMatch($declaredHash, '^[0-9a-f]{64}$') -or $declaredHash -ne $contentHash) {
                        Add-ErrorIssue "round=$round op=$ordinal target_id=$targetId create-file binding invalid"; break
                    }
                    if ($slot.WorkingExists) {
                        $workingHash = Get-VxSha256 ([Text.UTF8Encoding]::new($false).GetBytes([string]$slot.WorkingText))
                        if ($workingHash -ne $declaredHash) { Add-ErrorIssue "round=$round op=$ordinal target_id=$targetId already-exists content mismatch"; break }
                        Add-InfoIssue "round=$round op=$ordinal target_id=$targetId action=already-exists"
                    }
                    else { $slot.WorkingExists = $true; $slot.WorkingText = $content; Add-InfoIssue "round=$round op=$ordinal target_id=$targetId action=created" }
                }
                elseif ($type -eq 'regex-patch') {
                    if (-not $slot.WorkingExists) { Add-ErrorIssue "round=$round op=$ordinal target_id=$targetId target does not exist"; break }
                    $pattern = [string]$operation.pattern
                    if ([string]::IsNullOrWhiteSpace($pattern) -or (Test-UnsafeNestedQuantifier $pattern)) { Add-ErrorIssue "round=$round op=$ordinal target_id=$targetId invalid or unsafe pattern"; break }
                    try {
                        $regex = New-TaskRegex $pattern ([Text.RegularExpressions.RegexOptions]::Singleline)
                        $regexOccurrenceCount = Get-VxRegexOccurrenceCount -Regex $regex -Text ([string]$slot.WorkingText)
                    }
                    catch { Add-ErrorIssue "round=$round op=$ordinal target_id=$targetId regex failed detail=$($_.Exception.Message)"; break }
                    if ($regexOccurrenceCount -gt 1) { Add-ErrorIssue "round=$round op=$ordinal target_id=$targetId pattern not unique match_count=$regexOccurrenceCount"; break }
                    if ($regexOccurrenceCount -eq 1) {
                        $slot.WorkingText = $regex.Replace([string]$slot.WorkingText, [string]$operation.replacement, 1)
                        if ((Get-VxRegexOccurrenceCount -Regex $regex -Text ([string]$slot.WorkingText)) -ne 0) { Add-OperationSafetyIssue "round=$round op=$ordinal target_id=$targetId pattern remains matchable" }
                        Add-InfoIssue "round=$round op=$ordinal target_id=$targetId target_path=$($slot.Target.File) pattern_match=1"
                    }
                    elseif (-not (Test-VxMarkers $operation ([string]$slot.WorkingText))) { Add-ErrorIssue "round=$round op=$ordinal target_id=$targetId pattern unmatched and marker absent"; break }
                }
                else { Add-ErrorIssue "round=$round op=$ordinal unsupported operation type=$type"; break }

                if (-not (Test-VxMarkers $operation ([string]$slot.WorkingText))) { Add-OperationSafetyIssue "round=$round op=$ordinal target_id=$targetId target-local marker absent" }
                if ($errors.Count -gt $before) { break }
            }

            if ($errors.Count -eq $before -and $RequestedOperationIndex -eq 0) {
                $snapshot = @{}; foreach ($id in $slots.Keys) { $snapshot[$id] = "$($slots[$id].WorkingExists)`0$($slots[$id].WorkingText)" }
                foreach ($operation in $operations) {
                    $id = Get-VxTargetId $operation $Registry $round 0; $slot = $slots[$id]
                    $type = if ($operation.PSObject.Properties.Name -contains 'type') { ([string]$operation.type).Trim().ToLowerInvariant() } else { 'regex-patch' }
                    if ($type -eq 'create-file') {
                        $hash = Get-VxSha256 ([Text.UTF8Encoding]::new($false).GetBytes([string]$slot.WorkingText))
                        if (-not $slot.WorkingExists -or $hash -ne ([string]$operation.contentSha256).ToLowerInvariant()) { Add-OperationSafetyIssue "round=$round target_id=$id create replay failed" }
                    }
                    else {
                        $regex = New-TaskRegex ([string]$operation.pattern) ([Text.RegularExpressions.RegexOptions]::Singleline)
                        if ((Get-VxRegexOccurrenceCount -Regex $regex -Text ([string]$slot.WorkingText)) -ne 0 -or -not (Test-VxMarkers $operation ([string]$slot.WorkingText))) { Add-OperationSafetyIssue "round=$round target_id=$id regex replay failed" }
                    }
                }
                foreach ($id in $slots.Keys) { if ($snapshot[$id] -ne "$($slots[$id].WorkingExists)`0$($slots[$id].WorkingText)") { Add-OperationSafetyIssue "round=$round replay changed mapping target_id=$id" } }

                if ($roundTask.PSObject.Properties.Name -contains 'idempotentContainsByTarget') {
                    foreach ($property in @($roundTask.idempotentContainsByTarget.PSObject.Properties)) {
                        foreach ($marker in @(Get-StringArray $property.Value)) { if (-not ([string]$slots[$property.Name].WorkingText).Contains($marker.Trim())) { Add-OperationSafetyIssue "round=$round target_id=$($property.Name) round marker absent" } }
                    }
                }
                if ($roundTask.PSObject.Properties.Name -contains 'idempotentContains') {
                    $roundMarkerTargetId = [string]$Registry.DefaultTargetId
                    if ([string]::IsNullOrWhiteSpace($roundMarkerTargetId)) { Add-OperationSafetyIssue "round=$round legacy round marker target is ambiguous" }
                    else {
                        foreach ($marker in @(Get-StringArray $roundTask.idempotentContains)) {
                            if (-not ([string]$slots[$roundMarkerTargetId].WorkingText).Contains($marker.Trim())) { Add-OperationSafetyIssue "round=$round target_id=$roundMarkerTargetId legacy round marker absent" }
                        }
                    }
                }
                foreach ($assertion in @($roundTask.postApplyAssertions)) {
                    $id = ([string]$assertion.target).Trim(); $name = [string]$assertion.name
                    try {
                        $assertionRegex = New-TaskRegex ([string]$assertion.pattern) ([Text.RegularExpressions.RegexOptions]::Singleline)
                        $actual = Get-VxRegexOccurrenceCount -Regex $assertionRegex -Text ([string]$slots[$id].WorkingText)
                    }
                    catch { Add-OperationSafetyIssue "round=$round assertion=$name target_id=$id invalid regex"; continue }
                    if ($actual -ne [int]$assertion.expectedCount) { Add-OperationSafetyIssue "round=$round assertion=$name target_id=$id expected=$($assertion.expectedCount) actual=$actual" }
                }
            }

            if ($errors.Count -eq $before -and $RequestedOperationIndex -eq 0) {
                $roundJson = $roundTask | ConvertTo-Json -Depth 64 -Compress
                $effectiveHeaders = @{}
                foreach ($candidateSlot in $slots.Values) {
                    if ($candidateSlot.WorkingExists -and $candidateSlot.Target.Kind -eq 'c-header') {
                        $effectiveHeaders[$candidateSlot.Target.File] = [string]$candidateSlot.WorkingText
                    }
                }
                foreach ($id in $roundTouched) { $slot = $slots[$id]; if ($slot.Target.Kind -eq 'c-source') { Test-EffectiveCSourceSyntax ([string]$slot.WorkingText) $slot.Target.FullPath $roundJson $round $effectiveHeaders } }
            }
            if ($errors.Count -gt $before) { if ($ChainRounds.IsPresent) { Add-InfoIssue "round=$round chain_stop=true reason=round-failed" }; break }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($effectiveRoundTag) -and -not $roundFound) {
        if ([regex]::IsMatch($effectiveRoundTag, '^V[1-4]$')) { Add-InfoIssue "round=$effectiveRoundTag not found (V-round has no JSON definition)" } else { Add-ErrorIssue "round=$effectiveRoundTag not found" }
    }
    if ($ChainRounds.IsPresent -and $errors.Count -eq 0) { foreach ($number in $chainStart..4) { if (-not $visited.Contains("D$number")) { Add-ErrorIssue "chain round missing round=D$number"; break } } }

    $warningFailed = $warnings.Count -gt 0 -and $FailOnWarnings.IsPresent -and $Policy -eq 'enforce'
    $errorFailed = $errors.Count -gt 0 -and $Policy -eq 'enforce'
    if (-not [string]::IsNullOrWhiteSpace($OutputValidatedArtifactDirectory) -and -not $warningFailed -and -not $errorFailed) {
        $artifactRound = if ([string]::IsNullOrWhiteSpace($effectiveRoundTag)) { 'all' } elseif ($ChainRounds.IsPresent) { "$effectiveRoundTag-D4" } else { $effectiveRoundTag }
        Publish-VxArtifact $OutputValidatedArtifactDirectory $Registry $slots $touched $artifactRound $operationCount
    }
    $scope = if ([string]::IsNullOrWhiteSpace($effectiveRoundTag)) { 'all' } elseif ($RequestedOperationIndex -gt 0) { "$effectiveRoundTag`:op$RequestedOperationIndex" } elseif ($ChainRounds.IsPresent) { "$effectiveRoundTag-D4:chain" } else { $effectiveRoundTag }
    Write-Output "[TASK-STATIC-CHECK] policy=$Policy scope=$scope task=$resolvedTaskDefinition schema=vx-draft targets=$($Registry.Targets.Count) target_set_sha256=$($Registry.TargetSetSha256)"
    foreach ($item in $infos) { Write-Output "[TASK-STATIC-CHECK] severity=info detail=$item" }
    foreach ($item in $warnings) { Write-Output "[TASK-STATIC-CHECK] severity=warn detail=$item" }
    foreach ($item in $errors) { Write-Output "[TASK-STATIC-CHECK] severity=error detail=$item" }
    Write-Output "[TASK-STATIC-CHECK] summary errors=$($errors.Count) warnings=$($warnings.Count) infos=$($infos.Count)"
    if ($warningFailed) { Exit-TaskStaticCheck 3 }
    if ($errorFailed) { Exit-TaskStaticCheck 2 }
    Exit-TaskStaticCheck 0
}

. (Join-Path $PSScriptRoot 'task_definition_vx_prerequisite_union.ps1')

function Invoke-VxTaskStaticCheck {
    param([object]$Definition, [object]$Registry)

    Invoke-VxTaskStaticCheckCore -Definition $Definition -Registry $Registry
}
