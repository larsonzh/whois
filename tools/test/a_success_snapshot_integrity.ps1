Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'task_definition_target_registry.ps1')

function ConvertTo-ASnapshotRelativePath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $normalized = $Path.Trim().TrimStart([char]0xFEFF).Replace('\', '/').TrimStart('/')
    if ([string]::IsNullOrWhiteSpace($normalized) -or
        [System.IO.Path]::IsPathRooted($normalized) -or
        $normalized -match '(^|/)\.\.(/|$)') {
        return ''
    }

    return $normalized
}

function Get-ASnapshotTaskTargetRegistry {
    param(
        [string]$TaskDefinitionFile,
        [AllowEmptyString()][string]$RepositoryRoot = ''
    )

    if ([string]::IsNullOrWhiteSpace($TaskDefinitionFile) -or -not (Test-Path -LiteralPath $TaskDefinitionFile -PathType Leaf)) {
        throw "A snapshot task definition not found: $TaskDefinitionFile"
    }

    if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
        $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    }
    $resolvedTaskDefinition = (Resolve-Path -LiteralPath $TaskDefinitionFile).Path
    $task = Get-Content -LiteralPath $TaskDefinitionFile -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    return Resolve-TaskDefinitionTargetRegistry -TaskDefinition $task -TaskDefinitionPath $resolvedTaskDefinition -RepositoryRoot $RepositoryRoot
}

function Get-ASnapshotTaskTargetPaths {
    param([string]$TaskDefinitionFile)

    $registry = Get-ASnapshotTaskTargetRegistry -TaskDefinitionFile $TaskDefinitionFile
    $result = @($registry.Targets | ForEach-Object { [string]$_.File } | Sort-Object -Unique)
    if ($result.Count -eq 0) {
        throw "A snapshot task definition has no valid target paths: $TaskDefinitionFile"
    }
    return $result
}

function Write-ASuccessSnapshotManifest {
    param(
        [string]$SnapshotDir,
        [AllowEmptyString()][string]$TaskDefinitionFile = ''
    )

    $sourceDir = Join-Path $SnapshotDir 'source'
    $sourceFilesPath = Join-Path $SnapshotDir 'source_files.txt'
    if (-not (Test-Path -LiteralPath $sourceDir -PathType Container)) {
        throw "A snapshot source directory missing: $sourceDir"
    }
    if (-not (Test-Path -LiteralPath $sourceFilesPath -PathType Leaf)) {
        throw "A snapshot source file list missing: $sourceFilesPath"
    }

    $registry = if ([string]::IsNullOrWhiteSpace($TaskDefinitionFile)) { $null } else { Get-ASnapshotTaskTargetRegistry -TaskDefinitionFile $TaskDefinitionFile }
    $isVx = $null -ne $registry -and $registry.SchemaVersion -eq 'vx-draft'
    $targets = if ($isVx) {
        @($registry.Targets | Sort-Object File)
    }
    else {
        @(Get-Content -LiteralPath $sourceFilesPath -Encoding utf8 -ErrorAction Stop |
            ForEach-Object { ConvertTo-ASnapshotRelativePath -Path ([string]$_) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique |
            ForEach-Object { [pscustomobject]@{ Id = ''; File = $_; Kind = ''; Lifecycle = '' } })
    }

    $entries = @()
    foreach ($target in $targets) {
        $path = [string]$target.File
        $filePath = Join-Path $sourceDir $path.Replace('/', '\')
        $exists = Test-Path -LiteralPath $filePath -PathType Leaf
        if (-not $exists -and -not $isVx) {
            throw "A snapshot listed source file missing: $path"
        }
        if ($isVx) {
            $entries += [pscustomobject][ordered]@{
                id = [string]$target.Id
                path = $path
                kind = [string]$target.Kind
                lifecycle = [string]$target.Lifecycle
                exists = [bool]$exists
                length = if ($exists) { [long](Get-Item -LiteralPath $filePath).Length } else { $null }
                sha256 = if ($exists) { (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
            }
        }
        else {
            $item = Get-Item -LiteralPath $filePath
            $entries += [pscustomobject][ordered]@{
                path = $path
                length = [long]$item.Length
                sha256 = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    }

    $manifest = [ordered]@{
        schema = 'A_SUCCESS_SNAPSHOT_MANIFEST_V1'
        algorithm = 'SHA256'
        fileCount = [int]@($entries).Count
        files = @($entries)
    }
    if ($isVx) {
        $manifest.schema_version = 'vx-draft'
        $manifest.target_set_sha256 = [string]$registry.TargetSetSha256
    }
    $manifestPath = Join-Path $SnapshotDir 'source_manifest.json'
    $json = $manifest | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($manifestPath, $json + "`n", [System.Text.UTF8Encoding]::new($false))
    return $manifestPath
}

function Test-ASuccessSnapshotIntegrity {
    param(
        [string]$SnapshotDir,
        [string[]]$AllowedPaths = @(),
        [string]$DestinationRoot = '',
        [AllowEmptyString()][string]$ExpectedTargetSetSha256 = ''
    )

    $errors = New-Object 'System.Collections.Generic.List[string]'
    $manifestPath = Join-Path $SnapshotDir 'source_manifest.json'
    $sourceDir = Join-Path $SnapshotDir 'source'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        [void]$errors.Add('manifest-missing')
        return [pscustomobject]@{ Pass = $false; FileCount = 0; Errors = @($errors); ManifestPath = $manifestPath }
    }

    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        [void]$errors.Add('manifest-invalid-json')
        return [pscustomobject]@{ Pass = $false; FileCount = 0; Errors = @($errors); ManifestPath = $manifestPath }
    }
    if ([string]$manifest.schema -ne 'A_SUCCESS_SNAPSHOT_MANIFEST_V1' -or [string]$manifest.algorithm -ne 'SHA256') {
        [void]$errors.Add('manifest-schema-invalid')
    }
    $isVx = $manifest.PSObject.Properties.Name -contains 'schema_version' -and [string]$manifest.schema_version -eq 'vx-draft'
    if ($isVx) {
        $manifestTargetSetSha256 = [string]$manifest.target_set_sha256
        if ($manifestTargetSetSha256 -notmatch '^[0-9a-f]{64}$') {
            [void]$errors.Add('manifest-target-set-hash-invalid')
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedTargetSetSha256) -and $manifestTargetSetSha256 -ne $ExpectedTargetSetSha256) {
            [void]$errors.Add('manifest-target-set-hash-mismatch')
        }
    }

    $allowedSet = @{}
    foreach ($allowedPath in @($AllowedPaths)) {
        $normalizedAllowed = ConvertTo-ASnapshotRelativePath -Path $allowedPath
        if (-not [string]::IsNullOrWhiteSpace($normalizedAllowed)) {
            $allowedSet[$normalizedAllowed.ToLowerInvariant()] = $true
        }
    }

    $manifestSet = @{}
    foreach ($entry in @($manifest.files)) {
        $path = ConvertTo-ASnapshotRelativePath -Path ([string]$entry.path)
        if ([string]::IsNullOrWhiteSpace($path)) {
            [void]$errors.Add('manifest-path-invalid')
            continue
        }
        $pathKey = $path.ToLowerInvariant()
        if ($manifestSet.ContainsKey($pathKey)) {
            [void]$errors.Add("manifest-path-duplicate:$path")
            continue
        }
        $manifestSet[$pathKey] = $true
        if ($allowedSet.Count -gt 0 -and -not $allowedSet.ContainsKey($pathKey)) {
            [void]$errors.Add("path-not-allowed:$path")
        }

        $snapshotFile = Join-Path $sourceDir $path.Replace('/', '\')
        $expectedExists = if ($isVx -and $entry.PSObject.Properties.Name -contains 'exists') { [bool]$entry.exists } else { $true }
        $snapshotExists = Test-Path -LiteralPath $snapshotFile -PathType Leaf
        if ($expectedExists -and -not $snapshotExists) { [void]$errors.Add("snapshot-file-missing:$path") }
        elseif (-not $expectedExists -and $snapshotExists) { [void]$errors.Add("snapshot-file-unexpected:$path") }
        elseif ($expectedExists) {
            $item = Get-Item -LiteralPath $snapshotFile
            $actualHash = (Get-FileHash -LiteralPath $snapshotFile -Algorithm SHA256).Hash.ToLowerInvariant()
            if ([long]$entry.length -ne [long]$item.Length) { [void]$errors.Add("snapshot-length-mismatch:$path") }
            if ([string]$entry.sha256 -ne $actualHash) { [void]$errors.Add("snapshot-hash-mismatch:$path") }
        }

        if (-not [string]::IsNullOrWhiteSpace($DestinationRoot)) {
            $destinationFile = Join-Path $DestinationRoot $path.Replace('/', '\')
            $destinationExists = Test-Path -LiteralPath $destinationFile -PathType Leaf
            if ($expectedExists -and -not $destinationExists) { [void]$errors.Add("destination-file-missing:$path") }
            elseif (-not $expectedExists -and $destinationExists) { [void]$errors.Add("destination-file-unexpected:$path") }
            elseif ($expectedExists) {
                $destinationItem = Get-Item -LiteralPath $destinationFile
                $destinationHash = (Get-FileHash -LiteralPath $destinationFile -Algorithm SHA256).Hash.ToLowerInvariant()
                if ([long]$entry.length -ne [long]$destinationItem.Length -or [string]$entry.sha256 -ne $destinationHash) {
                    [void]$errors.Add("destination-hash-mismatch:$path")
                }
            }
        }
    }

    $treeFiles = @()
    if (Test-Path -LiteralPath $sourceDir -PathType Container) {
        $sourceDirFull = [System.IO.Path]::GetFullPath($sourceDir)
        $treeFiles = @(
            Get-ChildItem -LiteralPath $sourceDir -File -Recurse -ErrorAction Stop |
                ForEach-Object { ConvertTo-ASnapshotRelativePath -Path $_.FullName.Substring($sourceDirFull.Length).TrimStart('\') } |
                Sort-Object -Unique
        )
    }
    foreach ($treePath in $treeFiles) {
        if (-not $manifestSet.ContainsKey($treePath.ToLowerInvariant())) {
            [void]$errors.Add("unmanifested-file:$treePath")
        }
    }
    $expectedTreeFileCount = if ($isVx) { @($manifest.files | Where-Object { [bool]$_.exists }).Count } else { $manifestSet.Count }
    if ([int]$manifest.fileCount -ne $manifestSet.Count -or $expectedTreeFileCount -ne $treeFiles.Count) {
        [void]$errors.Add('manifest-file-count-mismatch')
    }

    return [pscustomobject]@{
        Pass = ($errors.Count -eq 0)
        FileCount = [int]$manifestSet.Count
        Errors = @($errors)
        ManifestPath = $manifestPath
    }
}

function Restore-ASuccessSnapshotAbsentTargets {
    param(
        [string]$SnapshotDir,
        [string]$DestinationRoot,
        [string[]]$AllowedPaths = @(),
        [AllowEmptyString()][string]$ExpectedTargetSetSha256 = ''
    )

    $integrity = Test-ASuccessSnapshotIntegrity -SnapshotDir $SnapshotDir -AllowedPaths $AllowedPaths -ExpectedTargetSetSha256 $ExpectedTargetSetSha256
    if (-not $integrity.Pass) {
        throw "A snapshot absent-target restore blocked by integrity check: $($integrity.Errors -join ',')"
    }

    $manifest = Get-Content -LiteralPath $integrity.ManifestPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    $isVx = $manifest.PSObject.Properties.Name -contains 'schema_version' -and [string]$manifest.schema_version -eq 'vx-draft'
    if (-not $isVx) {
        return [pscustomobject]@{ RemovedCount = 0; AbsentPaths = @() }
    }

    $destinationRootFull = [System.IO.Path]::GetFullPath($DestinationRoot).TrimEnd('\') + '\'
    $absentPaths = New-Object 'System.Collections.Generic.List[string]'
    $removedCount = 0
    foreach ($entry in @($manifest.files)) {
        if (-not ($entry.PSObject.Properties.Name -contains 'exists') -or [bool]$entry.exists) {
            continue
        }

        $relativePath = ConvertTo-ASnapshotRelativePath -Path ([string]$entry.path)
        $destinationPath = [System.IO.Path]::GetFullPath((Join-Path $DestinationRoot $relativePath.Replace('/', '\')))
        if (-not $destinationPath.StartsWith($destinationRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "A snapshot absent target escaped destination root: $relativePath"
        }
        if (Test-Path -LiteralPath $destinationPath -PathType Container) {
            throw "A snapshot absent target is a directory: $relativePath"
        }
        if (Test-Path -LiteralPath $destinationPath -PathType Leaf) {
            Remove-Item -LiteralPath $destinationPath -Force -ErrorAction Stop
            $removedCount++
        }
        if (Test-Path -LiteralPath $destinationPath) {
            throw "A snapshot absent target restore failed: $relativePath"
        }
        [void]$absentPaths.Add($relativePath)
    }

    return [pscustomobject]@{
        RemovedCount = $removedCount
        AbsentPaths = @($absentPaths)
    }
}
