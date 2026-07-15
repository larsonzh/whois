Set-StrictMode -Version Latest

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

function Get-ASnapshotTaskTargetPaths {
    param([string]$TaskDefinitionFile)

    if ([string]::IsNullOrWhiteSpace($TaskDefinitionFile) -or -not (Test-Path -LiteralPath $TaskDefinitionFile -PathType Leaf)) {
        throw "A snapshot task definition not found: $TaskDefinitionFile"
    }

    $task = Get-Content -LiteralPath $TaskDefinitionFile -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    $paths = New-Object 'System.Collections.Generic.List[string]'
    if ($task.PSObject.Properties.Name -contains 'targetFile') {
        $path = ConvertTo-ASnapshotRelativePath -Path ([string]$task.targetFile)
        if (-not [string]::IsNullOrWhiteSpace($path)) {
            [void]$paths.Add($path)
        }
    }
    if ($task.PSObject.Properties.Name -contains 'targetFiles') {
        foreach ($target in @($task.targetFiles)) {
            if ($null -eq $target -or -not ($target.PSObject.Properties.Name -contains 'file')) {
                continue
            }
            $path = ConvertTo-ASnapshotRelativePath -Path ([string]$target.file)
            if (-not [string]::IsNullOrWhiteSpace($path)) {
                [void]$paths.Add($path)
            }
        }
    }

    $result = @($paths | Sort-Object -Unique)
    if ($result.Count -eq 0) {
        throw "A snapshot task definition has no valid target paths: $TaskDefinitionFile"
    }
    return $result
}

function Write-ASuccessSnapshotManifest {
    param([string]$SnapshotDir)

    $sourceDir = Join-Path $SnapshotDir 'source'
    $sourceFilesPath = Join-Path $SnapshotDir 'source_files.txt'
    if (-not (Test-Path -LiteralPath $sourceDir -PathType Container)) {
        throw "A snapshot source directory missing: $sourceDir"
    }
    if (-not (Test-Path -LiteralPath $sourceFilesPath -PathType Leaf)) {
        throw "A snapshot source file list missing: $sourceFilesPath"
    }

    $entries = @()
    $paths = @(
        Get-Content -LiteralPath $sourceFilesPath -Encoding utf8 -ErrorAction Stop |
            ForEach-Object { ConvertTo-ASnapshotRelativePath -Path ([string]$_) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )
    foreach ($path in $paths) {
        $filePath = Join-Path $sourceDir $path.Replace('/', '\')
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
            throw "A snapshot listed source file missing: $path"
        }
        $item = Get-Item -LiteralPath $filePath
        $hash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $entries += [pscustomobject][ordered]@{
            path = $path
            length = [long]$item.Length
            sha256 = $hash
        }
    }

    $manifest = [ordered]@{
        schema = 'A_SUCCESS_SNAPSHOT_MANIFEST_V1'
        algorithm = 'SHA256'
        fileCount = [int]@($entries).Count
        files = @($entries)
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
        [string]$DestinationRoot = ''
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
        if (-not (Test-Path -LiteralPath $snapshotFile -PathType Leaf)) {
            [void]$errors.Add("snapshot-file-missing:$path")
            continue
        }
        $item = Get-Item -LiteralPath $snapshotFile
        $actualHash = (Get-FileHash -LiteralPath $snapshotFile -Algorithm SHA256).Hash.ToLowerInvariant()
        if ([long]$entry.length -ne [long]$item.Length) {
            [void]$errors.Add("snapshot-length-mismatch:$path")
        }
        if ([string]$entry.sha256 -ne $actualHash) {
            [void]$errors.Add("snapshot-hash-mismatch:$path")
        }

        if (-not [string]::IsNullOrWhiteSpace($DestinationRoot)) {
            $destinationFile = Join-Path $DestinationRoot $path.Replace('/', '\')
            if (-not (Test-Path -LiteralPath $destinationFile -PathType Leaf)) {
                [void]$errors.Add("destination-file-missing:$path")
            }
            else {
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
    if ([int]$manifest.fileCount -ne $manifestSet.Count -or $manifestSet.Count -ne $treeFiles.Count) {
        [void]$errors.Add('manifest-file-count-mismatch')
    }

    return [pscustomobject]@{
        Pass = ($errors.Count -eq 0)
        FileCount = [int]$manifestSet.Count
        Errors = @($errors)
        ManifestPath = $manifestPath
    }
}
