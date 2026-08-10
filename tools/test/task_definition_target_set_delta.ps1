Set-StrictMode -Version Latest

function Get-TaskTargetSetSnapshot {
    param([Parameter(Mandatory = $true)][object]$Registry)

    $targets = @($Registry.Targets | Sort-Object File | ForEach-Object {
        $exists = Test-Path -LiteralPath $_.FullPath -PathType Leaf
        [pscustomobject]@{
            Id = [string]$_.Id
            Path = [string]$_.File
            Exists = [bool]$exists
            Sha256 = if ($exists) { (Get-FileHash -LiteralPath $_.FullPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        }
    })
    return [pscustomobject]@{
        TargetSetSha256 = [string]$Registry.TargetSetSha256
        Targets = $targets
    }
}

function Compare-TaskTargetSetSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Before,
        [Parameter(Mandatory = $true)][object]$After
    )

    if ([string]$Before.TargetSetSha256 -ne [string]$After.TargetSetSha256) {
        throw 'target registry drift while comparing source delta'
    }
    $beforeById = @{}
    foreach ($entry in @($Before.Targets)) { $beforeById[[string]$entry.Id] = $entry }
    $afterById = @{}
    foreach ($entry in @($After.Targets)) { $afterById[[string]$entry.Id] = $entry }
    if ($beforeById.Count -ne $afterById.Count) {
        throw 'target inventory drift while comparing source delta'
    }

    $changedTargets = New-Object System.Collections.Generic.List[string]
    foreach ($id in @($beforeById.Keys | Sort-Object)) {
        if (-not $afterById.ContainsKey($id)) {
            throw "target inventory drift while comparing source delta id=$id"
        }
        $beforeEntry = $beforeById[$id]
        $afterEntry = $afterById[$id]
        if ([string]$beforeEntry.Path -ne [string]$afterEntry.Path) {
            throw "target path drift while comparing source delta id=$id"
        }
        if ([bool]$beforeEntry.Exists -ne [bool]$afterEntry.Exists -or
            [string]$beforeEntry.Sha256 -ne [string]$afterEntry.Sha256) {
            $changedTargets.Add($id)
        }
    }
    return [pscustomobject]@{
        Changed = ($changedTargets.Count -gt 0)
        ChangedTargets = $changedTargets.ToArray()
        TargetCount = $beforeById.Count
    }
}