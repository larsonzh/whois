param(
    [string]$TemplateFile = 'docs\UNATTENDED_AB_START_TEMPLATE_CN.md',
    [AllowEmptyString()][string]$OutputFile = '',
    [AllowEmptyString()][string]$ATaskDefinition = '',
    [AllowEmptyString()][string]$BTaskDefinition = '',
    [AllowEmptyString()][string]$Window = '',
    [AllowEmptyString()][string]$RemoteIp = '',
    [AllowEmptyString()][string]$RemoteUser = '',
    [AllowEmptyString()][string]$RemoteKeyPath = '',
    [string[]]$Set = @(),
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoPath {
    param(
        [string]$RepoRoot,
        [string]$Path,
        [bool]$MustExist = $true
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    $combined = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $RepoRoot $Path }
    $fullPath = [System.IO.Path]::GetFullPath($combined)

    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath)) {
        throw "Path not found: $fullPath"
    }

    return $fullPath
}

function Get-TemplateBlock {
    param([string]$TemplatePath)

    $lines = @(Get-Content -LiteralPath $TemplatePath -ErrorAction Stop)
    $inFence = $false
    $block = New-Object 'System.Collections.Generic.List[string]'

    foreach ($line in $lines) {
        if ($line.Trim().StartsWith('```')) {
            if (-not $inFence) {
                $inFence = $true
                $block = New-Object 'System.Collections.Generic.List[string]'
                continue
            }

            $inFence = $false
            $candidate = @($block)
            $hasHeader = $candidate -contains 'AB_UNATTENDED_START_V1'
            $hasKeyValue = @($candidate | Where-Object { $_ -match '^[A-Z0-9_]+=.*$' }).Count -gt 10
            if ($hasHeader -and $hasKeyValue) {
                return $candidate
            }
            continue
        }

        if ($inFence) {
            [void]$block.Add([string]$line)
        }
    }

    throw "Unable to locate start-file template block in $TemplatePath"
}

function Convert-LinesToOrderedMap {
    param([string[]]$Lines)

    $orderedKeys = New-Object 'System.Collections.Generic.List[string]'
    $map = [ordered]@{}

    foreach ($line in @($Lines)) {
        if ($line -match '^([A-Z0-9_]+)=(.*)$') {
            $key = $Matches[1]
            $value = $Matches[2]
            if (-not $map.Contains($key)) {
                [void]$orderedKeys.Add($key)
            }
            $map[$key] = $value
        }
    }

    return [pscustomobject]@{
        OrderedKeys = @($orderedKeys)
        Map = $map
    }
}

function Get-NormalizedTaskDefinitionValue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    $normalized = $Value.Trim().Replace('\\', '/')
    if (-not $normalized.EndsWith('.json', [System.StringComparison]::OrdinalIgnoreCase)) {
        $normalized = "$normalized.json"
    }

    if (-not $normalized.StartsWith('testdata/', [System.StringComparison]::OrdinalIgnoreCase) -and -not [System.IO.Path]::IsPathRooted($normalized)) {
        $normalized = "testdata/$normalized"
    }

    return $normalized
}

function ConvertTo-KeyValueOverride {
    param([string]$Entry)

    if ([string]::IsNullOrWhiteSpace($Entry)) {
        throw 'Override entry must not be empty.'
    }

    $idx = $Entry.IndexOf('=')
    if ($idx -lt 1) {
        throw "Invalid override entry (expected KEY=VALUE): $Entry"
    }

    $key = $Entry.Substring(0, $idx).Trim()
    $value = $Entry.Substring($idx + 1)

    if (-not ($key -match '^[A-Z0-9_]+$')) {
        throw "Invalid override key: $key"
    }

    return [pscustomobject]@{ Key = $key; Value = $value }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$templatePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $TemplateFile -MustExist $true

$resolvedOutput = if ([string]::IsNullOrWhiteSpace($OutputFile)) {
    $defaultName = "unattended_ab_start_{0}.md" -f (Get-Date -Format 'yyyyMMdd-HHmm')
    Resolve-RepoPath -RepoRoot $repoRoot -Path (Join-Path 'tmp' $defaultName) -MustExist $false
}
else {
    Resolve-RepoPath -RepoRoot $repoRoot -Path $OutputFile -MustExist $false
}

if ((Test-Path -LiteralPath $resolvedOutput) -and -not $Force.IsPresent) {
    throw "Output file already exists. Use -Force to overwrite: $resolvedOutput"
}

$templateBlock = Get-TemplateBlock -TemplatePath $templatePath
$templateState = Convert-LinesToOrderedMap -Lines $templateBlock
$values = [ordered]@{}
foreach ($key in @($templateState.OrderedKeys)) {
    $values[$key] = [string]$templateState.Map[$key]
}

if (-not [string]::IsNullOrWhiteSpace($ATaskDefinition)) {
    $values['A_TASK_DEFINITION'] = Get-NormalizedTaskDefinitionValue -Value $ATaskDefinition
}
if (-not [string]::IsNullOrWhiteSpace($BTaskDefinition)) {
    $values['B_TASK_DEFINITION'] = Get-NormalizedTaskDefinitionValue -Value $BTaskDefinition
}
if (-not [string]::IsNullOrWhiteSpace($Window)) {
    $values['WINDOW'] = $Window
}
if (-not [string]::IsNullOrWhiteSpace($RemoteIp)) {
    $values['REMOTE_IP'] = $RemoteIp
}
if (-not [string]::IsNullOrWhiteSpace($RemoteUser)) {
    $values['REMOTE_USER'] = $RemoteUser
}
if (-not [string]::IsNullOrWhiteSpace($RemoteKeyPath)) {
    $values['REMOTE_KEYPATH'] = $RemoteKeyPath
}

$extraKeys = New-Object 'System.Collections.Generic.List[string]'
foreach ($entry in @($Set)) {
    $kv = ConvertTo-KeyValueOverride -Entry $entry
    if (-not $values.Contains($kv.Key)) {
        [void]$extraKeys.Add($kv.Key)
    }
    $values[$kv.Key] = [string]$kv.Value
}

$outputLines = New-Object 'System.Collections.Generic.List[string]'
foreach ($line in @($templateBlock)) {
    if ($line -match '^([A-Z0-9_]+)=(.*)$') {
        $key = $Matches[1]
        if ($values.Contains($key)) {
            [void]$outputLines.Add("$key=$($values[$key])")
        }
        else {
            [void]$outputLines.Add($line)
        }
    }
    else {
        [void]$outputLines.Add($line)
    }
}

foreach ($extraKey in @($extraKeys)) {
    [void]$outputLines.Add("$extraKey=$($values[$extraKey])")
}

$outputDir = Split-Path -Parent $resolvedOutput
if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

Set-Content -LiteralPath $resolvedOutput -Value @($outputLines) -Encoding utf8

Write-Output ("[CREATE-START-FILE] template_file={0}" -f $templatePath)
Write-Output ("[CREATE-START-FILE] output_file={0}" -f $resolvedOutput)
Write-Output ("[CREATE-START-FILE] total_keys={0}" -f @($values.Keys).Count)
Write-Output ("[CREATE-START-FILE] a_task={0}" -f [string]$values['A_TASK_DEFINITION'])
Write-Output ("[CREATE-START-FILE] b_task={0}" -f [string]$values['B_TASK_DEFINITION'])
Write-Output ("[CREATE-START-FILE] window={0}" -f [string]$values['WINDOW'])
