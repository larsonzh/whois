param(
    [string]$TemplateFile = 'docs\UNATTENDED_AB_START_TEMPLATE_CN.md',
    [AllowEmptyString()][string]$OutputFile = '',
    [ValidateSet('active', 'smoke')][string]$OutputCategory = 'active',
    [ValidateSet('normal', 'anti-missent', 'low-disturb', 'event-only', 'all-modes')][string]$Mode = 'normal',
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

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'CREATE-UNATTENDED-AB-START-FILE'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

$pathGuardModulePath = Join-Path $PSScriptRoot 'path_write_guard.ps1'
if (-not (Test-Path -LiteralPath $pathGuardModulePath)) {
    throw "Missing script: $pathGuardModulePath"
}
. $pathGuardModulePath

function Get-Utf8Text {
    param([string]$Path)

    $encoding = New-Object System.Text.UTF8Encoding($true, $true)
    try {
        return [System.IO.File]::ReadAllText($Path, $encoding)
    }
    catch {
        throw "Failed to read UTF-8 text file: $Path; detail=$($_.Exception.Message)"
    }
}

function Test-Utf8TextReplacementChar {
    param(
        [string]$Text,
        [string]$Path,
        [string]$Tag
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return
    }

    $replacement = [string][char]0xFFFD
    if ($Text.IndexOf($replacement, [System.StringComparison]::Ordinal) -lt 0) {
        return
    }

    $lineNumbers = New-Object 'System.Collections.Generic.List[string]'
    $lines = @($Text -split "`r?`n", -1)
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if (([string]$lines[$index]).Contains($replacement)) {
            [void]$lineNumbers.Add([string]($index + 1))
        }
    }

    throw ("[{0}] detected replacement character (U+FFFD) in {1} at line(s): {2}. Please repair file encoding/content before proceeding." -f $Tag, $Path, ($lineNumbers -join ','))
}

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

    $templateText = Get-Utf8Text -Path $TemplatePath
    Test-Utf8TextReplacementChar -Text $templateText -Path $TemplatePath -Tag 'CREATE-START-FILE'

    $lines = @($templateText -split "`r?`n")
    if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -eq '') {
        if ($lines.Count -eq 1) {
            $lines = @()
        }
        else {
            $lines = @($lines[0..($lines.Count - 2)])
        }
    }

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

    $rawCandidate = @($lines | Where-Object { $_ -match '^(#|\s*$)' -or $_ -match '^[A-Z0-9_]+=.*$' -or $_ -eq 'AB_UNATTENDED_START_V1' })
    $rawHasHeader = $lines -contains 'AB_UNATTENDED_START_V1'
    $rawHasKeyValue = @($lines | Where-Object { $_ -match '^[A-Z0-9_]+=.*$' }).Count -gt 10
    if ($rawHasHeader -and $rawHasKeyValue -and $rawCandidate.Count -eq $lines.Count) {
        return $lines
    }

    throw "Unable to locate start-file template block in $TemplatePath"
}

function Convert-LinesToOrderedMap {
    param([string[]]$Lines)

    $orderedKeys = New-Object 'System.Collections.Generic.List[string]'
    $map = [ordered]@{}
    $keyLineMap = @{}
    $lineNo = 0

    foreach ($line in @($Lines)) {
        $lineNo++
        if ($line -match '^([A-Z0-9_]+)=(.*)$') {
            $key = $Matches[1]
            $value = $Matches[2]

            if ($map.Contains($key)) {
                $firstLine = [int]$keyLineMap[$key]
                throw ("Duplicate key '{0}' detected in template block at line {1} and line {2}." -f $key, $firstLine, $lineNo)
            }

            $keyLineMap[$key] = $lineNo
            [void]$orderedKeys.Add($key)
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

function Get-ModeTemplatePath {
    param(
        [string]$RepoRoot,
        [string]$DefaultTemplateFile,
        [string]$SelectedMode
    )

    switch ($SelectedMode) {
        'normal' {
            return Resolve-RepoPath -RepoRoot $RepoRoot -Path $DefaultTemplateFile -MustExist $true
        }
        'anti-missent' {
            return Resolve-RepoPath -RepoRoot $RepoRoot -Path $DefaultTemplateFile -MustExist $true
        }
        'low-disturb' {
            return Resolve-RepoPath -RepoRoot $RepoRoot -Path 'testdata\unattended_start\smoke\unattended_ab_start_status_ticket_low_disturb_smoke.md' -MustExist $true
        }
        'event-only' {
            return Resolve-RepoPath -RepoRoot $RepoRoot -Path 'testdata\unattended_start\smoke\unattended_ab_start_event_only_smoke.md' -MustExist $true
        }
    }

    throw "Unsupported mode: $SelectedMode"
}

function Set-ModeDefaults {
    param(
        [System.Collections.Specialized.OrderedDictionary]$Values,
        [string]$SelectedMode
    )

    if ($SelectedMode -eq 'anti-missent') {
        $Values['AI_CHAT_POLICY_WORK_MODE'] = 'anti-missent'
        $Values['AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY'] = 'true'
    }
}

function Get-ModeFileSuffix {
    param([string]$SelectedMode)

    switch ($SelectedMode) {
        'normal' { return '' }
        'anti-missent' { return '_anti_missent' }
        'low-disturb' { return '_low_disturb' }
        'event-only' { return '_event_only' }
    }

    throw "Unsupported mode: $SelectedMode"
}

function Resolve-OutputPathForMode {
    param(
        [string]$RepoRoot,
        [string]$ResolvedBaseOutput,
        [string]$SelectedMode,
        [bool]$GeneratingAllModes
    )

    if (-not $GeneratingAllModes -or $SelectedMode -eq 'normal') {
        return $ResolvedBaseOutput
    }

    $directory = Split-Path -Parent $ResolvedBaseOutput
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($ResolvedBaseOutput)
    $extension = [System.IO.Path]::GetExtension($ResolvedBaseOutput)
    $suffix = Get-ModeFileSuffix -SelectedMode $SelectedMode
    $candidate = Join-Path $directory ($fileName + $suffix + $extension)
    return Resolve-RepoPath -RepoRoot $RepoRoot -Path $candidate -MustExist $false
}

function Write-StartFileForMode {
    param(
        [string]$RepoRoot,
        [string]$TemplatePath,
        [string]$ResolvedOutput,
        [string]$SelectedMode,
        [AllowEmptyString()][string]$ATaskDefinitionValue,
        [AllowEmptyString()][string]$BTaskDefinitionValue,
        [AllowEmptyString()][string]$WindowValue,
        [AllowEmptyString()][string]$RemoteIpValue,
        [AllowEmptyString()][string]$RemoteUserValue,
        [AllowEmptyString()][string]$RemoteKeyPathValue,
        [string[]]$SetValues,
        [bool]$ForceWrite
    )

    $modeOutputPath = Assert-GuardUnattendedStartFileOutputPath -RepoRoot $RepoRoot -Path $ResolvedOutput
    if ((Test-Path -LiteralPath $modeOutputPath) -and -not $ForceWrite) {
        throw "Output file already exists. Use -Force to overwrite: $modeOutputPath"
    }

    $templateBlock = Get-TemplateBlock -TemplatePath $TemplatePath
    $templateState = Convert-LinesToOrderedMap -Lines $templateBlock
    $values = [ordered]@{}
    foreach ($key in @($templateState.OrderedKeys)) {
        $values[$key] = [string]$templateState.Map[$key]
    }

    Set-ModeDefaults -Values $values -SelectedMode $SelectedMode

    if (-not [string]::IsNullOrWhiteSpace($ATaskDefinitionValue)) {
        $values['A_TASK_DEFINITION'] = Get-NormalizedTaskDefinitionValue -Value $ATaskDefinitionValue
    }
    if (-not [string]::IsNullOrWhiteSpace($BTaskDefinitionValue)) {
        $values['B_TASK_DEFINITION'] = Get-NormalizedTaskDefinitionValue -Value $BTaskDefinitionValue
    }
    if (-not [string]::IsNullOrWhiteSpace($WindowValue)) {
        $values['WINDOW'] = $WindowValue
    }
    if (-not [string]::IsNullOrWhiteSpace($RemoteIpValue)) {
        $values['REMOTE_IP'] = $RemoteIpValue
    }
    if (-not [string]::IsNullOrWhiteSpace($RemoteUserValue)) {
        $values['REMOTE_USER'] = $RemoteUserValue
    }
    if (-not [string]::IsNullOrWhiteSpace($RemoteKeyPathValue)) {
        $values['REMOTE_KEYPATH'] = $RemoteKeyPathValue
    }

    $extraKeys = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in @($SetValues)) {
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

    $outputDir = Split-Path -Parent $modeOutputPath
    if (-not (Test-Path -LiteralPath $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    $outputText = ($outputLines -join "`n") + "`n"
    Test-Utf8TextReplacementChar -Text $outputText -Path $modeOutputPath -Tag 'CREATE-START-FILE'
    $tempPath = "$modeOutputPath.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    try {
        $utf8WithBom = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($tempPath, $outputText, $utf8WithBom)
        Move-Item -LiteralPath $tempPath -Destination $modeOutputPath -Force
        $tempPath = ''
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }

    return [pscustomobject]@{
        Mode = $SelectedMode
        TemplatePath = $TemplatePath
        OutputPath = $modeOutputPath
        Values = $values
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

$resolvedBaseOutput = if ([string]::IsNullOrWhiteSpace($OutputFile)) {
    $defaultName = "unattended_ab_start_{0}.md" -f (Get-Date -Format 'yyyyMMdd-HHmm')
    $defaultDir = Join-Path 'testdata\unattended_start' $OutputCategory
    Resolve-RepoPath -RepoRoot $repoRoot -Path (Join-Path $defaultDir $defaultName) -MustExist $false
}
else {
    Resolve-RepoPath -RepoRoot $repoRoot -Path $OutputFile -MustExist $false
}

$resolvedBaseOutput = Assert-GuardUnattendedStartFileOutputPath -RepoRoot $repoRoot -Path $resolvedBaseOutput

$generateAllModes = ($Mode -eq 'all-modes')

$selectedModes = if ($generateAllModes) {
    @('normal', 'anti-missent', 'low-disturb', 'event-only')
}
else {
    @($Mode)
}

$results = New-Object 'System.Collections.Generic.List[object]'
foreach ($selectedMode in @($selectedModes)) {
    $templatePath = Get-ModeTemplatePath -RepoRoot $repoRoot -DefaultTemplateFile $TemplateFile -SelectedMode $selectedMode
    $modeOutputPath = Resolve-OutputPathForMode -RepoRoot $repoRoot -ResolvedBaseOutput $resolvedBaseOutput -SelectedMode $selectedMode -GeneratingAllModes $generateAllModes
    $result = Write-StartFileForMode -RepoRoot $repoRoot -TemplatePath $templatePath -ResolvedOutput $modeOutputPath -SelectedMode $selectedMode -ATaskDefinitionValue $ATaskDefinition -BTaskDefinitionValue $BTaskDefinition -WindowValue $Window -RemoteIpValue $RemoteIp -RemoteUserValue $RemoteUser -RemoteKeyPathValue $RemoteKeyPath -SetValues $Set -ForceWrite $Force.IsPresent
    [void]$results.Add($result)
}

foreach ($result in $results.ToArray()) {
    Write-Output ("[CREATE-START-FILE] template_file={0}" -f $result.TemplatePath)
    Write-Output ("[CREATE-START-FILE] mode={0}" -f [string]$result.Mode)
    Write-Output ("[CREATE-START-FILE] output_file={0}" -f [string]$result.OutputPath)
    Write-Output ("[CREATE-START-FILE] total_keys={0}" -f @($result.Values.Keys).Count)
    Write-Output ("[CREATE-START-FILE] a_task={0}" -f [string]$result.Values['A_TASK_DEFINITION'])
    Write-Output ("[CREATE-START-FILE] b_task={0}" -f [string]$result.Values['B_TASK_DEFINITION'])
    Write-Output ("[CREATE-START-FILE] window={0}" -f [string]$result.Values['WINDOW'])
}
