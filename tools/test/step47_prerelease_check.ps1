param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$ListFile = "testdata/step47_reserved_list_default.txt",
    [string]$Scope = "reserved",
    [switch]$EnableEarlyUnknown,
    [switch]$RunPreclassTableGuard,
    [string]$PreclassTableGuardScript = "",
    [switch]$RunPreclassMinMatrix,
    [string]$PreclassMinMatrixScript = "",
    [switch]$RunPreclassP1Gate,
    [string]$PreclassCaseListFile = "",
    [string]$PreclassGroupThresholdFile = "",
    [string]$PreclassGroupThresholdSpec = "",
    [string]$OutDirRoot = ""
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not $ListFile -or $ListFile.Trim().Length -eq 0) {
    Write-Error "List file path is empty"
    exit 2
}

if (-not (Test-Path $ListFile)) {
    Write-Error "List file not found: $ListFile"
    exit 2
}

$scopeNorm = $Scope.Trim().ToLowerInvariant()
if ($scopeNorm -notin @("minimal", "reserved", "all")) {
    Write-Error "Invalid -Scope '$Scope' (expected minimal|reserved|all)"
    exit 2
}

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\step47_prerelease"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$readinessScript = Join-Path $PSScriptRoot "step47_readiness_matrix.ps1"
$abScript = Join-Path $PSScriptRoot "step47_ab_compare.ps1"
$rollbackScript = Join-Path $PSScriptRoot "step47_rollback_drill.ps1"
$preclassP1Script = Join-Path $PSScriptRoot "preclass_p1_gate_matrix.ps1"
if (-not $PreclassTableGuardScript -or $PreclassTableGuardScript.Trim().Length -eq 0) {
    $PreclassTableGuardScript = Join-Path $PSScriptRoot "preclass_table_guard.ps1"
}
if (-not $PreclassMinMatrixScript -or $PreclassMinMatrixScript.Trim().Length -eq 0) {
    $PreclassMinMatrixScript = Join-Path $PSScriptRoot "preclass_min_matrix.ps1"
}

if ($RunPreclassTableGuard) {
    if (-not (Test-Path $PreclassTableGuardScript)) {
        Write-Error "Preclass table guard script not found: $PreclassTableGuardScript"
        exit 2
    }
    Write-Output ("[STEP47-CHECK] preclass_table_guard=enabled script={0}" -f $PreclassTableGuardScript)
}
else {
    Write-Output "[STEP47-CHECK] preclass_table_guard=disabled"
}

if ($RunPreclassMinMatrix) {
    if (-not (Test-Path $PreclassMinMatrixScript)) {
        Write-Error "Preclass min matrix script not found: $PreclassMinMatrixScript"
        exit 2
    }
    Write-Output ("[STEP47-CHECK] preclass_min_matrix=enabled script={0}" -f $PreclassMinMatrixScript)
}
else {
    Write-Output "[STEP47-CHECK] preclass_min_matrix=disabled"
}

if ($RunPreclassP1Gate) {
    if (-not (Test-Path $preclassP1Script)) {
        Write-Error "Preclass gate script not found: $preclassP1Script"
        exit 2
    }

    if ($PreclassCaseListFile -and $PreclassCaseListFile.Trim().Length -gt 0 -and -not (Test-Path $PreclassCaseListFile)) {
        Write-Error "Preclass case list file not found: $PreclassCaseListFile"
        exit 2
    }

    if ($PreclassGroupThresholdFile -and $PreclassGroupThresholdFile.Trim().Length -gt 0 -and -not (Test-Path $PreclassGroupThresholdFile)) {
        Write-Error "Preclass group threshold file not found: $PreclassGroupThresholdFile"
        exit 2
    }

    Write-Output ("[STEP47-CHECK] preclass_gate=enabled case_file={0} threshold_file={1}" -f $PreclassCaseListFile, $PreclassGroupThresholdFile)
}
else {
    Write-Output "[STEP47-CHECK] preclass_gate=disabled"
}

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action,
        [string]$OutRegex
    )

    Write-Output ("[STEP47-CHECK] step={0} status=running" -f $Name)
    $raw = & $Action 2>&1
    $lines = $raw | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.Exception.Message
        }
        else {
            $_
        }
    }
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) {
        $exitCode = 0
    }

    $logPath = Join-Path $outDir ("{0}.log" -f $Name)
    $lines | Out-File -FilePath $logPath -Encoding utf8

    $text = ($lines -join "`n")
    $stepOut = ""
    if ($OutRegex -and $OutRegex.Trim().Length -gt 0) {
        $m = [regex]::Match($text, $OutRegex)
        if ($m.Success) {
            $stepOut = $m.Groups[1].Value
        }
    }

    $status = if ($exitCode -eq 0) { "pass" } else { "fail" }
    Write-Output ("[STEP47-CHECK] step={0} status={1} exit={2}" -f $Name, $status, $exitCode)

    return [pscustomobject]@{
        Name = $Name
        ExitCode = $exitCode
        Status = $status
        OutDir = $stepOut
        Log = $logPath
    }
}

$readinessResult = (Invoke-Step -Name "readiness" -OutRegex '(?m)^\[STEP47\] out_dir=(.+)$' -Action {
    & $readinessScript -BinaryPath $BinaryPath
} | Select-Object -Last 1)

$abResult = (Invoke-Step -Name "ab" -OutRegex '(?m)^\[STEP47-AB\] out_dir=(.+)$' -Action {
    if ($EnableEarlyUnknown) {
        & $abScript -BinaryPath $BinaryPath -Scope $scopeNorm -EnableEarlyUnknown -EarlyUnknownListFile $ListFile
    }
    else {
        & $abScript -BinaryPath $BinaryPath -Scope $scopeNorm -EarlyUnknownListFile $ListFile
    }
} | Select-Object -Last 1)

$rollbackResult = (Invoke-Step -Name "rollback" -OutRegex '(?m)^\[STEP47-ROLLBACK\] out_dir=(.+)$' -Action {
    if ($EnableEarlyUnknown) {
        & $rollbackScript -BinaryPath $BinaryPath -Scope $scopeNorm -EnableEarlyUnknown -EarlyUnknownListFile $ListFile
    }
    else {
        & $rollbackScript -BinaryPath $BinaryPath -Scope $scopeNorm -EarlyUnknownListFile $ListFile
    }
} | Select-Object -Last 1)

$results = @($readinessResult, $abResult, $rollbackResult)

if ($RunPreclassTableGuard) {
    $tableGuardResult = (Invoke-Step -Name "preclass-table-guard" -OutRegex '(?m)^\[PRECLASS-TABLE-GUARD\] out_dir=(.+)$' -Action {
        & $PreclassTableGuardScript
    } | Select-Object -Last 1)
    $results += $tableGuardResult
}

if ($RunPreclassMinMatrix) {
    $preclassMinResult = (Invoke-Step -Name "preclass-min-matrix" -OutRegex '(?m)^\[PRECLASS-MATRIX\] out_dir=(.+)$' -Action {
        & $PreclassMinMatrixScript -BinaryPath $BinaryPath
    } | Select-Object -Last 1)
    $results += $preclassMinResult
}

if ($RunPreclassP1Gate) {
    $preclassResult = (Invoke-Step -Name "preclass-p1-gate" -OutRegex '(?m)^\[PRECLASS-P1\] out_dir=(.+)$' -Action {
        $preclassArgs = @{
            BinaryPath = $BinaryPath
        }

        if ($PreclassCaseListFile -and $PreclassCaseListFile.Trim().Length -gt 0) {
            $preclassArgs["CaseListFile"] = $PreclassCaseListFile
        }
        if ($PreclassGroupThresholdFile -and $PreclassGroupThresholdFile.Trim().Length -gt 0) {
            $preclassArgs["GroupPassThresholdFile"] = $PreclassGroupThresholdFile
        }
        if ($PreclassGroupThresholdSpec -and $PreclassGroupThresholdSpec.Trim().Length -gt 0) {
            $preclassArgs["GroupPassThresholdSpec"] = $PreclassGroupThresholdSpec
        }

        & $preclassP1Script @preclassArgs
    } | Select-Object -Last 1)
    $results += $preclassResult
}
$summaryCsv = Join-Path $outDir "summary.csv"
$summaryTxt = Join-Path $outDir "summary.txt"
$results | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$results | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$failedCount = @($results | Where-Object { $_.ExitCode -ne 0 }).Count

Write-Output ("[STEP47-CHECK] out_dir={0}" -f $outDir)
Write-Output ("[STEP47-CHECK] summary_csv={0}" -f $summaryCsv)
Write-Output ("[STEP47-CHECK] summary_txt={0}" -f $summaryTxt)

foreach ($result in $results) {
    Write-Output ("[STEP47-CHECK] step={0} status={1} step_out={2} log={3}" -f $result.Name, $result.Status, $result.OutDir, $result.Log)
}

if ($failedCount -gt 0) {
    Write-Output ("[STEP47-CHECK] result=fail failed_steps={0}" -f $failedCount)
    exit 1
}

Write-Output "[STEP47-CHECK] result=pass"
exit 0
