$procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*unattended_ab_session_guard.ps1*" -and $_.CommandLine -like "*unattended_ab_start_20260422-2300.md*" }
if ($procs) {
    if ($procs.Count -gt 1) { $proc = $procs[0] } else { $proc = $procs }
    $pidValue = $proc.ProcessId
    Write-Host "GUARD_PID=$pidValue"
    try {
        Wait-Process -Id $pidValue -Timeout 600 -ErrorAction Stop
        Write-Host "WAIT_RESULT=exited"
    } catch {
        Write-Host "WAIT_RESULT=timeout"
    }
} else {
    Write-Host "GUARD_MISSING"
    exit 3
}

$startFile = "tmp/unattended_ab_start_20260422-2300.md"
$lines = Get-Content $startFile

function Get-LineValue($targetKey) {
    foreach ($line in $using:lines) {
        if ($line.StartsWith($targetKey + "=")) {
            return $line.Substring($targetKey.Length + 1).Trim()
        }
    }
    return ""
}

$aStatus = ""
$bStatus = ""
$sessionStatus = ""
$sessionNotes = ""

foreach ($l in $lines) {
    if ($l.StartsWith("A_FINAL_STATUS=")) { $aStatus = $l.Substring(15).Trim() }
    if ($l.StartsWith("B_FINAL_STATUS=")) { $bStatus = $l.Substring(15).Trim() }
    if ($l.StartsWith("SESSION_FINAL_STATUS=")) { $sessionStatus = $l.Substring(21).Trim() }
    if ($l.StartsWith("SESSION_FINAL_NOTES=")) { $sessionNotes = $l.Substring(20).Trim() }
}

Write-Host "A_FINAL_STATUS=$aStatus"
Write-Host "B_FINAL_STATUS=$bStatus"
Write-Host "SESSION_FINAL_STATUS=$sessionStatus"

$supLog = ""
$compLog = ""
$liveStat = ""

if ($sessionNotes -match "supervisor_log=([^;]+)") { $supLog = $Matches[1].Trim() }
if ($sessionNotes -match "companion_log=([^;]+)") { $compLog = $Matches[1].Trim() }
if ($sessionNotes -match "live_status=([^;]+)") { $liveStat = $Matches[1].Trim() }

if ($liveStat -and (Test-Path $liveStat)) {
    Write-Host "--- LIVE STATUS ---"
    Get-Content $liveStat -Raw | Write-Host
}

if ($supLog -and (Test-Path $supLog)) {
    Write-Host "--- SUPERVISOR LOG (TAIL 30) ---"
    Get-Content $supLog -Tail 30 | Write-Host
}

if ($compLog -and (Test-Path $compLog)) {
    Write-Host "--- COMPANION LOG (TAIL 30) ---"
    Get-Content $compLog -Tail 30 | Write-Host
}
