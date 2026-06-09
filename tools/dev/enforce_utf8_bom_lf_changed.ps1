param(
    [AllowEmptyString()][string]$RepoRoot = '',
    [ValidateSet('check', 'fix')][string]$Mode = 'check',
    [ValidateSet('off', 'warn', 'enforce')][string]$Policy = 'enforce',
    [int]$MaxReport = 120,
    [string[]]$Extensions = @('.ps1', '.json', '.md'),
    [string[]]$ExcludePaths = @(),
    [switch]$IncludeUntracked,
    [string[]]$TargetPaths = @(),
    [switch]$FailIfLocked
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Enter-EncodingMutex {
    param(
        [string]$Root,
        [bool]$FailOnLock
    )

    $fullPath = [System.IO.Path]::GetFullPath($Root).ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hashBytes = $sha1.ComputeHash($bytes)
    }
    finally {
        $sha1.Dispose()
    }

    $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    $name = "Global\whois-encoding-policy-$hash"
    $mutex = New-Object System.Threading.Mutex($false, $name)

    $acquired = $false
    $waitWatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }
        finally {
            $waitWatch.Stop()
        }

        if (-not $acquired) {
            if ($FailOnLock) {
                throw ("encoding mutex busy: {0}" -f $name)
            }

            Write-Output ("[ENCODING-POLICY-CHANGED] lock=busy action=skip mutex={0}" -f $name)
            Write-Output ("[ENCODING-POLICY-CHANGED] lock_metrics lock_busy=true lock_busy_count=1 lock_wait_ms={0} lock_name={1}" -f [int]$waitWatch.ElapsedMilliseconds, $name)
            $mutex.Dispose()
            exit 0
        }

        return [pscustomobject]@{ Name = $name; Mutex = $mutex; WaitMs = [int]$waitWatch.ElapsedMilliseconds }
    }
    catch {
        if ($null -ne $mutex) {
            try { $mutex.Dispose() } catch { Write-Verbose ("Suppress dispose failure: {0}" -f $_.Exception.Message) }
        }
        throw
    }
}

function Convert-ToCandidateRelativePath {
    param(
        [string]$Root,
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $normalized = $Path.Trim().Replace('\\', '/')
    if ([System.IO.Path]::IsPathRooted($normalized)) {
        return Convert-ToRepoRelativePath -Root $Root -Path $normalized
    }

    return $normalized
}

function Convert-ToRepoRelativePath {
    param(
        [string]$Root,
        [string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    if ($pathFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        $rel = $pathFull.Substring($rootFull.Length).TrimStart([char]92, [char]47)
        return $rel.Replace('\\', '/')
    }

    return $pathFull.Replace('\\', '/')
}

function Test-ExcludedPath {
    param(
        [string]$RelativePath,
        [string[]]$Excluded
    )

    if ($null -eq $Excluded -or $Excluded.Count -eq 0) {
        return $false
    }

    foreach ($prefix in $Excluded) {
        if ([string]::IsNullOrWhiteSpace($prefix)) {
            continue
        }

        $normalizedPrefix = $prefix.Replace('\\', '/').Trim()
        if ($RelativePath.StartsWith($normalizedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Get-GitOutputText {
    param(
        [string]$Root,
        [string[]]$GitArgs,
        [string]$Name
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Git CRLF warnings are emitted on stderr; keep them in output and handle by pattern.
        $ErrorActionPreference = 'Continue'
        $output = @((& git -C $Root @GitArgs 2>&1) | ForEach-Object { [string]$_ })
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    if ($exitCode -ne 0) {
        $detail = @($output | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        throw ("git {0} failed exit={1} detail={2}" -f $Name, $exitCode, ($detail -join ' | '))
    }

    return @($output)
}

function Get-ChangedCandidateFileList {
    param(
        [string]$Root,
        [switch]$IncludeUntracked
    )

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    $gitWarningPattern = '^\s*(warning:|git(\.exe)?\s*:\s*warning:)'

    $unstaged = Get-GitOutputText -Root $Root -GitArgs @('diff', '--name-only', '--diff-filter=ACMR', '--') -Name 'diff'
    foreach ($line in @($unstaged)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if (([string]$line).Trim() -match $gitWarningPattern) {
            continue
        }

        [void]$set.Add(([string]$line).Trim().Replace('\\', '/'))
    }

    $staged = Get-GitOutputText -Root $Root -GitArgs @('diff', '--cached', '--name-only', '--diff-filter=ACMR', '--') -Name 'diff --cached'
    foreach ($line in @($staged)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if (([string]$line).Trim() -match $gitWarningPattern) {
            continue
        }

        [void]$set.Add(([string]$line).Trim().Replace('\\', '/'))
    }

    if ($IncludeUntracked.IsPresent) {
        $untracked = Get-GitOutputText -Root $Root -GitArgs @('ls-files', '--others', '--exclude-standard', '--') -Name 'ls-files --others'
        foreach ($line in @($untracked)) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            if (([string]$line).Trim() -match $gitWarningPattern) {
                continue
            }

            [void]$set.Add(([string]$line).Trim().Replace('\\', '/'))
        }
    }

    return @($set)
}

function Get-EncodingStatus {
    param([string]$FilePath)

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)
    $hasCr = ([Array]::IndexOf($bytes, [byte]13) -ge 0)
    $hasLf = ([Array]::IndexOf($bytes, [byte]10) -ge 0)

    $eol = if (-not $hasCr -and $hasLf) {
        'LF'
    }
    elseif (-not $hasCr -and -not $hasLf) {
        'None'
    }
    elseif ($hasCr -and $hasLf) {
        'CRLF-or-Mixed'
    }
    else {
        'CR-only'
    }

    [PSCustomObject]@{
        HasBom      = $hasBom
        HasCr       = $hasCr
        HasLf       = $hasLf
        Eol         = $eol
        IsCompliant = ($hasBom -and -not $hasCr)
    }
}

function Convert-ToUtf8BomLf {
    param([string]$FilePath)

    $text = [System.IO.File]::ReadAllText($FilePath)
    $text = ($text -replace "`r`n", "`n") -replace "`r", "`n"
    if (-not [string]::IsNullOrEmpty($text) -and -not $text.EndsWith("`n", [System.StringComparison]::Ordinal)) {
        $text += "`n"
    }

    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($FilePath, $text, $utf8Bom)
}

if ($Policy -eq 'off') {
    Write-Output '[ENCODING-POLICY-CHANGED] policy=off action=skip'
    exit 0
}

$mutexContext = Enter-EncodingMutex -Root $RepoRoot -FailOnLock:$FailIfLocked.IsPresent

try {
    $changed = @()
    if ($null -ne $TargetPaths -and $TargetPaths.Count -gt 0) {
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($target in @($TargetPaths)) {
            $rel = Convert-ToCandidateRelativePath -Root $RepoRoot -Path ([string]$target)
            if ([string]::IsNullOrWhiteSpace($rel)) {
                continue
            }

            [void]$set.Add($rel)
        }

        $changed = @($set)
    }
    else {
        $changed = Get-ChangedCandidateFileList -Root $RepoRoot -IncludeUntracked:$IncludeUntracked.IsPresent
    }

    $scanned = 0
    $eligible = 0
    $nonCompliant = 0
    $fixed = 0
    $remaining = 0
    $failedFixes = New-Object 'System.Collections.Generic.List[string]'
    $nonCompliantFiles = New-Object 'System.Collections.Generic.List[string]'
    $reported = 0

    foreach ($relRaw in @($changed)) {
    if ([string]::IsNullOrWhiteSpace($relRaw)) {
        continue
    }

    $rel = ([string]$relRaw).Trim().Replace('\\', '/')
    if (Test-ExcludedPath -RelativePath $rel -Excluded $ExcludePaths) {
        continue
    }

    $ext = ''
    try {
        $ext = [System.IO.Path]::GetExtension($rel).ToLowerInvariant()
    }
    catch {
        continue
    }
    if ($Extensions -notcontains $ext) {
        continue
    }

        $full = Join-Path $RepoRoot ($rel.Replace('/', '\\'))
    if (-not (Test-Path -LiteralPath $full)) {
        continue
    }

        $scanned++
        $eligible++
        $status = Get-EncodingStatus -FilePath $full
        if ($status.IsCompliant) {
            continue
        }

        $nonCompliant++
        [void]$nonCompliantFiles.Add($rel)
        if ($reported -lt $MaxReport) {
            Write-Output ("[ENCODING-POLICY-CHANGED] noncompliant path={0} bom={1} eol={2}" -f $rel, $status.HasBom, $status.Eol)
            $reported++
        }

        if ($Mode -eq 'fix') {
        try {
            Convert-ToUtf8BomLf -FilePath $full
            $after = Get-EncodingStatus -FilePath $full
            if ($after.IsCompliant) {
                $fixed++
                if ($reported -lt $MaxReport) {
                    Write-Output ("[ENCODING-POLICY-CHANGED] fixed path={0}" -f $rel)
                    $reported++
                }
            }
            else {
                $remaining++
                [void]$failedFixes.Add($rel)
            }
        }
        catch {
            $remaining++
            [void]$failedFixes.Add($rel)
            Write-Warning ("[ENCODING-POLICY-CHANGED] fix_failed path={0} detail={1}" -f $rel, $_.Exception.Message)
        }
    }
    }

    if ($Mode -eq 'check') {
        $remaining = $nonCompliant
    }

    Write-Output ("[ENCODING-POLICY-CHANGED] summary mode={0} policy={1} changed={2} scanned={3} eligible={4} non_compliant={5} fixed={6} remaining={7}" -f $Mode, $Policy, @($changed).Count, $scanned, $eligible, $nonCompliant, $fixed, $remaining)
    Write-Output ("[ENCODING-POLICY-CHANGED] lock_metrics lock_busy=false lock_busy_count=0 lock_wait_ms={0} lock_name={1}" -f [int]$mutexContext.WaitMs, [string]$mutexContext.Name)

    if ($nonCompliantFiles.Count -gt 0) {
        $preview = @($nonCompliantFiles | Select-Object -First 20)
        Write-Output ("[ENCODING-POLICY-CHANGED] noncompliant_preview count={0} files={1}" -f $nonCompliantFiles.Count, ($preview -join ';'))
    }

    if ($failedFixes.Count -gt 0) {
        $preview = @($failedFixes | Select-Object -First 20)
        Write-Warning ("[ENCODING-POLICY-CHANGED] failed_preview count={0} files={1}" -f $failedFixes.Count, ($preview -join ';'))
    }

    if ($Policy -eq 'warn' -and $remaining -gt 0) {
        Write-Warning ("[ENCODING-POLICY-CHANGED] policy=warn remaining={0}" -f $remaining)
        exit 0
    }

    if ($Policy -eq 'enforce' -and $remaining -gt 0) {
        Write-Output ("[ENCODING-POLICY-CHANGED] policy=enforce remaining={0} exit_code=1" -f $remaining)
        exit 1
    }

    exit 0
}
finally {
    if ($null -ne $mutexContext -and $null -ne $mutexContext.Mutex) {
        try { $mutexContext.Mutex.ReleaseMutex() | Out-Null } catch { Write-Verbose ("Suppress release failure: {0}" -f $_.Exception.Message) }
        try { $mutexContext.Mutex.Dispose() } catch { Write-Verbose ("Suppress dispose failure: {0}" -f $_.Exception.Message) }
    }
}
