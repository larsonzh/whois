param(
    [AllowEmptyString()][string]$RepoRoot = '',
    [ValidateSet('check', 'fix')][string]$Mode = 'check',
    [ValidateSet('off', 'warn', 'enforce')][string]$Policy = 'enforce',
    [switch]$IncludeUntracked,
    [string[]]$TargetPaths = @(),
    [switch]$FailIfLocked
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Enter-SrcEncodingMutex {
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
    $name = "Global\whois-src-encoding-policy-$hash"
    $mutex = New-Object System.Threading.Mutex($false, $name)

    $acquired = $false
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }
        finally {
            $stopwatch.Stop()
        }

        if (-not $acquired) {
            if ($FailOnLock) {
                throw ("src encoding mutex busy: {0}" -f $name)
            }

            Write-Output ("[SRC-ENCODING-POLICY] lock=busy action=skip mutex={0}" -f $name)
            Write-Output ("[SRC-ENCODING-POLICY] lock_metrics lock_busy=true lock_busy_count=1 lock_wait_ms={0} lock_name={1}" -f [int]$stopwatch.ElapsedMilliseconds, $name)
            $mutex.Dispose()
            exit 0
        }

        return [pscustomobject]@{
            Name = $name
            Mutex = $mutex
            WaitMs = [int]$stopwatch.ElapsedMilliseconds
        }
    }
    catch {
        if ($null -ne $mutex) {
            try {
                $mutex.Dispose()
            }
            catch {
                Write-Verbose ("Suppress dispose failure: {0}" -f $_.Exception.Message)
            }
        }
        throw
    }
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

function Get-ChangedSrcCandidateList {
    param(
        [string]$Root,
        [switch]$IncludeUntracked
    )

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $gitWarningPattern = '^\s*(warning:|git(\.exe)?\s*:\s*warning:)'

    $unstaged = Get-GitOutputText -Root $Root -GitArgs @('diff', '--name-only', '--diff-filter=ACMR', '--', 'src/', 'include/') -Name 'diff src+include'
    foreach ($line in @($unstaged)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if (([string]$line).Trim() -match $gitWarningPattern) {
            continue
        }

        [void]$set.Add(([string]$line).Trim().Replace('\\', '/'))
    }

    $staged = Get-GitOutputText -Root $Root -GitArgs @('diff', '--cached', '--name-only', '--diff-filter=ACMR', '--', 'src/', 'include/') -Name 'diff --cached src+include'
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
        $untracked = Get-GitOutputText -Root $Root -GitArgs @('ls-files', '--others', '--exclude-standard', '--', 'src/', 'include/') -Name 'ls-files --others src+include'
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

function Test-IsSrcWhoisCodePath {
    param([string]$RelativePath)

    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        return $false
    }

    $normalized = $RelativePath.Replace('\\', '/').ToLowerInvariant()
    if (-not ($normalized.StartsWith('src/') -or $normalized.StartsWith('include/'))) {
        return $false
    }

    $ext = [System.IO.Path]::GetExtension($normalized)
    return $ext -in @('.c', '.h')
}

function Get-SrcEncodingStatus {
    param([string]$FilePath)

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)
    $hasCr = ([Array]::IndexOf($bytes, [byte]13) -ge 0)
    $hasLf = ([Array]::IndexOf($bytes, [byte]10) -ge 0)

    $isUtf8 = $true
    try {
        $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        [void]$strictUtf8.GetString($bytes)
    }
    catch {
        $isUtf8 = $false
    }

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
        IsUtf8      = $isUtf8
        HasBom      = $hasBom
        HasCr       = $hasCr
        Eol         = $eol
        IsCompliant = ($isUtf8 -and -not $hasBom -and -not $hasCr)
    }
}

function Convert-ToUtf8LfNoBom {
    param([string]$FilePath)

    $text = [System.IO.File]::ReadAllText($FilePath)
    $text = ($text -replace "`r`n", "`n") -replace "`r", "`n"
    if (-not [string]::IsNullOrEmpty($text) -and -not $text.EndsWith("`n", [System.StringComparison]::Ordinal)) {
        $text += "`n"
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($FilePath, $text, $utf8NoBom)
}

if ($Policy -eq 'off') {
    Write-Output '[SRC-ENCODING-POLICY] policy=off action=skip'
    exit 0
}

$mutexContext = Enter-SrcEncodingMutex -Root $RepoRoot -FailOnLock:$FailIfLocked.IsPresent

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
        $changed = Get-ChangedSrcCandidateList -Root $RepoRoot -IncludeUntracked:$IncludeUntracked.IsPresent
    }

    $scanned = 0
    $eligible = 0
    $nonCompliant = 0
    $fixed = 0
    $remaining = 0
    $reported = 0
    $failedFixes = New-Object 'System.Collections.Generic.List[string]'
    $nonCompliantFiles = New-Object 'System.Collections.Generic.List[string]'

    foreach ($relRaw in @($changed)) {
        if ([string]::IsNullOrWhiteSpace($relRaw)) {
            continue
        }

        $rel = ([string]$relRaw).Trim().Replace('\\', '/')
        $scanned++
        if (-not (Test-IsSrcWhoisCodePath -RelativePath $rel)) {
            continue
        }

        $eligible++
        $full = Join-Path $RepoRoot ($rel.Replace('/', '\\'))
        if (-not (Test-Path -LiteralPath $full)) {
            continue
        }

        $status = Get-SrcEncodingStatus -FilePath $full
        if ($status.IsCompliant) {
            continue
        }

        $nonCompliant++
        [void]$nonCompliantFiles.Add($rel)
        if ($reported -lt 120) {
            Write-Output ("[SRC-ENCODING-POLICY] noncompliant path={0} utf8={1} bom={2} eol={3}" -f $rel, $status.IsUtf8, $status.HasBom, $status.Eol)
            $reported++
        }

        if ($Mode -eq 'fix') {
            try {
                Convert-ToUtf8LfNoBom -FilePath $full
                $after = Get-SrcEncodingStatus -FilePath $full
                if ($after.IsCompliant) {
                    $fixed++
                    if ($reported -lt 120) {
                        Write-Output ("[SRC-ENCODING-POLICY] fixed path={0}" -f $rel)
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
                Write-Warning ("[SRC-ENCODING-POLICY] fix_failed path={0} detail={1}" -f $rel, $_.Exception.Message)
            }
        }
    }

    if ($Mode -eq 'check') {
        $remaining = $nonCompliant
    }

    Write-Output ("[SRC-ENCODING-POLICY] summary mode={0} policy={1} changed={2} scanned={3} eligible={4} non_compliant={5} fixed={6} remaining={7}" -f $Mode, $Policy, @($changed).Count, $scanned, $eligible, $nonCompliant, $fixed, $remaining)
    Write-Output ("[SRC-ENCODING-POLICY] lock_metrics lock_busy=false lock_busy_count=0 lock_wait_ms={0} lock_name={1}" -f [int]$mutexContext.WaitMs, [string]$mutexContext.Name)

    if ($nonCompliantFiles.Count -gt 0) {
        $preview = @($nonCompliantFiles | Select-Object -First 20)
        Write-Output ("[SRC-ENCODING-POLICY] noncompliant_preview count={0} files={1}" -f $nonCompliantFiles.Count, ($preview -join ';'))
    }

    if ($failedFixes.Count -gt 0) {
        $preview = @($failedFixes | Select-Object -First 20)
        Write-Warning ("[SRC-ENCODING-POLICY] failed_preview count={0} files={1}" -f $failedFixes.Count, ($preview -join ';'))
    }

    if ($Policy -eq 'warn' -and $remaining -gt 0) {
        Write-Warning ("[SRC-ENCODING-POLICY] policy=warn remaining={0}" -f $remaining)
        exit 0
    }

    if ($Policy -eq 'enforce' -and $remaining -gt 0) {
        Write-Output ("[SRC-ENCODING-POLICY] policy=enforce remaining={0} exit_code=1" -f $remaining)
        exit 1
    }

    exit 0
}
finally {
    if ($null -ne $mutexContext -and $null -ne $mutexContext.Mutex) {
        try {
            $mutexContext.Mutex.ReleaseMutex() | Out-Null
        }
        catch {
            Write-Verbose ("Suppress release failure: {0}" -f $_.Exception.Message)
        }
        try {
            $mutexContext.Mutex.Dispose()
        }
        catch {
            Write-Verbose ("Suppress dispose failure: {0}" -f $_.Exception.Message)
        }
    }
}
