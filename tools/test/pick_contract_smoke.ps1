param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$OutDirRoot = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
if (-not (Test-Path $BinaryPath)) { Write-Error "Binary not found: $BinaryPath"; exit 2 }
if (-not $OutDirRoot) { $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\pick_contract" }
$outDir = Join-Path $OutDirRoot (Get-Date -Format "yyyyMMdd-HHmmss")
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$pass = 0; $fail = 0; $results = @()

function Invoke-Case([string]$Name, [string[]]$Arguments, [string[]]$InputLines = @()) {
    $stdoutPath = Join-Path $outDir "$Name.stdout.txt"
    $stderrPath = Join-Path $outDir "$Name.stderr.txt"
    $start = @{ FilePath=$BinaryPath; ArgumentList=$Arguments; RedirectStandardOutput=$stdoutPath;
        RedirectStandardError=$stderrPath; NoNewWindow=$true; PassThru=$true; Wait=$true }
    if ($InputLines.Count) {
        $stdinPath = Join-Path $outDir "$Name.stdin.txt"
        [IO.File]::WriteAllText($stdinPath, ([string]::Join("`n", $InputLines) + "`n"),
            [Text.UTF8Encoding]::new($false)); $start.RedirectStandardInput = $stdinPath
    }
    $process = Start-Process @start
    $stdout = if (Test-Path $stdoutPath) { Get-Content -Raw $stdoutPath } else { "" }
    $stderr = if (Test-Path $stderrPath) { Get-Content -Raw $stderrPath } else { "" }
    [pscustomobject]@{ Name=$Name; ExitCode=$process.ExitCode; Stdout=$stdout; Stderr=$stderr;
        Lines=@($stdout -split "`r?`n" | Where-Object { $_.Length }) }
}

function Add-Result([string]$Name, [bool]$Ok, [string]$Detail) {
    if ($Ok) { $script:pass++; $state="PASS" } else { $script:fail++; $state="FAIL" }
    Write-Output "[$state] $Name $Detail"; $script:results += "$state case=$Name detail=$Detail"
}

$selftest = Invoke-Case "selftest" @("--selftest")
$ok = $selftest.ExitCode -eq 0 -and $selftest.Stderr -match 'opts-pick-parser: PASS' -and
    $selftest.Stderr -match 'opts-pick-mode-without-pick: PASS' -and
    $selftest.Stderr -match 'pick-extract-first-join: PASS'
Add-Result $selftest.Name $ok "exit=$($selftest.ExitCode)"

$all = Invoke-Case "all-empty" @("--fold", "--pick", "netname,country,inetnum,inet6num,origin,route,descr", "255.0.0.0")
$expected = "netname=`tcountry=`tinetnum=`tinet6num=`torigin=`troute=`tdescr="
Add-Result $all.Name ($all.ExitCode -eq 0 -and $all.Lines[1] -eq $expected) "exit=$($all.ExitCode)"

$order = Invoke-Case "observation-order" @("--fold", "--pick", "country", "--print-chain", "--print-meta", "255.0.0.0")
$ok = $order.ExitCode -eq 0 -and $order.Lines.Count -eq 4 -and $order.Lines[1] -eq "country=" -and
    $order.Lines[2] -eq "chain=unknown" -and $order.Lines[3] -match '^query='
Add-Result $order.Name $ok "lines=$($order.Lines.Count)"

$dedupe = Invoke-Case "dedupe-order" @("--pick", " Country,netname,COUNTRY ", "255.0.0.0")
Add-Result $dedupe.Name ($dedupe.ExitCode -eq 0 -and @($dedupe.Lines | Where-Object { $_ -eq "country=`tnetname=" }).Count -eq 1) "exit=$($dedupe.ExitCode)"

$last = Invoke-Case "last-pick-wins" @("--pick", "country", "--pick", "netname", "255.0.0.0")
Add-Result $last.Name ($last.ExitCode -eq 0 -and $last.Lines[-1] -eq "netname=" -and
    @($last.Lines | Where-Object { $_ -match '^country=' }).Count -eq 0) "exit=$($last.ExitCode)"

$batch = Invoke-Case "batch-explicit" @("-B", "--pick", "country") @("10.0.0.8", "255.0.0.0")
Add-Result $batch.Name ($batch.ExitCode -eq 0 -and @($batch.Lines | Where-Object { $_ -eq "country=" }).Count -eq 2) "exit=$($batch.ExitCode)"

$batchAuto = Invoke-Case "batch-auto" @("--pick", "country") @("10.0.0.8", "255.0.0.0")
Add-Result $batchAuto.Name ($batchAuto.ExitCode -eq 0 -and @($batchAuto.Lines | Where-Object { $_ -eq "country=" }).Count -eq 2) "exit=$($batchAuto.ExitCode)"

$invalidCases = @(
    @{ Name="invalid-key"; Args=@("--pick", "bogus", "8.8.8.8"); Error="Unsupported --pick key" },
    @{ Name="empty-key"; Args=@("--pick", "country,,netname", "8.8.8.8"); Error="contains an empty key" },
    @{ Name="mode-without-pick"; Args=@("--pick-mode", "join", "8.8.8.8"); Error="requires --pick" },
    @{ Name="invalid-mode"; Args=@("--pick", "country", "--pick-mode", "all", "8.8.8.8"); Error="Invalid --pick-mode" },
    @{ Name="plain-conflict"; Args=@("--pick", "country", "--plain", "8.8.8.8"); Error="--pick cannot be combined with --plain" }
)
foreach ($case in $invalidCases) {
    $run = Invoke-Case $case.Name $case.Args
    $ok = $run.ExitCode -ne 0 -and $run.Stderr -match [regex]::Escape($case.Error) -and
        $run.Stdout -notmatch '(?m)^=== Query:'
    Add-Result $run.Name $ok "exit=$($run.ExitCode)"
}

$summary = @("pick contract smoke summary", "artifact=$BinaryPath", "run=$outDir",
    "pass=$pass fail=$fail") + $results
[IO.File]::WriteAllText((Join-Path $outDir "summary.txt"), ([string]::Join("`n", $summary) + "`n"),
    [Text.UTF8Encoding]::new($false))
Write-Output "Summary: pass=$pass fail=$fail"; Write-Output "Report: $outDir"
if ($fail) { exit 1 }; exit 0