Param(
    [string]$RbHost = '10.0.0.199',
    [string]$RbUser = 'larson',
    [string]$RbKey = '/c/Users/妙妙呜/.ssh/id_rsa',
    [string]$RbQueries = '8.8.8.8 1.1.1.1',
    [string]$RbSyncDirs = '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois',
    [int]$RbSmoke = 1,
    [int]$RbParallel = 1,
    [string]$RbSmokeArgs = '',
    [int]$RbGolden = 1,
    [string]$RbCflagsExtra = '-O3 -s'
)

$cmd = "cd /d/LZProjects/whois; tools/remote/remote_build_and_test.sh -H $RbHost -u $RbUser -k '$RbKey' -r $RbSmoke -q '$RbQueries' -s '$RbSyncDirs' -P $RbParallel -a '$RbSmokeArgs' -G $RbGolden -E '$RbCflagsExtra'"
& "C:\Program Files\Git\bin\bash.exe" -lc "$cmd"
exit $LASTEXITCODE
