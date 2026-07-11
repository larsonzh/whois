git status --porcelain

git add -A

# Try commit; if no changes, record note and continue
git commit -m 'fix(monitor): accept System.DateTime CreationDate in Test-RoleProcessTrulyAlive to avoid false zombie detection'
if ($LASTEXITCODE -ne 0) {
    Write-Host 'git commit returned non-zero (likely no changes to commit)'
}

# Get current HEAD short hash
$hash = git rev-parse --short HEAD 2>$null

# Push to origin/master
git push origin HEAD:master

Write-Host "COMMIT_HASH:$hash"
