# MCP Gateway — Phase 0 backup (run daily via Windows Task Scheduler).
#
# Backs up the four things that hold state:
#   1. gateway Postgres (appdb)            -> pg_dump SQL file
#   2. gateway state volume (gw-data)      -> tar.gz  (audit log, approvals, credentials)
#   3. gateway PKI volume  (gw-pki)        -> tar.gz  (issued certs)
#   4. Gitea (code backup: sqlite DB + repositories)
#
# Destination: D:\Backups\mcp\<yyyy-MM-dd_HHmm>\   (14-day retention)
# NOTE: same-disk backup — protects against deletion/corruption, not disk failure.
# Copy D:\Backups offsite/second disk when hardware allows (Phase 2+).

$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
$root  = 'D:\Backups\mcp'
$dest  = Join-Path $root $stamp
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$log = Join-Path $root 'backup.log'
function Log($m) { "$(Get-Date -Format s)  $m" | Add-Content -Encoding utf8 $log }

try {
    # 1. Postgres dump (via cmd so redirect writes raw bytes, not UTF-16)
    cmd /c "docker exec gateway-postgres-1 pg_dump -U postgres -d appdb > `"$dest\appdb.sql`""
    if ($LASTEXITCODE -ne 0) { throw "pg_dump failed ($LASTEXITCODE)" }

    # 2 + 3. Gateway docker volumes -> tarballs
    docker run --rm -v gateway_gw-data:/data -v "${dest}:/backup" alpine tar czf /backup/gw-data.tgz -C /data .
    if ($LASTEXITCODE -ne 0) { throw "gw-data archive failed" }
    docker run --rm -v gateway_gw-pki:/data -v "${dest}:/backup" alpine tar czf /backup/gw-pki.tgz -C /data .
    if ($LASTEXITCODE -ne 0) { throw "gw-pki archive failed" }

    # 4. Gitea: sqlite DB + repositories (robocopy exit <8 = success)
    Copy-Item 'D:\Gitea\data\gitea.db' (Join-Path $dest 'gitea.db')
    robocopy 'D:\Gitea\data\gitea-repositories' (Join-Path $dest 'gitea-repositories') /MIR /R:2 /W:2 /NFL /NDL /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy gitea repos failed ($LASTEXITCODE)" }

    # Retention: keep 14 days
    Get-ChildItem $root -Directory | Where-Object {
        $_.Name -match '^\d{4}-\d{2}-\d{2}_\d{4}$' -and
        $_.CreationTime -lt (Get-Date).AddDays(-14)
    } | Remove-Item -Recurse -Force -Confirm:$false

    Log "OK  -> $dest"
    exit 0
}
catch {
    Log "FAIL -> $($_.Exception.Message)"
    exit 1
}
