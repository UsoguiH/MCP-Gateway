# MCP Gateway — backup (run daily via Windows Task Scheduler).
#
# Backs up the four things that hold state:
#   1. gateway Postgres (appdb)            -> pg_dump SQL file
#   2. gateway state volume (gw-data)      -> tar.gz  (audit log, approvals, credentials)
#   3. gateway PKI volume  (gw-pki)        -> tar.gz  (issued certs)
#   4. Gitea (code backup: sqlite DB + repositories)
#
# DESTINATION — the H15 fix. A backup on the SAME PHYSICAL DISK as the data protects only
# against deletion/corruption, not disk failure. So:
#   * The primary destination is configurable (param -Dest or env MCP_BACKUP_DIR); it still
#     defaults to D:\Backups\mcp so an existing scheduled task keeps working.
#   * If you set -Offsite (or env MCP_BACKUP_OFFSITE) to a second disk or a UNC share
#     (\\nas\mcp-backups), the run is MIRRORED there too — that is the disaster-proof copy.
#   * If the primary destination is on the same volume as the gateway data and no offsite
#     is set, the script SUCCEEDS but logs a loud warning, so "backups are green" never
#     quietly means "one disk failure from total loss".
#
# Usage:
#   powershell -File scripts\backup.ps1
#   powershell -File scripts\backup.ps1 -Offsite '\\nas01\mcp-backups'
#   $env:MCP_BACKUP_OFFSITE='E:\Backups\mcp'; powershell -File scripts\backup.ps1
param(
    [string]$Dest    = $(if ($env:MCP_BACKUP_DIR)     { $env:MCP_BACKUP_DIR }     else { 'D:\Backups\mcp' }),
    [string]$Offsite = $(if ($env:MCP_BACKUP_OFFSITE) { $env:MCP_BACKUP_OFFSITE } else { '' }),
    [int]$RetentionDays = 14
)

$ErrorActionPreference = 'Stop'
$stamp   = Get-Date -Format 'yyyy-MM-dd_HHmm'
$root    = $Dest
$destDir = Join-Path $root $stamp
New-Item -ItemType Directory -Force -Path $destDir | Out-Null
$log = Join-Path $root 'backup.log'
function Log($m) { "$(Get-Date -Format s)  $m" | Add-Content -Encoding utf8 $log }

# Is the backup destination on the same physical disk as the gateway data (D:)? If so, and
# with no offsite copy configured, this backup does not survive a disk failure.
function Test-SameVolume($pathA, $pathB) {
    try {
        $a = [System.IO.Path]::GetPathRoot((Resolve-Path -LiteralPath $pathA -ErrorAction SilentlyContinue).Path)
        $b = [System.IO.Path]::GetPathRoot($pathB)
        return ($a -and $b -and $a.TrimEnd('\') -ieq $b.TrimEnd('\'))
    } catch { return $false }
}

try {
    # 1. Postgres dump (via cmd so redirect writes raw bytes, not UTF-16)
    cmd /c "docker exec gateway-postgres-1 pg_dump -U postgres -d appdb > `"$destDir\appdb.sql`""
    if ($LASTEXITCODE -ne 0) { throw "pg_dump failed ($LASTEXITCODE)" }

    # 2 + 3. Gateway docker volumes -> tarballs
    docker run --rm -v gateway_gw-data:/data -v "${destDir}:/backup" alpine tar czf /backup/gw-data.tgz -C /data .
    if ($LASTEXITCODE -ne 0) { throw "gw-data archive failed" }
    docker run --rm -v gateway_gw-pki:/data -v "${destDir}:/backup" alpine tar czf /backup/gw-pki.tgz -C /data .
    if ($LASTEXITCODE -ne 0) { throw "gw-pki archive failed" }

    # 4. Gitea: sqlite DB + repositories (robocopy exit <8 = success)
    if (Test-Path 'D:\Gitea\data\gitea.db') {
        Copy-Item 'D:\Gitea\data\gitea.db' (Join-Path $destDir 'gitea.db')
        robocopy 'D:\Gitea\data\gitea-repositories' (Join-Path $destDir 'gitea-repositories') /MIR /R:2 /W:2 /NFL /NDL /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "robocopy gitea repos failed ($LASTEXITCODE)" }
    }

    # Offsite / second-disk mirror — the copy that survives a disk failure (H15).
    if ($Offsite) {
        $offsiteRun = Join-Path $Offsite $stamp
        New-Item -ItemType Directory -Force -Path $offsiteRun | Out-Null
        robocopy $destDir $offsiteRun /MIR /R:2 /W:2 /NFL /NDL /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "offsite mirror to $Offsite failed ($LASTEXITCODE)" }
        # Retention on the offsite copy too.
        Get-ChildItem $Offsite -Directory -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '^\d{4}-\d{2}-\d{2}_\d{4}$' -and
            $_.CreationTime -lt (Get-Date).AddDays(-$RetentionDays)
        } | Remove-Item -Recurse -Force -Confirm:$false
        Log "OK  offsite -> $offsiteRun"
    }
    elseif (Test-SameVolume $destDir 'D:\') {
        Log ("WARN same-disk backup: destination '$root' is on the same volume as the " +
             "gateway data. This survives deletion/corruption but NOT disk failure. Set " +
             "-Offsite (or MCP_BACKUP_OFFSITE) to a second disk or a UNC share.")
    }

    # Retention: keep N days on the primary destination
    Get-ChildItem $root -Directory | Where-Object {
        $_.Name -match '^\d{4}-\d{2}-\d{2}_\d{4}$' -and
        $_.CreationTime -lt (Get-Date).AddDays(-$RetentionDays)
    } | Remove-Item -Recurse -Force -Confirm:$false

    Log "OK  -> $destDir"
    exit 0
}
catch {
    Log "FAIL -> $($_.Exception.Message)"
    exit 1
}
