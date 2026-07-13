# MCP Gateway - restore drill (Phase 3, task 5).
#
# Exit criterion: "a restore from backup has been EXECUTED once". An untested backup is
# a hope, not a backup - and a restore that produces a database whose audit chain does
# not verify is a tampering finding, not merely a bad backup.
#
# Restores a backup run into a THROWAWAY postgres container + scratch directory and
# proves it is usable:
#   1. appdb.sql and gwstate.sql restore cleanly into a fresh postgres:17
#   2. the restored audit chain VERIFIES from genesis (HMAC intact, zero broken links)
#   3. every gw-data*.tgz unpacks and every JSON store in it parses
# It never touches the live stack.
#
# Run it monthly against the OFFSITE copy - that is the copy that has to work:
#   powershell -File scripts\restore_drill.ps1 -From '\\nas01\mcp-backups\2026-07-13_0831'
# or against the newest local run:
#   powershell -File scripts\restore_drill.ps1
#
# NOTE: ASCII only. Windows PowerShell 5.1 reads .ps1 as ANSI unless there is a BOM, so
# non-ASCII characters here corrupt string parsing in ways that look like syntax errors.
param(
    [string]$From = '',
    [string]$BackupRoot = $(if ($env:MCP_BACKUP_DIR) { $env:MCP_BACKUP_DIR } else { 'D:\Backups\mcp' }),
    [int]$Port = 15599
)
$ErrorActionPreference = 'Stop'

if (-not $From) {
    $latest = Get-ChildItem $BackupRoot -Directory |
        Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}_\d{4}$' } |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $latest) { throw "no backup runs under $BackupRoot" }
    $From = $latest.FullName
}
Write-Host "== restore drill from: $From"
$started = Get-Date

$name    = 'mcp-restore-drill'
$scratch = Join-Path $env:TEMP "mcp-restore-drill-$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -ItemType Directory -Force -Path $scratch | Out-Null

# Removing a container that isn't there, and probing a database that isn't up yet, both
# write to stderr - and Windows PowerShell turns a native command's stderr into a
# terminating error under ErrorActionPreference='Stop'. So: only remove what exists, and
# probe with the preference relaxed.
function Remove-DrillContainer {
    $existing = docker ps -aq --filter "name=^$name$"
    if ($existing) { docker rm -f $name | Out-Null }
}

try {
    # -- 1. throwaway postgres + SQL restore ---------------------------------
    Remove-DrillContainer
    docker run -d --name $name -e POSTGRES_PASSWORD=drill -p "${Port}:5432" postgres:17 | Out-Null

    $deadline = (Get-Date).AddSeconds(90)
    $ready = $false
    do {
        Start-Sleep -Seconds 2
        $ErrorActionPreference = 'SilentlyContinue'
        docker exec $name pg_isready -U postgres | Out-Null
        $ready = ($LASTEXITCODE -eq 0)
        $ErrorActionPreference = 'Stop'
    } until ($ready -or (Get-Date) -gt $deadline)
    if (-not $ready) { throw "throwaway postgres did not become ready" }

    # 1a. Cluster globals (roles) FIRST. A per-database dump only references roles like
    # mcp_app / gwstate; it never creates them, so without this the restore dies with
    # 'role "..." does not exist'. This is the failure the drill exists to find.
    $globals = Join-Path $From 'globals.sql'
    if (Test-Path $globals) {
        Get-Content -Raw $globals | docker exec -i $name psql -U postgres -q
        if ($LASTEXITCODE -ne 0) { throw "globals.sql (roles) failed to restore" }
        Write-Host "   restored globals.sql (cluster roles)"
    }
    else {
        Write-Host "   !! no globals.sql in this backup - roles are NOT backed up."
        Write-Host "      Creating placeholder roles so the drill can proceed, but a REAL"
        Write-Host "      restore from this run would fail. Re-run scripts\backup.ps1."
        foreach ($role in @('mcp_app', 'mcp_login', 'gwstate')) {
            docker exec $name psql -U postgres -q -c "DO `$`$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='$role') THEN CREATE ROLE $role; END IF; END `$`$;" | Out-Null
        }
    }

    foreach ($db in @('appdb', 'gwstate')) {
        $sql = Join-Path $From "$db.sql"
        if (-not (Test-Path $sql)) { Write-Host "   ($db.sql not in this backup - skipped)"; continue }
        docker exec $name psql -U postgres -q -c "CREATE DATABASE $db" | Out-Null
        # Pipe the dump in: PowerShell reserves '<', and quoting a Windows path through
        # cmd.exe for a redirect is its own small nightmare.
        Get-Content -Raw $sql | docker exec -i $name psql -U postgres -d $db -v ON_ERROR_STOP=1 -q
        if ($LASTEXITCODE -ne 0) { throw "$db.sql failed to restore" }
        $rows = docker exec $name psql -U postgres -d $db -tA -c "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')"
        Write-Host "   restored $db.sql ($rows tables)"
    }

    # -- 2. verify the restored audit chain ----------------------------------
    if (Test-Path (Join-Path $From 'gwstate.sql')) {
        $gatewayRoot = Split-Path $PSScriptRoot
        $verifier = Join-Path $scratch 'verify_chain.py'
        # The verifier lives in a temp dir, so sys.path[0] is NOT the gateway root -
        # it takes the root as an argument.
        $py = @'
import os
import sys
import time

sys.path.insert(0, sys.argv[1])
import psycopg

# pg_isready (run via docker exec) reports the server up INSIDE the container, but
# Docker Desktop's port proxy can take a few more seconds to start forwarding the
# published port. Wait for a real host-side connection before verifying.
url = os.environ["MCP_STATE_DB_URL"]
last = None
for attempt in range(30):
    try:
        psycopg.connect(url, connect_timeout=3).close()
        break
    except Exception as exc:
        last = exc
        time.sleep(2)
else:
    print(f"could not reach the restored database on its published port: "
          f"{type(last).__name__}: {last}")
    sys.exit(1)

from app import audit
ok, msg = audit.verify_chain()
print(msg)
sys.exit(0 if ok else 1)
'@
        Set-Content -Path $verifier -Value $py -Encoding ascii

        # Connect as the gateway's OWN least-privilege role, not the superuser.
        #
        # Two reasons. First, it is the stronger check: it proves the restored database is
        # usable BY THE GATEWAY, which is the thing recovery actually has to deliver.
        # Second, restoring globals.sql restores every role's PASSWORD too - including the
        # superuser's - so `postgres` in this throwaway container no longer has the
        # password we started it with; it has production's. That is a real trap in a real
        # recovery, and it is written up in OPERATIONS.md section 5a.
        $gwPwFile = Join-Path $gatewayRoot 'deploy\secrets\gwstate_pw'
        if (-not (Test-Path $gwPwFile)) { throw "deploy/secrets/gwstate_pw not found - cannot verify the restored chain" }
        $gwPw = (Get-Content $gwPwFile -Raw).Trim()

        # The chain's HMAC key is what makes it verifiable AT ALL. A restored audit log
        # without its key is just JSON: you can read it, but you cannot prove nobody
        # edited it - which is the entire point of keeping it. Back the key up separately
        # from the data (OPERATIONS.md section 5a); if you lose it, every archived chain
        # becomes unverifiable, permanently.
        $auditKeyFile = Join-Path $gatewayRoot 'deploy\secrets\audit_key'
        if (-not (Test-Path $auditKeyFile)) { throw "deploy/secrets/audit_key not found - the restored chain CANNOT be verified without it" }

        $env:MCP_STATE_DB_URL  = "postgresql://gwstate:$gwPw@localhost:$Port/gwstate"
        $env:MCP_AUDIT_KEY_FILE = $auditKeyFile
        Write-Host "   verifying as role 'gwstate' on localhost:$Port (port map: $(docker port $name 5432))"
        Push-Location $gatewayRoot
        try {
            $out = python $verifier $gatewayRoot
            $rc  = $LASTEXITCODE
        }
        finally {
            Pop-Location
            Remove-Item Env:\MCP_STATE_DB_URL -ErrorAction SilentlyContinue
            Remove-Item Env:\MCP_AUDIT_KEY_FILE -ErrorAction SilentlyContinue
        }
        if ($rc -ne 0) { throw "restored audit chain FAILED verification: $out" }
        Write-Host "   audit chain on the RESTORED database: $out"
    }

    # -- 3. unpack + parse the flat-file volume(s) ----------------------------
    Get-ChildItem $From -Filter 'gw-data*.tgz' | ForEach-Object {
        $dest = Join-Path $scratch $_.BaseName
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        tar -xzf $_.FullName -C $dest
        if ($LASTEXITCODE -ne 0) { throw "$($_.Name) failed to unpack" }
        $bad = 0
        Get-ChildItem $dest -Filter '*.json' | ForEach-Object {
            try { Get-Content $_.FullName -Raw | ConvertFrom-Json | Out-Null }
            catch { $bad++; Write-Host "   !! $($_.Name) does not parse" }
        }
        if ($bad) { throw "$bad store file(s) corrupt in $($_.Name)" }
        Write-Host "   $($_.Name): unpacked, all JSON stores parse"
    }

    $rto = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
    Write-Host ""
    Write-Host "RESTORE DRILL PASSED  (wall-clock RTO: $rto s)"
    Write-Host "Record the date + RTO in OPERATIONS.md section 5a (restore-drill log)."
    exit 0
}
catch {
    Write-Host ""
    Write-Host "RESTORE DRILL FAILED: $($_.Exception.Message)"
    exit 1
}
finally {
    $ErrorActionPreference = 'SilentlyContinue'
    Remove-DrillContainer
    Remove-Item -Recurse -Force $scratch -ErrorAction SilentlyContinue
}
