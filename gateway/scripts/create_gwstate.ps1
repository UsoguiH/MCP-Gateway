# Create the gwstate database + role on an EXISTING gateway Postgres container
# (deploy/postgres_init/02_gwstate.sh only runs on a fresh pgdata volume).
#
# Usage:
#   powershell -File scripts\create_gwstate.ps1                       # generates a password
#   powershell -File scripts\create_gwstate.ps1 -Container gateway-postgres-1
#
# Writes the generated password to deploy\secrets\gwstate_pw (Docker file-secret,
# same custody as the other secrets) unless the file already exists.
param(
    [string]$Container = 'gateway-postgres-1',
    [string]$SecretFile = "$PSScriptRoot\..\deploy\secrets\gwstate_pw"
)
$ErrorActionPreference = 'Stop'

if (Test-Path $SecretFile) {
    $pw = (Get-Content $SecretFile -Raw).Trim()
    Write-Host "using existing secret deploy/secrets/gwstate_pw"
} else {
    $bytes = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $pw = [Convert]::ToBase64String($bytes) -replace '[/+=]', 'x'
    [IO.File]::WriteAllText((Resolve-Path (Split-Path $SecretFile)).Path + '\gwstate_pw', $pw)
    Write-Host "generated new secret -> deploy/secrets/gwstate_pw"
}

$sqlRole = @"
DO `$do`$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gwstate') THEN
    CREATE ROLE gwstate LOGIN PASSWORD '$pw';
  ELSE
    ALTER ROLE gwstate LOGIN PASSWORD '$pw';
  END IF;
END
`$do`$;
"@

docker exec $Container psql -U postgres -v ON_ERROR_STOP=1 -c $sqlRole
if ($LASTEXITCODE -ne 0) { throw "role creation failed" }

$exists = docker exec $Container psql -U postgres -tA -c "SELECT 1 FROM pg_database WHERE datname = 'gwstate'"
if ($exists -notmatch '1') {
    docker exec $Container psql -U postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE gwstate OWNER gwstate"
    if ($LASTEXITCODE -ne 0) { throw "database creation failed" }
}

docker exec $Container psql -U postgres -d gwstate -v ON_ERROR_STOP=1 -c "REVOKE ALL ON SCHEMA public FROM PUBLIC; GRANT ALL ON SCHEMA public TO gwstate;"
if ($LASTEXITCODE -ne 0) { throw "schema grant failed" }

# The gateway consumes the full URL as a Docker file-secret (MCP_STATE_DB_URL_FILE).
$urlFile = Join-Path (Split-Path $SecretFile) 'gwstate_url'
[IO.File]::WriteAllText($urlFile, "postgresql://gwstate:$pw@postgres:5432/gwstate")
Write-Host "gwstate ready. URL secret -> deploy/secrets/gwstate_url"
Write-Host "(compose wires it via MCP_STATE_DB_URL_FILE -> /run/secrets/gwstate_url)"
