param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8765,
    [string]$CertFile = "runtime/secrets/server.crt",
    [string]$KeyFile = "runtime/secrets/server.key"
)

$ErrorActionPreference = "Stop"

function Get-LogTimestamp {
    Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

function Write-LogError([string]$Message) {
    Write-Error "[$(Get-LogTimestamp)] $Message"
}

if (-not (Test-Path -LiteralPath $CertFile) -or -not (Test-Path -LiteralPath $KeyFile)) {
    Write-LogError "Missing certificate files. Run scripts/generate_self_signed_cert.ps1 first."
}

uv run uvicorn app.main:app `
    --host $HostAddress `
    --port $Port `
    --ssl-certfile $CertFile `
    --ssl-keyfile $KeyFile `
    --log-config logging.json
