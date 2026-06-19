param(
    [string]$DnsName = "localhost",
    [string]$OutDir = "runtime/secrets",
    [string[]]$IpAddress = @("127.0.0.1", "10.0.2.2")
)

$ErrorActionPreference = "Stop"

function Get-LogTimestamp {
    Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

function Write-LogHost([string]$Message) {
    Write-Host "[$(Get-LogTimestamp)] $Message"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$keyPath = Join-Path $OutDir "server.key"
$crtPath = Join-Path $OutDir "server.crt"
$configPath = Join-Path $OutDir "openssl-san.cnf"
$randomPath = Join-Path $OutDir ".rnd"

$altNames = @("DNS.1 = $DnsName")
for ($i = 0; $i -lt $IpAddress.Count; $i++) {
    $altNames += "IP.$($i + 1) = $($IpAddress[$i])"
}

@"
[ req ]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[ dn ]
CN = $DnsName

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
$($altNames -join "`n")
"@ | Set-Content -LiteralPath $configPath -Encoding ASCII

$previousRandFile = $env:RANDFILE
$env:RANDFILE = $randomPath
try {
    openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes `
        -keyout $keyPath -out $crtPath -config $configPath
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed to generate the self-signed certificate."
    }

    $fingerprint = openssl x509 -in $crtPath -noout -fingerprint -sha256
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed to read the generated certificate fingerprint."
    }
} finally {
    if ($null -eq $previousRandFile) {
        Remove-Item Env:RANDFILE -ErrorAction SilentlyContinue
    } else {
        $env:RANDFILE = $previousRandFile
    }
}
Write-LogHost "Certificate: $crtPath"
Write-LogHost "Private key:  $keyPath"
Write-LogHost $fingerprint
Write-LogHost "Configure this SHA-256 fingerprint in Windows and Android clients."
