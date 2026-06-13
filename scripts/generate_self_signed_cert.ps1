param(
    [string]$DnsName = "localhost",
    [string]$OutDir = "runtime/secrets"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$keyPath = Join-Path $OutDir "server.key"
$crtPath = Join-Path $OutDir "server.crt"

openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes `
    -keyout $keyPath -out $crtPath -subj "/CN=$DnsName" `
    -addext "subjectAltName=DNS:$DnsName,IP:127.0.0.1"

$fingerprint = openssl x509 -in $crtPath -noout -fingerprint -sha256
Write-Host "Certificate: $crtPath"
Write-Host "Private key:  $keyPath"
Write-Host $fingerprint
Write-Host "Configure this SHA-256 fingerprint in Windows and Android clients."
