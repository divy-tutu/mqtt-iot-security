# Remove only the exact project CA certificate from the current user's trust store.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$certificatePath = (Resolve-Path "runtime/public/ca.crt").Path
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
$matches = @(Get-ChildItem Cert:\CurrentUser\Root | Where-Object Thumbprint -eq $certificate.Thumbprint)
if (-not $matches) {
    Write-Host "HomePulse lab CA is not present in the current user's trust store."
    exit 0
}
$matches | Remove-Item
Write-Host "Removed HomePulse lab CA from the current user's trust store."
