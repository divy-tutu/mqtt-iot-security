# Trust the project's private CA for the current Windows user only.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$certificatePath = (Resolve-Path "runtime/public/ca.crt").Path
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
$existing = Get-ChildItem Cert:\CurrentUser\Root | Where-Object Thumbprint -eq $certificate.Thumbprint
if ($existing) {
    Write-Host "HomePulse lab CA is already trusted for the current user."
    exit 0
}
Import-Certificate -FilePath $certificatePath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
Write-Host "Trusted HomePulse lab CA for the current user. Restart the browser, then open https://localhost:8443/."
Write-Host "Thumbprint: $($certificate.Thumbprint)"
