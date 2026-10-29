# Run from PowerShell: ./setup-lab.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed: $args" }
}
Invoke-Docker build -t mqtt-security-lab:local ./lab
New-Item -ItemType Directory -Force runtime | Out-Null
$runtimePath = (Resolve-Path runtime).Path
Invoke-Docker run --rm --user 0:0 -v "${runtimePath}:/runtime" mqtt-security-lab:local python provision.py
# Convert the initial plaintext files exactly once using Mosquitto's own utility.
if (-not (Test-Path runtime/passwords-hashed)) {
    foreach ($profile in @("baseline", "hardened")) {
        $credentialPath = Join-Path $runtimePath "$profile-broker"
        Invoke-Docker run --rm --user 0:0 -v "${credentialPath}:/credentials" eclipse-mosquitto:2.0.22 sh -c 'chmod 644 /credentials/passwd && mosquitto_passwd -U /credentials/passwd && chmod 444 /credentials/passwd'
    }
    Set-Content runtime/passwords-hashed "done"
}
Invoke-Docker compose up -d --build --wait
Write-Host "Lab: https://localhost:8443/dashboard"
Write-Host "HTTP on localhost:8080 redirects to HTTPS. Trust runtime/public/ca.crt in your browser/OS to remove the local-CA warning."
Write-Host "Read runtime/login.txt for your generated operator login."

