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
if (Test-Path runtime/provisioned) {
    Invoke-Docker run --rm --user 0:0 -v "${runtimePath}:/runtime" mqtt-security-lab:local python provision.py
} else {
    $bootstrapSecret = Read-Host 'Choose the initial admin password (8-128 characters)' -AsSecureString
    $bootstrapPassword = [System.Net.NetworkCredential]::new('', $bootstrapSecret).Password
    try {
        @{password=$bootstrapPassword} | ConvertTo-Json -Compress | & docker run --rm -i --user 0:0 -v "${runtimePath}:/runtime" mqtt-security-lab:local python provision.py
        if ($LASTEXITCODE -ne 0) { throw 'Provisioning failed.' }
    } finally { $bootstrapPassword=$null; $bootstrapSecret=$null }
}
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
Write-Host "Use your administrator-created account. Browser passwords are stored as salted hashes."

