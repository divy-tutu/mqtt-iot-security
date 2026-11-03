param([Parameter(Mandatory=$true)][ValidateSet('unauthorized-access','traffic-analysis','stolen-credential','camera-injection','modification','replay','evidence-tampering','availability-pressure')][string]$Scenario)
$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path "$PSScriptRoot\..\..")
& docker info --format '{{.ServerVersion}}' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop is not running.' }
& docker compose up -d --wait
if ($LASTEXITCODE -ne 0) { throw 'The local lab could not start.' }
& docker compose --profile test run --rm experiment python local_attack.py --scenario $Scenario
if ($LASTEXITCODE -ne 0) { throw "Attack demonstration failed: $Scenario" }
Write-Host "Done. The Security Lab page will update automatically: https://localhost:8443/lab"
