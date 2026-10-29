$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "Docker check failed: $args" }
}
try {
    Invoke-Docker compose -f docker-compose.yml -f docker-compose.ablation.yml up -d --wait hardened-lock hardened-gateway
    Invoke-Docker compose --profile test run --rm experiment python send_command.py UNLOCK --save
    Invoke-Docker compose --profile test run --rm experiment python send_command.py UNLOCK --replay --expect accepted
    Copy-Item results/last-operator-decision.json results/ablation-decision.json
} finally {
    Invoke-Docker compose up -d --wait hardened-lock hardened-gateway
}
Write-Host "Ablation complete. Full application controls restored."
