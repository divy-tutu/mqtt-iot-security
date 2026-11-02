$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
function Invoke-DemoDocker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "Demo command failed: $args" }
}
function Get-CaptureLog([string]$Container) {
    # Windows PowerShell 5 treats redirected native stderr as ErrorRecords.
    # tcpdump uses stderr for normal readiness and packet statistics.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = (& docker logs $Container 2>&1 | Out-String)
        $logExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    if ($logExit -ne 0) { throw 'Could not read packet-capture logs.' }
    return $output
}
function Invoke-CapturedPhase([string]$Level, [scriptblock]$Action) {
    $broker = if ($Level -eq 'baseline') { 'baseline-broker' } else { 'hardened-broker' }
    $port = if ($Level -eq 'baseline') { 1883 } else { 8883 }
    $brokerId = (Invoke-DemoDocker compose ps -q $broker).Trim()
    $captureName = "mqtt-capture-$runId-$Level"
    # Capture to a task-owned Linux volume; per-packet Windows mount writes can drop bursts.
    $captureVolume = "$captureName-data"
    $captureId = Invoke-DemoDocker run -d --name $captureName --network "container:$brokerId" --cap-drop ALL --cap-add NET_RAW --cap-add SETUID --cap-add SETGID --security-opt no-new-privileges:true --read-only --tmpfs /tmp --mount "type=volume,source=$captureVolume,target=/captures" --memory 192m --pids-limit 64 mqtt-packet-evidence:local timeout --signal=INT 180 tcpdump -B 8192 -i any -p -nn -s 0 -U -Z root -c 100000 -w "/captures/$Level.pcap" "tcp port $port"
    try {
        $ready = $false
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            $log = Get-CaptureLog $captureId
            if ($log -match 'listening on') { $ready = $true; break }
            Start-Sleep -Milliseconds 200
        }
        if (-not $ready) { throw 'Packet capture failed to become ready.' }
        & $Action
    } finally {
        # Drain the final response/disconnect packets before signaling tcpdump.
        Start-Sleep -Seconds 2
        $wasRunning = (Invoke-DemoDocker inspect --format '{{.State.Running}}' $captureId).Trim()
        if ($wasRunning -eq 'true') { Invoke-DemoDocker kill --signal INT $captureId | Out-Null }
        $captureExit = (Invoke-DemoDocker wait $captureId | Select-Object -Last 1).Trim()
        Invoke-DemoDocker cp "${captureId}:/captures/$Level.pcap" (Join-Path $captureDirectory "$Level.pcap")
        $log = Get-CaptureLog $captureId
        $log | Set-Content -Encoding utf8 (Join-Path $captureDirectory "$Level.log")
        @{ clean_stop = ($wasRunning -eq 'true' -and $captureExit -eq '0' -and $log -match '(?m)^0 packets dropped by kernel'); exit_code = $captureExit } | ConvertTo-Json | Set-Content -Encoding ascii (Join-Path $captureDirectory "$Level.json")
        Invoke-DemoDocker rm $captureId | Out-Null
        Invoke-DemoDocker volume rm $captureVolume | Out-Null
    }
}

# Host-only orchestration; the website never receives Docker control.
New-Item -ItemType Directory -Force results | Out-Null
$runLock = [System.IO.File]::Open((Join-Path $PSScriptRoot 'results/guided-demo.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
try {
    Invoke-DemoDocker info --format '{{.ServerVersion}}'
    Invoke-DemoDocker build -t mqtt-packet-evidence:local tools/packet-evidence
    Invoke-DemoDocker compose up -d --build --wait
    $runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
    $captureDirectory = (New-Item -ItemType Directory -Path "results/captures/$runId").FullName
    Invoke-DemoDocker compose --profile test run --rm experiment python guided_demo.py --stage start --run-id $runId
    $demoCompleted = $false
    try {
        Invoke-CapturedPhase baseline {
            Invoke-DemoDocker compose --profile test run --rm experiment python guided_demo.py --level baseline
        }
        Invoke-CapturedPhase hardened {
            Invoke-DemoDocker compose --profile test run --rm experiment python guided_demo.py --level hardened
            Invoke-DemoDocker compose --profile test run --rm experiment python guided_demo.py --level hardened --restart prepare
            Invoke-DemoDocker compose restart hardened-lock
            Invoke-DemoDocker compose --profile test run --rm experiment python guided_demo.py --level hardened --restart check
        }
        Invoke-DemoDocker compose -f docker-compose.yml -f docker-compose.ablation.yml up -d --wait hardened-lock hardened-gateway
        Invoke-CapturedPhase intermediate {
            Invoke-DemoDocker compose --profile test run --rm experiment python guided_demo.py --level intermediate
        }
        $demoCompleted = $true
    } finally {
        Invoke-DemoDocker compose up -d --wait hardened-lock hardened-gateway
        Invoke-DemoDocker compose exec hardened-lock python -c "import os; assert os.environ.get('COMMAND_POLICY','full') == 'full'"
        Invoke-DemoDocker compose exec hardened-gateway python -c "import os; assert os.environ.get('COMMAND_POLICY','full') == 'full'"
        $demoStage = if ($demoCompleted) { 'finish' } else { 'abort' }
        Invoke-DemoDocker compose --profile test run --rm experiment python guided_demo.py --stage $demoStage
        $resultsDirectory = (Resolve-Path results).Path
        Invoke-DemoDocker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp --memory 512m --pids-limit 64 --mount "type=bind,source=$resultsDirectory,target=/results" mqtt-packet-evidence:local
    }
    Write-Host "Evidence saved to $captureDirectory. Open https://localhost:8443/lab. Full controls restored."
} finally {
    $runLock.Dispose()
}
