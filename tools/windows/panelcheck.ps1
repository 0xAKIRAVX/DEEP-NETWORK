# panelcheck.ps1 — DEEP NETWORK Windows reachability check.
#
# Iranian Windows users often need to answer one question fast: "is it my
# connection, the CDN edge, or the panel itself?" This script checks the
# panel and the subscription from the user's own network exactly the way
# v2rayNG would fetch them, and prints a verdict:
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\panelcheck.ps1 `
#       -Panel https://panel.example.com -Sub https://panel.example.com/sub/ID
#
# Output per target: TCP reachability, HTTP status, elapsed ms, body size,
# first link row preview. Exit code 0 = everything reachable, 1 = at least
# one target failed.
param(
    [Parameter(Mandatory = $true)]
    [string]$Panel,

    [Parameter(Mandatory = $false)]
    [string]$Sub,

    [int]$TimeoutSec = 20
)

$ErrorActionPreference = 'Continue'
$exit = 0

function Test-Target {
    param([string]$Name, [string]$Url)

    Write-Host ""
    Write-Host ("== {0} ==" -f $Name) -ForegroundColor Cyan
    Write-Host ("   {0}" -f $Url)

    try {
        $ua = 'v2rayNG/1.9.16'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $resp = Invoke-WebRequest -Uri $Url -UserAgent $ua `
            -TimeoutSec $TimeoutSec -UseBasicParsing `
            -Method Get
        $sw.Stop()

        $bytes = $resp.RawContentStream.Length
        Write-Host ("   HTTP {0}  {1} bytes  {2:N0} ms" -f `
            [int]$resp.StatusCode, $bytes, $sw.ElapsedMilliseconds) -ForegroundColor Green

        if ($Sub -and $Name -eq 'subscription') {
            $text = $resp.Content
            if ($text -match '^(vless|vmess|trojan)://') {
                $first = ($text -split "`n")[0]
                $count = ($text -split "`n" | Where-Object { $_ -match '://' }).Count
                Write-Host ("   rows: {0}" -f $count) -ForegroundColor Green
                Write-Host ("   first: {0}" -f $first.Substring(0, [Math]::Min(72, $first.Length)))
            } else {
                Write-Host "   body is not a plain link list (may be base64)" -ForegroundColor Yellow
            }
        }
        return $true
    }
    catch {
        Write-Host ("   FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
        return $false
    }
}

$okPanel = Test-Target -Name 'panel' -Url $Panel
if (-not $okPanel) { $exit = 1 }

if ($Sub) {
    $okSub = Test-Target -Name 'subscription' -Url $Sub
    if (-not $okSub) { $exit = 1 }
}

Write-Host ""
if ($exit -eq 0) {
    Write-Host "VERDICT: everything reachable from this network." -ForegroundColor Green
} else {
    Write-Host "VERDICT: at least one target unreachable — see above." -ForegroundColor Red
}
exit $exit
