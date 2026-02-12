$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$dashboardPath = Join-Path $scriptDir "dashboard_static.html"

if (-not (Test-Path $dashboardPath)) {
    Write-Error "dashboard_static.html not found."
    exit 1
}

Start-Process $dashboardPath
