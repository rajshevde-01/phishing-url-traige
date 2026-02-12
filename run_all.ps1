$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$triagePath = Join-Path $scriptDir "triage.py"
$inputPath = Join-Path $scriptDir "sample_urls.csv"
$reportDir = Join-Path $scriptDir "reports"
$dashboardPath = Join-Path $scriptDir "dashboard_static.html"

if (-not (Test-Path $triagePath)) {
    Write-Error "triage.py not found."
    exit 1
}

if (-not (Test-Path $inputPath)) {
    Write-Error "sample_urls.csv not found."
    exit 1
}

python $triagePath --input $inputPath --out $reportDir
if ($LASTEXITCODE -ne 0) {
    Write-Error "triage.py failed."
    exit $LASTEXITCODE
}

if (Test-Path $dashboardPath) {
    Start-Process $dashboardPath
} else {
    Write-Error "dashboard_static.html not found."
    exit 1
}
