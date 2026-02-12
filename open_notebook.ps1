$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$notebookPath = Join-Path $scriptDir "dashboard.ipynb"

if (-not (Test-Path $notebookPath)) {
    Write-Error "dashboard.ipynb not found."
    exit 1
}

Start-Process $notebookPath
