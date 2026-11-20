# AntiCrawl Lab Windows PowerShell 一键启动脚本
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RootDir

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item ".env.example" ".env"
    Write-Host "[bootstrap] Copied .env.example -> .env"
}

$PyExe = Join-Path $RootDir "backend\.venv\Scripts\python.exe"
$PipExe = Join-Path $RootDir "backend\.venv\Scripts\pip.exe"

if (-not (Test-Path $PyExe)) {
    Write-Host "[bootstrap] Creating Python venv..."
    python -m venv "backend\.venv"
}

& $PipExe install -q -r "backend\requirements.txt"

Write-Host "[bootstrap] Generating dynamic anti-crawl fonts..."
& $PyExe "scripts\make_font.py"

Write-Host "[bootstrap] Initializing SQLite schema & seed data..."
Push-Location (Join-Path $RootDir "backend")
& $PyExe -c "from app.db import init_db; init_db()"
Pop-Location

if (-not (Test-Path "frontend\node_modules")) {
    Write-Host "[bootstrap] Installing frontend dependencies..."
    Push-Location (Join-Path $RootDir "frontend")
    npm install
    Pop-Location
}

$BackendProc = Start-Process -FilePath $PyExe -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000" -WorkingDirectory (Join-Path $RootDir "backend") -PassThru
$FrontendProc = Start-Process -FilePath "npm.cmd" -ArgumentList "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173" -WorkingDirectory (Join-Path $RootDir "frontend") -PassThru

Write-Host "[bootstrap] Backend PID=$($BackendProc.Id) on http://127.0.0.1:8000"
Write-Host "[bootstrap] Frontend PID=$($FrontendProc.Id) on http://127.0.0.1:5173"
Write-Host "[bootstrap] Press Ctrl+C to stop both processes."

try {
    Wait-Process -Id $BackendProc.Id, $FrontendProc.Id
} finally {
    if (-not $BackendProc.HasExited) { Stop-Process -Id $BackendProc.Id -Force }
    if (-not $FrontendProc.HasExited) { Stop-Process -Id $FrontendProc.Id -Force }
}
