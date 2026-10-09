# VulnWatch Startup Script (PowerShell)
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "         VULNWATCH - CYBERSECURITY + DEVOPS GROUP PROJECT" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "Team Members:" -ForegroundColor Yellow
Write-Host "  - 24DCS136_Yashvi Thakkar" -ForegroundColor White
Write-Host "  - 24DCS076_Mantra Patel" -ForegroundColor White
Write-Host "  - 24DCS089_Tirth Patel" -ForegroundColor White
Write-Host "  - 24DCS098_Mitesh Patil" -ForegroundColor White
Write-Host ""

Write-Host "[1/2] Starting FastAPI Backend on http://localhost:8000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\backend'; python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

Write-Host "[2/2] Starting React 3D HUD Frontend on http://localhost:5173..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\frontend'; npm run dev"

Write-Host ""
Write-Host "VulnWatch is now running!" -ForegroundColor Cyan
Write-Host "Frontend URL: http://localhost:5173" -ForegroundColor Yellow
Write-Host "Backend API Docs: http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Cyan
