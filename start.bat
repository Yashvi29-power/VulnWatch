@echo off
title VulnWatch - Continuous Vulnerability Monitoring & Runtime Behavior Analysis
echo ===============================================================================
echo            VULNWATCH - CYBERSECURITY + DEVOPS GROUP PROJECT
echo ===============================================================================
echo Team: 24DCS136 (Yashvi Thakkar), 24DCS076 (Mantra Patel), 24DCS089 (Tirth Patel), 24DCS098 (Mitesh Patil)
echo.
echo Starting VulnWatch Backend (FastAPI on http://localhost:8000)...
start cmd /k "cd backend && python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

echo Starting VulnWatch Frontend (Vite on http://localhost:5173)...
start cmd /k "cd frontend && npm run dev"

echo.
echo Services launched!
echo Open http://localhost:5173 in your browser.
echo ===============================================================================
pause
