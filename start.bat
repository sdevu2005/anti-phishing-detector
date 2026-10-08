@echo off
title PhishShield AI - Cyber Defense Server
cd /d "%~dp0"

echo ========================================================
echo   PhishShield AI - Anti-Phishing Cyber Defense Platform
echo ========================================================
echo.
echo [1/2] Opening dashboard in your default browser...
start "" "http://localhost:8000"

echo [2/2] Starting Python REST API Backend on port 8000...
echo.
python server.py

pause