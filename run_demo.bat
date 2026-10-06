@echo off
echo ========================================================
echo   NetGuard - Network Traffic Analyzer & Intrusion IDS
echo   REVA University SEE Hackathon Abhinava 2026
echo ========================================================
echo.
echo [1/3] Generating sample PCAP captures...
python generate_pcaps.py
echo.
echo [2/3] Running CLI Traffic Analysis...
python main.py
echo.
echo [3/3] Launching Live Web Dashboard in your browser...
python main.py --web
pause
