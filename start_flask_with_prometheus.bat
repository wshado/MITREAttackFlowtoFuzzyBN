@echo off
echo Starting Flask app with Prometheus Push Gateway integration...
echo.

REM Set Prometheus environment variables
set PROMETHEUS_PUSHGATEWAY_URL=localhost:9091
set PROMETHEUS_JOB_NAME=fuzzy_bn_service
set USE_PUSH_GATEWAY=true

echo Environment variables set:
echo   PROMETHEUS_PUSHGATEWAY_URL=%PROMETHEUS_PUSHGATEWAY_URL%
echo   PROMETHEUS_JOB_NAME=%PROMETHEUS_JOB_NAME%
echo   USE_PUSH_GATEWAY=%USE_PUSH_GATEWAY%
echo.

echo Starting Flask app...
python flask_app/bn-ws.py

pause
