@echo off
if "%~1"=="" (
    echo Пожалуйста, перетащите файл update_profiles.py на этот .bat файл.
    pause
    exit /b
)
cd /d "%~dp1"
python update_profiles.py profiles.txt
pause