@echo off
chcp 65001 >nul
cd /d %~dp0
echo ============================================
echo   越权测试工具 打包脚本
echo ============================================
pip show pyinstaller >nul 2>&1 || pip install pyinstaller
pyinstaller --onefile --noconsole --clean --name 越权测试工具 ^
  --hidden-import websocket --hidden-import requests ^
  idor_pro.py
echo.
echo 打包完成: dist\越权测试工具.exe
pause
