@echo off
cd /d "%~dp0"
if exist "opsis-agent-gui.exe" (
    start "" "opsis-agent-gui.exe"
) else if exist "src-tauri\target\release\opsis-agent-gui.exe" (
    start "" "src-tauri\target\release\opsis-agent-gui.exe"
)
