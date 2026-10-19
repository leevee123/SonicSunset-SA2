@echo off
setlocal
set "SOURCE_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if not exist "%SOURCE_PYTHON%" set "SOURCE_PYTHON=python"
"%SOURCE_PYTHON%" "%~dp0restore_source.py"
pause
