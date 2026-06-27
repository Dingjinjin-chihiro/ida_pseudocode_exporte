@echo off
setlocal
chcp 65001 >nul
python "%~dp0pyside6_static_test.py"
if errorlevel 1 goto :error
python "%~dp0core_batch_static_test.py"
if errorlevel 1 goto :error
python "%~dp0auto_path_static_test.py"
if errorlevel 1 goto :error
python "%~dp0function_names_static_test.py"
if errorlevel 1 goto :error
echo.
echo All static checks passed.
pause
exit /b 0
:error
echo.
echo Static checks failed.
pause
exit /b 1
