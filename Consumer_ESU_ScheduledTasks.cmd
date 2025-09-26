@setlocal DisableDelayedExpansion
@echo off
set "Path=%SystemRoot%\System32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SystemRoot%\System32\WindowsPowerShell\v1.0\"
if exist "%SystemRoot%\Sysnative\reg.exe" (
set "Path=%SystemRoot%\Sysnative;%SystemRoot%;%SystemRoot%\Sysnative\Wbem;%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\;%Path%"
)
set "_err===== ERROR ===="
for /f "tokens=6 delims=[]. " %%# in ('ver') do (
if %%# gtr 19045 goto :E_Win
if %%# lss 19041 goto :E_Win
)
reg query HKU\S-1-5-19 1>nul 2>nul || goto :E_Admin

set "_uKey=HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\ConsumerESU"
set "_mKey=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\ESU"
set _uESU=0
set _mESU=0
for /f "skip=2 tokens=2*" %%a in ('reg query "%_uKey%" /v ESUEligibility 2^>nul') do call set /a _uESU=%%b
for /f "skip=2 tokens=2*" %%a in ('reg query "%_mKey%" /v Win10ConsumerESUStatus 2^>nul') do call set /a _mESU=%%b
set _enrolled=1
if %_uESU% neq 3 if %_uESU% neq 11 if %_uESU% neq 12 set _enrolled=0
if %_mESU% neq 3 if %_mESU% neq 11 if %_mESU% neq 12 set _enrolled=0
if %_enrolled% equ 1 (set "_status=Enrolled") else (set "_status=!! NOT ENROLLED !!")

:mMenu
@cls
echo ============================================================
echo Consumer ESU Status: %_status%
echo ============================================================
echo.
echo [1] Disable Consumer ESU scheduled tasks
echo.
echo [2] Enable Consumer ESU scheduled tasks
echo.
echo [3] Exit
echo.
echo ============================================================
echo.
choice /C 123 /N /M "Choose a menu option: "
set _elr=%errorlevel%
if %_elr%==3 goto :eof
if %_elr%==2 (set "_opt=/ENABLE"&goto :Tasks)
if %_elr%==1 (set "_opt=/DISABLE"&goto :Tasks)
goto :mMenu

:Tasks
@cls
set "_cmnd=schtasks.exe /Change %_opt% /TN"
set "_task=\Microsoft\Windows\Clip\ClipEsuConsumer"
echo.
%_cmnd% "%_task%" 2>nul && echo.
%_cmnd% "%_task%ProcessPreOrder" 2>nul && echo.
%_cmnd% "%_task%ProcessRefund" 2>nul && echo.
%_cmnd% "%_task%ProcessECUpdate" 2>nul && echo.
echo.
echo Done.
goto :TheEnd

:E_Admin
echo %_err%
echo This script requires administrator privileges.
goto :TheEnd

:E_Win
echo %_err%
echo This script is for Windows 10 v22H2 only.
goto :TheEnd

:TheEnd
echo.
echo Press any key to exit.
pause >nul
goto :eof
